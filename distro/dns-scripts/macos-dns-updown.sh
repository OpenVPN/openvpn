#!/bin/bash
#
# dns-updown - add/remove openvpn provided DNS information
#
# (C) Copyright 2025 OpenVPN Inc <sales@openvpn.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Example env from openvpn (most are not applied):
#
#   dns_vars_file /tmp/openvpn_dvf_58b95c0c97b2db43afb5d745f986c53c.tmp
#
#      or
#
#   dev utun0
#   script_type dns-up
#   dns_search_domain_1 mycorp.in
#   dns_search_domain_2 eu.mycorp.com
#   dns_server_1_address_1 192.168.99.254
#   dns_server_1_address_2 fd00::99:53
#   dns_server_1_port_2 53
#   dns_server_1_resolve_domain_1 mycorp.in
#   dns_server_1_resolve_domain_2 eu.mycorp.com
#   dns_server_1_dnssec true
#   dns_server_1_transport DoH
#   dns_server_1_sni dns.mycorp.in
#

lockdir=/var/lock
if [ ! -d "${lockdir}" ]; then
    /bin/mkdir "${lockdir}"
    /bin/chmod 1777 "${lockdir}"
fi

i=1
lockfile="${lockdir}/openvpn-dns-updown.lock"
while ! /usr/bin/shlock -f $lockfile -p $$; do
    if [ $((++i)) -gt 10 ]; then
        echo "dns-updown failed, could not acquire lock"
        exit 1
    fi
    sleep 0.2
done
trap "/bin/rm -f ${lockfile}" EXIT

[ -z "${dns_vars_file}" ] || . "${dns_vars_file}"

itf_dns_key="State:/Network/Service/openvpn-${dev}/DNS"

function primary_dns_key {
    local uuid=$(echo "show State:/Network/Global/IPv4" | /usr/sbin/scutil | grep "PrimaryService" | cut -d: -f2 | xargs)
    echo "Setup:/Network/Service/${uuid}/DNS"
}

function dns_backup_key {
    local key="$(echo "list State:/Network/Service/openvpn-.*/DnsBackup" | /usr/sbin/scutil | cut -d= -f2 | xargs)"
    if [[ "${key}" =~ no\ key ]]; then
        echo "State:/Network/Service/openvpn-${dev}/DnsBackup"
    else
        echo "${key}"
    fi
}

function property_value {
    local key="$1"
    local prop="$2"

    [ -n "${key}" -a -n "${prop}" ] || return

    local match_prop="${prop} : (.*)"
    local match_array_start="${prop} : <array>"
    local match_array_elem="[0-9]* : (.*)"
    local match_array_end="}"
    local in_array=false
    local values=""

    echo "show ${key}" | /usr/sbin/scutil | while read line; do
        if [ "${in_array}" = false ] && [[ "${line}" =~ "${match_array_start}" ]]; then
            in_array=true
        elif [ "${in_array}" = true ] && [[ "${line}" =~ ${match_array_elem} ]]; then
            values+="${BASH_REMATCH[1]} "
        elif [ "${in_array}" = true ] && [[ "${line}" =~ "${match_array_end}" ]]; then
            echo "${values}"
            break
        elif [[ "${line}" =~ ${match_prop} ]]; then
            echo "${BASH_REMATCH[1]}"
            break
        fi
    done
}

function only_standard_server_ports {
    local i=1
    while :; do
        local addr_var=dns_server_${n}_address_${i}
        [ -n "${!addr_var}" ] || return 0

        local port_var=dns_server_${n}_port_${i}
        [ -z "${!port_var}" -o "${!port_var}" = "53" ] || return 1

        i=$((i+1))
    done
}

function find_compat_profile {
    local n=1
    while :; do
        local addr_var=dns_server_${n}_address_1
        [ -n "${!addr_var}" ] || {
            echo "setting DNS failed, no compatible server profile"
            exit 1
        }

        # Skip server profiles which require DNSSEC,
        # secure transport or use a custom port
        local dnssec_var=dns_server_${n}_dnssec
        local transport_var=dns_server_${n}_transport
        [ -z "${!transport_var}" -o "${!transport_var}" = "plain" ] \
            && [ -z "${!dnssec_var}" -o "${!dnssec_var}" = "no" ] \
            && only_standard_server_ports && break

        n=$((n+1))
    done
    echo $n
}

function get_search_domains {
    property_value State:/Network/Global/DNS SearchDomains
}

function get_server_addresses {
    property_value "$(primary_dns_key)" ServerAddresses
}

function set_search_domains {
    [ -n "$1" ] || return
    local dns_key=$(primary_dns_key)
    local dns_backup_key="$(dns_backup_key)"
    local search_domains="${1}$(get_search_domains)"

    local cmds=""
    cmds+="get ${dns_key}\n"
    cmds+="d.add SearchDomains * ${search_domains}\n"
    cmds+="set ${dns_key}\n"

    if ! [[ "${dns_backup_key}" =~ ${dev}/ ]]; then
        # Add the domains to the backup in case the default goes down
        local existing="$(property_value ${dns_backup_key} SearchDomains)"
        cmds+="get ${dns_backup_key}\n"
        cmds+="d.add SearchDomains * ${search_domains} ${existing}\n"
        cmds+="set ${dns_backup_key}\n"
    fi

    echo -e "${cmds}" | /usr/sbin/scutil
}

function unset_search_domains {
    [ -n "$1" ] || return
    local dns_key=$(primary_dns_key)
    local dns_backup_key="$(dns_backup_key)"
    local search_domains="$(get_search_domains)"
    search_domains=$(echo $search_domains | sed -e "s/$1//")

    local cmds=""
    cmds+="get ${dns_key}\n"
    cmds+="d.add SearchDomains * ${search_domains}\n"
    cmds+="set ${dns_key}\n"

    if ! [[ "${dns_backup_key}" =~ ${dev}/ ]]; then
        # Remove the domains from the backup for when the default goes down
        search_domains="$(property_value ${dns_backup_key} SearchDomains)"
        search_domains=$(echo $search_domains | sed -e "s/$1//")
        cmds+="get ${dns_backup_key}\n"
        cmds+="d.add SearchDomains * ${search_domains}\n"
        cmds+="set ${dns_backup_key}\n"
    fi

    echo -e "${cmds}" | /usr/sbin/scutil
}

function addresses_string {
    local n=$1
    local i=1
    local addresses=""
    while :; do
        local addr_var=dns_server_${n}_address_${i}
        local addr="${!addr_var}"
        [ -n "$addr" ] || break
        addresses+="${addr} "
        i=$((i+1))
    done
    echo "$addresses"
}

function search_domains_string {
    local n=$1
    local i=1
    local search_domains=""
    while :; do
        domain_var=dns_search_domain_${i}
        [ -n "${!domain_var}" ] || break
        # Add as search domain, if it doesn't already exist
        [[ "$search_domains" =~ (^| )${!domain_var}( |$) ]] \
            || search_domains+="${!domain_var} "
        i=$((i+1))
    done
    echo "$search_domains"
}

function match_domains_string {
    local n=$1
    local i=1
    local match_domains=""
    while :; do
        domain_var=dns_server_${n}_resolve_domain_${i}
        [ -n "${!domain_var}" ] || break
        # Add as match domain, if it doesn't already exist
        [[ "$match_domains" =~ (^| )${!domain_var}( |$) ]] \
            || match_domains+="${!domain_var} "
        i=$((i+1))
    done
    echo "$match_domains"
}

function set_dns {
    local n="$(find_compat_profile)"
    local addresses="$(addresses_string $n)"
    local search_domains="$(search_domains_string $n)"
    local match_domains="$(match_domains_string $n)"

    if [ -n "$match_domains" ]; then
        local cmds=""
        cmds+="d.init\n"
        cmds+="d.add ServerAddresses * ${addresses}\n"
        cmds+="d.add SupplementalMatchDomains * ${match_domains}\n"
        cmds+="d.add SupplementalMatchDomainsNoSearch # 1\n"
        cmds+="add ${itf_dns_key}\n"
        echo -e "${cmds}" | /usr/sbin/scutil
        set_search_domains "$search_domains"
    else
        local dns_backup_key="$(dns_backup_key)"
        [[ "${dns_backup_key}" =~ ${dev}/ ]] || {
            echo "setting DNS failed, already redirecting to another tunnel"
            exit 1
        }

        local cmds=""
        cmds+="get $(primary_dns_key)\n"
        cmds+="set ${dns_backup_key}\n"
        cmds+="d.init\n"
        cmds+="d.add ServerAddresses * ${addresses}\n"
        cmds+="d.add SearchDomains * ${search_domains}\n"
        cmds+="d.add SearchOrder # 5000\n"
        cmds+="set $(primary_dns_key)\n"
        echo -e "${cmds}" | /usr/sbin/scutil
    fi

    /usr/bin/dscacheutil -flushcache
}

function unset_dns {
    local n="$(find_compat_profile)"
    local match_domains="$(match_domains_string $n)"

    if [ -n "$match_domains" ]; then
        local search_domains="$(search_domains_string $n)"
        echo "remove ${itf_dns_key}" | /usr/sbin/scutil
        unset_search_domains "$search_domains"
    else
        # Do not unset if this tunnel did not set/backup DNS before
        local dns_backup_key="$(dns_backup_key)"
        [[ "${dns_backup_key}" =~ ${dev}/ ]] || return

        local cmds=""
        local servers="$(get_server_addresses)"
        local addresses="$(addresses_string $n)"
        # Only restore backup if the server addresses match
        if [ "${servers}" = "${addresses}" ]; then
            cmds+="get ${dns_backup_key}\n"
            cmds+="set $(primary_dns_key)\n"
        else
            echo "not restoring global DNS configuration, server addresses have changed"
        fi
        cmds+="remove ${dns_backup_key}\n"
        echo -e "${cmds}" | /usr/sbin/scutil
    fi

    /usr/bin/dscacheutil -flushcache
}

if [ "$script_type" = "dns-up" ]; then
    set_dns
else
    unset_dns
fi
