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

[ -z "${dns_vars_file}" ] || . "${dns_vars_file}"

itf_dns_key="State:/Network/Service/openvpn-${dev}/DNS"
dns_backup_key="State:/Network/Service/openvpn-${dev}/DnsBackup"
dns_backup_key_pattern="State:/Network/Service/openvpn-.*/DnsBackup"

function primary_dns_key {
    local uuid=$(echo "show State:/Network/Global/IPv4" | /usr/sbin/scutil | grep "PrimaryService" | cut -d: -f2 | xargs)
    echo "Setup:/Network/Service/${uuid}/DNS"
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
    return $n
}

function get_search_domains {
    local search_domains=""
    local resolver=0
    /usr/sbin/scutil --dns | while read line; do
        if [[ "$line" =~ resolver.# ]]; then
            resolver=$((resolver+1))
        elif [ "$resolver" = 1 ] && [[ "$line" =~ search.domain ]]; then
            search_domains+="$(echo $line | cut -d: -f2 | xargs) "
        elif [ "$resolver" -gt 1 ]; then
            echo "$search_domains"
            break
        fi
    done
}

function set_search_domains {
    [ -n "$1" ] || return
    dns_key=$(primary_dns_key)
    search_domains="${1}$(get_search_domains)"

    local cmds=""
    cmds+="get ${dns_key}\n"
    cmds+="d.add SearchDomains * ${search_domains}\n"
    cmds+="set ${dns_key}\n"
    echo -e "${cmds}" | /usr/sbin/scutil
}

function unset_search_domains {
    [ -n "$1" ] || return
    dns_key=$(primary_dns_key)
    search_domains="$(get_search_domains)"
    search_domains=$(echo $search_domains | sed -e "s/$1//")

    local cmds=""
    cmds+="get ${dns_key}\n"
    cmds+="d.add SearchDomains * ${search_domains}\n"
    cmds+="set ${dns_key}\n"
    echo -e "${cmds}" | /usr/sbin/scutil
}

function set_dns {
    find_compat_profile
    local n=$?

    local i=1
    local addrs=""
    while :; do
        local addr_var=dns_server_${n}_address_${i}
        local addr="${!addr_var}"
        [ -n "$addr" ] || break

        local port_var=dns_server_${n}_port_${i}
        if [ -n "${!port_var}" ]; then
            if [[ "$addr" =~ : ]]; then
                addr="[$addr]"
            fi
            addrs+="${addr}:${!port_var}${sni} "
        else
            addrs+="${addr}${sni} "
        fi
        i=$((i+1))
    done

    i=1
    local match_domains=""
    while :; do
        domain_var=dns_server_${n}_resolve_domain_${i}
        [ -n "${!domain_var}" ] || break
        # Add as match domain, if it doesn't already exist
        [[ "$match_domains" =~ (^| )${!domain_var}( |$) ]] \
            || match_domains+="${!domain_var} "
        i=$((i+1))
    done

    i=1
    local search_domains=""
    while :; do
        domain_var=dns_search_domain_${i}
        [ -n "${!domain_var}" ] || break
        # Add as search domain, if it doesn't already exist
        [[ "$search_domains" =~ (^| )${!domain_var}( |$) ]] \
            || search_domains+="${!domain_var} "
        i=$((i+1))
    done

    if [ -n "$match_domains" ]; then
        local cmds=""
        cmds+="d.init\n"
        cmds+="d.add ServerAddresses * ${addrs}\n"
        cmds+="d.add SupplementalMatchDomains * ${match_domains}\n"
        cmds+="d.add SupplementalMatchDomainsNoSearch # 1\n"
        cmds+="add ${itf_dns_key}\n"
        echo -e "${cmds}" | /usr/sbin/scutil
        set_search_domains "$search_domains"
    else
        echo list ${dns_backup_key_pattern} | /usr/sbin/scutil | grep -q 'no key' || {
            echo "setting DNS failed, already redirecting to another tunnel"
            exit 1
        }

        local cmds=""
        cmds+="get $(primary_dns_key)\n"
        cmds+="set ${dns_backup_key}\n"
        cmds+="d.init\n"
        cmds+="d.add ServerAddresses * ${addrs}\n"
        cmds+="d.add SearchDomains * ${search_domains}\n"
        cmds+="d.add SearchOrder # 5000\n"
        cmds+="set $(primary_dns_key)\n"
        echo -e "${cmds}" | /usr/sbin/scutil
    fi

    /usr/bin/dscacheutil -flushcache
}

function unset_dns {
    find_compat_profile
    local n=$?

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

    domain_var=dns_server_${n}_resolve_domain_1
    if [ -n "${!domain_var}" ]; then
        echo "remove ${itf_dns_key}" | /usr/sbin/scutil
        unset_search_domains "$search_domains"
    else
        # Do not unset if this tunnel did not set/backup DNS before
        echo list ${dns_backup_key} | /usr/sbin/scutil | grep -qv 'no key' || return

        local cmds=""
        cmds+="get ${dns_backup_key}\n"
        cmds+="set $(primary_dns_key)\n"
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
