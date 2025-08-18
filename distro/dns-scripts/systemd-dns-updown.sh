#!/bin/bash
#
# dns-updown - add/remove openvpn provided DNS information
#
# Copyright (C) 2024-2025 OpenVPN Inc <sales@openvpn.net>
#
# SPDX-License-Identifier: GPL-2.0
#
# Add/remove openvpn DNS settings from the env into/from
# the system. Supported backends in this order:
#
#   * systemd-resolved
#   * resolvconf
#   * /etc/resolv.conf file
#
# Example env from openvpn (not all are always applied):
#
#   dns_vars_file /tmp/openvpn_dvf_58b95c0c97b2db43afb5d745f986c53c.tmp
#
#      or
#
#   dev tun0
#   script_type dns-up
#   dns_search_domain_1 mycorp.in
#   dns_search_domain_2 eu.mycorp.com
#   dns_server_1_address_1 192.168.99.254
#   dns_server_1_address_2 fd00::99:53
#   dns_server_1_port_1 53
#   dns_server_1_port_2 53
#   dns_server_1_resolve_domain_1 mycorp.in
#   dns_server_1_resolve_domain_2 eu.mycorp.com
#   dns_server_1_dnssec true
#   dns_server_1_transport DoH
#   dns_server_1_sni dns.mycorp.in
#

[ -z "${dns_vars_file}" ] || . "${dns_vars_file}"

function do_resolved_servers {
    local sni=""
    local transport_var=dns_server_${n}_transport
    local sni_var=dns_server_${n}_sni
    [ "${!transport_var}" = "DoT" ] && sni="#${!sni_var}"

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

    resolvectl dns "$dev" $addrs
}

function do_resolved_domains {
    local list=""
    for domain_var in ${!dns_search_domain_*}; do
        list+="${!domain_var} "
    done
    local domain_var=dns_server_${n}_resolve_domain_1
    if [ -z "${!domain_var}" ]; then
        resolvectl default-route "$dev" true
        list+="~."
    else
        resolvectl default-route "$dev" false
        local i=1
        while :; do
            domain_var=dns_server_${n}_resolve_domain_${i}
            [ -n "${!domain_var}" ] || break
            # Add as split domain (~ prefix), if it doesn't already exist
            [[ "$list" =~ (^| )"${!domain_var}"( |$) ]] \
                || list+="~${!domain_var} "
            i=$((i+1))
        done
    fi

    resolvectl domain "$dev" $list
}

function do_resolved_dnssec {
    local dnssec_var=dns_server_${n}_dnssec
    if [ "${!dnssec_var}" = "optional" ]; then
        resolvectl dnssec "$dev" allow-downgrade
    elif [ "${!dnssec_var}" = "yes" ]; then
        resolvectl dnssec "$dev" true
    else
        resolvectl dnssec "$dev" false
    fi
}

function do_resolved_dnsovertls {
    local transport_var=dns_server_${n}_transport
    if [ "${!transport_var}" = "DoT" ]; then
        resolvectl dnsovertls "$dev" true
    else
        resolvectl dnsovertls "$dev" false
    fi
}

function do_resolved {
    [[ "$(readlink /etc/resolv.conf)" =~ systemd ]] || return 1

    n=1
    while :; do
        local addr_var=dns_server_${n}_address_1
        [ -n "${!addr_var}" ] || {
            echo "setting DNS failed, no compatible server profile"
            return 1
        }

        # Skip server profiles which require DNS-over-HTTPS
        local transport_var=dns_server_${n}_transport
        [ -n "${!transport_var}" -a "${!transport_var}" = "DoH" ] || break

        n=$((n+1))
    done

    if [ "$script_type" = "dns-up" ]; then
        echo "setting DNS using resolvectl"
        do_resolved_servers
        do_resolved_domains
        do_resolved_dnssec
        do_resolved_dnsovertls
    else
        echo "unsetting DNS using resolvectl"
        resolvectl revert "$dev"
    fi

    return 0
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

function resolv_conf_compat_profile {
    local n=1
    while :; do
        local server_addr_var=dns_server_${n}_address_1
        [ -n "${!server_addr_var}" ] || {
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

function do_resolvconf {
    [ -x /sbin/resolvconf ] || return 1

    resolv_conf_compat_profile
    local n=$?

    if [ "$script_type" = "dns-up" ]; then
        echo "setting DNS using resolvconf"
        local domains=""
        for domain_var in ${!dns_search_domain_*}; do
            domains+="${!domain_var} "
        done
        {
            local i=1
            local maxns=3
            while [ "${i}" -le "${maxns}" ]; do
                local addr_var=dns_server_${n}_address_${i}
                [ -n "${!addr_var}" ] || break
                echo "nameserver ${!addr_var}"
                i=$((i+1))
            done
            [ -z "$domains" ] || echo "search $domains"
        } | /sbin/resolvconf -a "$dev"
    else
        echo "unsetting DNS using resolvconf"
        /sbin/resolvconf -d "$dev"
    fi

    return 0
}

function do_resolv_conf_file {
    conf=/etc/resolv.conf
    test -e "$conf" || exit 1

    resolv_conf_compat_profile
    local n=$?

    if [ "$script_type" = "dns-up" ]; then
        echo "setting DNS using resolv.conf file"

        local addr1_var=dns_server_${n}_address_1
        local addr2_var=dns_server_${n}_address_2
        local addr3_var=dns_server_${n}_address_3
        text="### openvpn ${dev} begin ###\n"
        text="${text}nameserver ${!addr1_var}\n"
        test -z "${!addr2_var}" || text="${text}nameserver ${!addr2_var}\n"
        test -z "${!addr3_var}" || text="${text}nameserver ${!addr3_var}\n"

        test -z "$dns_search_domain_1" || {
            for i in $(seq 1 6); do
                eval domains=\"$domains\$dns_search_domain_${i} \" || break
            done
            text="${text}search $domains\n"
        }
        text="${text}### openvpn ${dev} end ###"

        sed -i "1i${text}" "$conf"
    else
        echo "unsetting DNS using resolv.conf file"
        sed -i "/### openvpn ${dev} begin ###/,/### openvpn ${dev} end ###/d" "$conf"
    fi

    return 0
}

do_resolved || do_resolvconf || do_resolv_conf_file || {
    echo "setting DNS failed, no method succeeded"
    exit 1
}
