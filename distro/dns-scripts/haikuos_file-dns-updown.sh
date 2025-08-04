#!/bin/sh
#
# Simple OpenVPN up/down script for modifying Haiku OS resolv.conf
# (C) Copyright 2024 OpenVPN Inc <sales@openvpn.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Example env from openvpn (most are not applied):
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

set -e +u

only_standard_server_ports() {
    i=1
    while true; do
        eval addr=\"\$dns_server_${n}_address_${i}\"
        [ -n "$addr" ] || return 0

        eval port=\"\$dns_server_${n}_port_${i}\"
        [ -z "$port" -o "$port" = "53" ] || return 1

        i=$(expr $i + 1)
    done
}

conf=/boot/system/settings/network/resolv.conf
test -e "$conf" || exit 1
test -z "${dns_vars_file}" || . "${dns_vars_file}"
case "${script_type}" in
dns-up)
    n=1
    while :; do
        eval addr=\"\$dns_server_${n}_address_1\"
        [ -n "$addr" ] || {
            echo "setting DNS failed, no compatible server profile"
            exit 1
        }

        # Skip server profiles which require DNSSEC,
        # secure transport or use a custom port
        eval dnssec=\"\$dns_server_${n}_dnssec\"
        eval transport=\"\$dns_server_${n}_transport\"
        [ -z "$transport" -o "$transport" = "plain" ] \
            && [ -z "$dnssec" -o "$dnssec" = "no" ] \
            && only_standard_server_ports && break

        n=$(expr $n + 1)
    done

    eval addr1=\"\$dns_server_${n}_address_1\"
    eval addr2=\"\$dns_server_${n}_address_2\"
    eval addr3=\"\$dns_server_${n}_address_3\"
    text="### openvpn ${dev} begin ###\n"
    text="${text}nameserver $addr1\n"
    test -z "$addr2" || text="${text}nameserver $addr2\n"
    test -z "$addr3" || text="${text}nameserver $addr3\n"

    test -z "$dns_search_domain_1" || {
        for i in $(seq 1 6); do
            eval domains=\"$domains\$dns_search_domain_${i} \" || break
        done
        text="${text}search $domains\n"
    }
    text="${text}### openvpn ${dev} end ###"
    text="${text}\n$(cat ${conf})"

    echo "${text}" > "${conf}"
    ;;
dns-down)
    sed -i'' -e "/### openvpn ${dev} begin ###/,/### openvpn ${dev} end ###/d" "$conf"
    ;;
esac
