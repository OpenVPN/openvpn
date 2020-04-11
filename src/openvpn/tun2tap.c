/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
Author: pengtianabc@hotmail.com
Date: 2020-4-12 11:17:33
Function: simulate arp logical for tun device on client
TODO: ship for server, but i think that not worth
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
// #include "openvpn.h"
#include "tun2tap.h"

#include "memdbg.h"

static inline void dump_hex(const uint8_t *buf, int len, char *name){
        int i = 0;
        printf("===buf name:%s, len:%d==\n", name, len);
        for(; i < len; i++){
                printf("%02x", buf[i]);
        }
        printf("\n======================\n");
}

/*
 * Should we handle arp to the remote?
 */
bool
check_tun2tap_send_dowork(struct context *c, int flag)
{
    int ret = true;
    if (!c->options.tun2tap){
        return ret;
    }
    if (TUN2TAP_FLAG_ENCAP == flag){
        dmsg(D_TUN2TAP, "TUN2TAP: encap data from tun");
        // read from tun, check and send arp to link
        if ( BLEN(&c->c2.buf) >= sizeof(struct openvpn_iphdr)){
            struct openvpn_ethhdr hdr = {0};
            struct openvpn_iphdr *ip_hdr = BPTR(&c->c2.buf);
            struct openvpn_ipv6hdr *ipv6_hdr = BPTR(&c->c2.buf);
            int v = OPENVPN_IPH_GET_VER(ip_hdr->version_len);
            memcpy(hdr.dest, c->c1.tuntap->remote_mac_addr, OPENVPN_ETH_ALEN);
            memcpy(hdr.source, c->options.lladdr_v, OPENVPN_ETH_ALEN);
            
            if (0 == memcmp(hdr.dest, "\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00") - 1)){
                // build request
                // overwirte arp to buf
                struct openvpn_arp arp = { 0 };
                arp.mac_addr_type = htons(0x0001);
                arp.proto_addr_type = htons(0x0800);
                arp.mac_addr_size = 0x06;
                arp.proto_addr_size = 0x04;
                arp.arp_command = htons(ARP_REQUEST);
                memcpy(arp.mac_src, hdr.source, OPENVPN_ETH_ALEN);
                memcpy(arp.mac_dest, "\x00\x00\x00\x00\x00\x00", OPENVPN_ETH_ALEN);
                memcpy(hdr.dest, "\xff\xff\xff\xff\xff\xff", OPENVPN_ETH_ALEN);
                hdr.proto = htons(OPENVPN_ETH_P_ARP);
                switch (v)
                {
                case 4:
                    arp.ip_src = ip_hdr->saddr;
                    arp.ip_dest = ip_hdr->daddr;
                    break;
                case 6: 
                    // hdr.proto = htons(OPENVPN_ETH_P_IPV6);
                    // memcpy(&arp.ip_src, &ipv6_hdr->saddr, sizeof(ipv6_hdr->saddr));
                    // memcpy(&arp.ip_dest, &ipv6_hdr->daddr, sizeof(ipv6_hdr->daddr));
                default:
                    break;
                }
                buf_clear(&c->c2.buf);
                buf_write(&c->c2.buf, &hdr, sizeof(hdr));
                buf_write(&c->c2.buf, &arp, sizeof(arp));
            } else {
                switch (v)
                {
                case 4:
                    hdr.proto = htons(OPENVPN_ETH_P_IPV4);
                    break;
                case 6: 
                    hdr.proto = htons(OPENVPN_ETH_P_IPV6);
                default:
                    break;
                }
                ASSERT(buf_write_prepend(&c->c2.buf, &hdr, sizeof(hdr)));
            }
            dmsg(D_TUN2TAP, "dest addr is: %02x:%02x:%02x:%02x:%02x:%02x"
                , hdr.dest[0]
                , hdr.dest[1]
                , hdr.dest[2]
                , hdr.dest[3]
                , hdr.dest[4]
                , hdr.dest[5]
            );
            dmsg(D_TUN2TAP, "source addr is: %02x:%02x:%02x:%02x:%02x:%02x"
                , hdr.source[0]
                , hdr.source[1]
                , hdr.source[2]
                , hdr.source[3]
                , hdr.source[4]
                , hdr.source[5]
            );
        }
    } else if (TUN2TAP_FLAG_DECAP == flag){
        dmsg(D_TUN2TAP, "TUN2TAP: decap data to tun");
        // will write to tun, check is arp request, and save remote addr
        if (BLEN(&c->c2.buf) >= sizeof(struct openvpn_ethhdr)){
            struct openvpn_ethhdr *hdr = (struct openvpn_ethhdr *) BPTR(&c->c2.buf);
            memcpy(c->c1.tuntap->remote_mac_addr, hdr->source, OPENVPN_ETH_ALEN);
            dmsg(D_TUN2TAP, "saved remote mac: %02x:%02x:%02x:%02x:%02x:%02x"
                    , c->c1.tuntap->remote_mac_addr[0]
                    , c->c1.tuntap->remote_mac_addr[1]
                    , c->c1.tuntap->remote_mac_addr[2]
                    , c->c1.tuntap->remote_mac_addr[3]
                    , c->c1.tuntap->remote_mac_addr[4]
                    , c->c1.tuntap->remote_mac_addr[5]
            );
            if (hdr->proto == htons(OPENVPN_ETH_P_ARP)){
                if (BLEN(&c->c2.buf) >= sizeof(struct openvpn_ethhdr) + sizeof(struct openvpn_arp)){
                    struct openvpn_arp *arp_in = (struct openvpn_arp *)(BPTR(&c->c2.buf) + sizeof(struct openvpn_ethhdr));
                    if (arp_in->arp_command == htons(ARP_REPLY)){
                        dmsg(D_TUN2TAP, "TUN2TAP: ignore arp reply");
                        buf_clear(&c->c2.buf);
                        ret = false;
                    } else if (arp_in->arp_command == htons(ARP_REQUEST) ){
                        if (arp_in->ip_dest == htonl(c->c1.tuntap->local)){
                            // build reply
                            // write arp to link
                            struct openvpn_ethhdr hdr_out = {
                                .proto=htons(OPENVPN_ETH_P_ARP)
                            };
                            struct openvpn_arp arp_out = { 0 };
                            arp_out.mac_addr_type = htons(0x0001);
                            arp_out.proto_addr_type = htons(0x0800);
                            arp_out.mac_addr_size = 0x06;
                            arp_out.proto_addr_size = 0x04;
                            arp_out.arp_command = htons(ARP_REPLY);
                            memcpy(arp_out.mac_src, c->options.lladdr_v, OPENVPN_ETH_ALEN);
                            memcpy(arp_out.mac_dest, arp_in->mac_src, OPENVPN_ETH_ALEN);
                            memcpy(hdr_out.source, c->options.lladdr_v, OPENVPN_ETH_ALEN);
                            memcpy(hdr_out.dest, c->c1.tuntap->remote_mac_addr, OPENVPN_ETH_ALEN);
                            arp_out.ip_src = arp_in->ip_dest;
                            arp_out.ip_dest = arp_in->ip_src;
                            buf_clear(&c->c2.buf);
                            // dump_hex(BPTR(&c->c2.buf), BLEN(&c->c2.buf), "after clear");
                            buf_write(&c->c2.buf, &hdr_out, sizeof(hdr_out));
                            // dump_hex(BPTR(&c->c2.buf), BLEN(&c->c2.buf), "after write ether");
                            buf_write(&c->c2.buf, &arp_out, sizeof(arp_out));
                            // dump_hex(BPTR(&c->c2.buf), BLEN(&c->c2.buf), "after write arp");
                            encrypt_sign(c, true);
                            dmsg(D_TUN2TAP, "TUN2TAP: build arp reply success");
                        } else {
                            dmsg(D_TUN2TAP, "TUN2TAP: ignore any arp request not to me dest:%x me:%x", ntohl(arp_in->ip_dest), c->c1.tuntap->local);
                            buf_clear(&c->c2.buf);
                            ret = false;
                        }
                    } else{
                        dmsg(D_TUN2TAP, "TUN2TAP: ignore uknown arp type: %x", ntohs(arp_in->arp_command));
                        buf_clear(&c->c2.buf);
                        ret = false;
                    }
                }
            } else {
                buf_advance(&c->c2.to_tun, sizeof(struct openvpn_ethhdr));
            }
        }
    }
    return ret;
}
