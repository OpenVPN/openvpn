/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016 Selva Nair <selva.nair@gmail.com>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef _WIN32

#ifndef OPENVPN_BLOCK_DNS_H
#define OPENVPN_BLOCK_DNS_H

typedef void (*block_dns_msg_handler_t) (DWORD err, const char *msg);

DWORD
delete_block_dns_filters(HANDLE engine);

DWORD
add_block_dns_filters(HANDLE *engine, int iface_index, const WCHAR *exe_path,
                      block_dns_msg_handler_t msg_handler_callback);

#endif
#endif
