/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2021 Sentyron B.V. <openvpn@sentyron.com>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef MOCK_MSG_H
#define MOCK_MSG_H

/**
 * Mock debug level defaults to 0, which gives clean(-ish) test reports.  Call
 * this function from your test driver to increase debug output when you
 * need debug output.
 */
void mock_set_debug_level(msglvl_t level);

#define MOCK_MSG_BUF 2048

extern bool fatal_error_triggered;
extern char mock_msg_buf[MOCK_MSG_BUF];

msglvl_t mock_get_debug_level(void);

void mock_set_print_debug_level(msglvl_t level);

#endif /* MOCK_MSG */
