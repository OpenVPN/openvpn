/*
 *  error -- OpenVPN compatible error reporting API
 *           https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2018-2025 Simon Rozman <simon@rozman.si>
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

#include "error.h"


/* Globals */
unsigned int x_debug_level; /* GLOBAL */


void
x_msg(const unsigned int flags, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    x_msg_va(flags, format, arglist);
    va_end(arglist);
}
