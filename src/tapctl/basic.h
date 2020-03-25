/*
 *  basic -- Basic macros
 *           https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2018 Simon Rozman <simon@rozman.si>
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

#ifndef BASIC_H
#define BASIC_H

#ifdef _UNICODE
#define PRIsLPTSTR      "ls"
#define PRIsLPOLESTR    "ls"
#else
#define PRIsLPTSTR      "s"
#define PRIsLPOLESTR    "ls"
#endif
#define PRIXGUID        "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}"
#define PRIGUID_PARAM(g) \
    (g).Data1, (g).Data2, (g).Data3, (g).Data4[0], (g).Data4[1], (g).Data4[2], (g).Data4[3], (g).Data4[4], (g).Data4[5], (g).Data4[6], (g).Data4[7]
#define PRIGUID_PARAM_REF(g) \
    &(g).Data1, &(g).Data2, &(g).Data3, &(g).Data4[0], &(g).Data4[1], &(g).Data4[2], &(g).Data4[3], &(g).Data4[4], &(g).Data4[5], &(g).Data4[6], &(g).Data4[7]

#define __L(q)          L ## q
#define _L(q)           __L(q)

#ifndef _In_
#define _In_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _In_z_
#define _In_z_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _Inout_opt_
#define _Inout_opt_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Out_z_cap_
#define _Out_z_cap_(n)
#endif

#endif /* ifndef BASIC_H */
