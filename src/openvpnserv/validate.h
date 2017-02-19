
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

#ifndef VALIDATE_H
#define VALIDATE_H

#include "service.h"

/* Authorized groups who can use any options and config locations */
#define SYSTEM_ADMIN_GROUP TEXT("Administrators")
#define OVPN_ADMIN_GROUP TEXT("OpenVPN Administrators")
/* The last one may be reset in registry: HKLM\Software\OpenVPN\ovpn_admin_group */

BOOL
IsAuthorizedUser(PSID sid, const HANDLE token, const WCHAR *ovpn_admin_group);

BOOL
CheckOption(const WCHAR *workdir, int narg, WCHAR *argv[], const settings_t *s);

static inline BOOL
IsOption(const WCHAR *o)
{
    return (wcsncmp(o, L"--", 2) == 0);
}

#endif /* ifndef VALIDATE_H */
