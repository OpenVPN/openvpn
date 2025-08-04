
/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2016-2025 Selva Nair <selva.nair@gmail.com>
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

#ifndef VALIDATE_H
#define VALIDATE_H

#include "service.h"

/* Authorized groups who can use any options and config locations */
#define SYSTEM_ADMIN_GROUP L"Administrators"
#define OVPN_ADMIN_GROUP L"OpenVPN Administrators" /* may be set in HKLM\Software\OpenVPN\ovpn_admin_group */
#define OVPN_SERVICE_USER L"OpenVPNService" /* may be set in HKLM\Software\OpenVPN\ovpn_service_user */

/*
 * Check whether user is a member of Administrators group or
 * the group specified in ovpn_admin_group or
 * OpenVPN Virtual Service Account user
 */
BOOL
IsAuthorizedUser(PSID sid, const HANDLE token, const WCHAR *ovpn_admin_group, const WCHAR *ovpn_service_user);

BOOL
CheckOption(const WCHAR *workdir, int narg, WCHAR *argv[], const settings_t *s);

static inline BOOL
IsOption(const WCHAR *o)
{
    return (wcsncmp(o, L"--", 2) == 0);
}

#endif /* ifndef VALIDATE_H */
