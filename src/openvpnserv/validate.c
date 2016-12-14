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

#include "validate.h"

#include <lmaccess.h>
#include <shlwapi.h>
#include <lm.h>

static const WCHAR *white_list[] =
{
    L"auth-retry",
    L"config",
    L"log",
    L"log-append",
    L"management",
    L"management-forget-disconnect",
    L"management-hold",
    L"management-query-passwords",
    L"management-query-proxy",
    L"management-signal",
    L"management-up-down",
    L"mute",
    L"setenv",
    L"service",
    L"verb",

    NULL                                /* last value */
};

/*
 * Check workdir\fname is inside config_dir
 * The logic here is simple: we may reject some valid paths if ..\ is in any of the strings
 */
static BOOL
CheckConfigPath(const WCHAR *workdir, const WCHAR *fname, const settings_t *s)
{
    WCHAR tmp[MAX_PATH];
    const WCHAR *config_file = NULL;
    const WCHAR *config_dir = NULL;

    /* convert fname to full path */
    if (PathIsRelativeW(fname) )
    {
        snwprintf(tmp, _countof(tmp), L"%s\\%s", workdir, fname);
        tmp[_countof(tmp)-1] = L'\0';
        config_file = tmp;
    }
    else
    {
        config_file = fname;
    }

#ifdef UNICODE
    config_dir = s->config_dir;
#else
    if (MultiByteToWideChar(CP_UTF8, 0, s->config_dir, -1, widepath, MAX_PATH) == 0)
    {
        MsgToEventLog(M_SYSERR, TEXT("Failed to convert config_dir name to WideChar"));
        return FALSE;
    }
    config_dir = widepath;
#endif

    if (wcsncmp(config_dir, config_file, wcslen(config_dir)) == 0
        && wcsstr(config_file + wcslen(config_dir), L"..") == NULL)
    {
        return TRUE;
    }

    return FALSE;
}


/*
 * A simple linear search meant for a small wchar_t *array.
 * Returns index to the item if found, -1 otherwise.
 */
static int
OptionLookup(const WCHAR *name, const WCHAR *white_list[])
{
    int i;

    for (i = 0; white_list[i]; i++)
    {
        if (wcscmp(white_list[i], name) == 0)
        {
            return i;
        }
    }

    return -1;
}

/*
 * The Administrators group may be localized or renamed by admins.
 * Get the local name of the group using the SID.
 */
static BOOL
GetBuiltinAdminGroupName(WCHAR *name, DWORD nlen)
{
    BOOL b = FALSE;
    PSID admin_sid = NULL;
    DWORD sid_size = SECURITY_MAX_SID_SIZE;
    SID_NAME_USE snu;

    WCHAR domain[MAX_NAME];
    DWORD dlen = _countof(domain);

    admin_sid = malloc(sid_size);
    if (!admin_sid)
    {
        return FALSE;
    }

    b = CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid,  &sid_size);
    if (b)
    {
        b = LookupAccountSidW(NULL, admin_sid, name, &nlen, domain, &dlen, &snu);
    }

    free(admin_sid);

    return b;
}

/*
 * Check whether user is a member of Administrators group or
 * the group specified in s->ovpn_admin_group
 */
BOOL
IsAuthorizedUser(SID *sid, settings_t *s)
{
    LOCALGROUP_USERS_INFO_0 *groups = NULL;
    DWORD nread;
    DWORD nmax;
    WCHAR *tmp = NULL;
    const WCHAR *admin_group[2];
    WCHAR username[MAX_NAME];
    WCHAR domain[MAX_NAME];
    WCHAR sysadmin_group[MAX_NAME];
    DWORD err, len = MAX_NAME;
    int i;
    BOOL ret = FALSE;
    SID_NAME_USE sid_type;

    /* Get username */
    if (!LookupAccountSidW(NULL, sid, username, &len, domain, &len, &sid_type))
    {
        MsgToEventLog(M_SYSERR, TEXT("LookupAccountSid"));
        goto out;
    }

    /* Get an array of groups the user is member of */
    err = NetUserGetLocalGroups(NULL, username, 0, LG_INCLUDE_INDIRECT, (LPBYTE *) &groups,
                                MAX_PREFERRED_LENGTH, &nread, &nmax);
    if (err && err != ERROR_MORE_DATA)
    {
        SetLastError(err);
        MsgToEventLog(M_SYSERR, TEXT("NetUserGetLocalGroups"));
        goto out;
    }

    if (GetBuiltinAdminGroupName(sysadmin_group, _countof(sysadmin_group)))
    {
        admin_group[0] = sysadmin_group;
    }
    else
    {
        MsgToEventLog(M_SYSERR, TEXT("Failed to get the name of Administrators group. Using the default."));
        /* use the default value */
        admin_group[0] = SYSTEM_ADMIN_GROUP;
    }

#ifdef UNICODE
    admin_group[1] = s->ovpn_admin_group;
#else
    tmp = NULL;
    len = MultiByteToWideChar(CP_UTF8, 0, s->ovpn_admin_group, -1, NULL, 0);
    if (len == 0 || (tmp = malloc(len*sizeof(WCHAR))) == NULL)
    {
        MsgToEventLog(M_SYSERR, TEXT("Failed to convert admin group name to WideChar"));
        goto out;
    }
    MultiByteToWideChar(CP_UTF8, 0, s->ovpn_admin_group, -1, tmp, len);
    admin_group[1] = tmp;
#endif

    /* Check if user's groups include any of the admin groups */
    for (i = 0; i < nread; i++)
    {
        if (wcscmp(groups[i].lgrui0_name, admin_group[0]) == 0
            || wcscmp(groups[i].lgrui0_name, admin_group[1]) == 0
            )
        {
            MsgToEventLog(M_INFO, TEXT("Authorizing user %s by virtue of membership in group %s"),
                          username, groups[i].lgrui0_name);
            ret = TRUE;
            break;
        }
    }

out:
    if (groups)
    {
        NetApiBufferFree(groups);
    }
    free(tmp);

    return ret;
}

/*
 * Check whether option argv[0] is white-listed. If argv[0] == "--config",
 * also check that argv[1], if present, passes CheckConfigPath().
 * The caller should set argc to the number of valid elements in argv[] array.
 */
BOOL
CheckOption(const WCHAR *workdir, int argc, WCHAR *argv[], const settings_t *s)
{
    /* Do not modify argv or *argv -- ideally it should be const WCHAR *const *, but alas...*/

    if (wcscmp(argv[0], L"--config") == 0
        && argc > 1
        && !CheckConfigPath(workdir, argv[1], s)
        )
    {
        return FALSE;
    }

    /* option name starts at 2 characters from argv[i] */
    if (OptionLookup(argv[0] + 2, white_list) == -1)   /* not found */
    {
        return FALSE;
    }

    return TRUE;
}
