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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
    L"pull-filter",
    L"script-security",

    NULL                                /* last value */
};

static BOOL IsUserInGroup(PSID sid, const PTOKEN_GROUPS groups, const WCHAR *group_name);

static PTOKEN_GROUPS GetTokenGroups(const HANDLE token);

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
#ifndef UNICODE
    WCHAR widepath[MAX_PATH];
#endif

    /* convert fname to full path */
    if (PathIsRelativeW(fname) )
    {
        openvpn_swprintf(tmp, _countof(tmp), L"%s\\%s", workdir, fname);
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
 * the group specified in ovpn_admin_group
 */
BOOL
IsAuthorizedUser(PSID sid, const HANDLE token, const WCHAR *ovpn_admin_group)
{
    const WCHAR *admin_group[2];
    WCHAR username[MAX_NAME];
    WCHAR domain[MAX_NAME];
    WCHAR sysadmin_group[MAX_NAME];
    DWORD len = MAX_NAME;
    BOOL ret = FALSE;
    SID_NAME_USE sid_type;

    /* Get username */
    if (!LookupAccountSidW(NULL, sid, username, &len, domain, &len, &sid_type))
    {
        MsgToEventLog(M_SYSERR, TEXT("LookupAccountSid"));
        /* not fatal as this is now used only for logging */
        username[0] = '\0';
        domain[0] = '\0';
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
    admin_group[1] = ovpn_admin_group;

    PTOKEN_GROUPS token_groups = GetTokenGroups(token);
    for (int i = 0; i < 2; ++i)
    {
        ret = IsUserInGroup(sid, token_groups, admin_group[i]);
        if (ret)
        {
            MsgToEventLog(M_INFO, TEXT("Authorizing user '%s@%s' by virtue of membership in group '%s'"),
                          username, domain, admin_group[i]);
            goto out;
        }
    }

out:
    free(token_groups);
    return ret;
}

/**
 * Get a list of groups in token.
 * Returns a pointer to TOKEN_GROUPS struct or NULL on error.
 * The caller should free the returned pointer.
 */
static PTOKEN_GROUPS
GetTokenGroups(const HANDLE token)
{
    PTOKEN_GROUPS groups = NULL;
    DWORD buf_size = 0;

    if (!GetTokenInformation(token, TokenGroups, groups, buf_size, &buf_size)
        && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        groups = malloc(buf_size);
    }
    if (!groups)
    {
        MsgToEventLog(M_SYSERR, L"GetTokenGroups");
    }
    else if (!GetTokenInformation(token, TokenGroups, groups, buf_size, &buf_size))
    {
        MsgToEventLog(M_SYSERR, L"GetTokenInformation");
        free(groups);
    }
    return groups;
}

/*
 * Find SID from name
 *
 * On input sid buffer should have space for at least sid_size bytes.
 * Returns true on success, false on failure.
 * Suggest: in caller allocate sid to hold SECURITY_MAX_SID_SIZE bytes
 */
static BOOL
LookupSID(const WCHAR *name, PSID sid, DWORD sid_size)
{
    SID_NAME_USE su;
    WCHAR domain[MAX_NAME];
    DWORD dlen = _countof(domain);

    if (!LookupAccountName(NULL, name, sid, &sid_size, domain, &dlen, &su))
    {
        return FALSE; /* not fatal as the group may not exist */
    }
    return TRUE;
}

/**
 * User is in group if the token groups contain the SID of the group
 * of if the user is a direct member of the group. The latter check
 * catches dynamic changes in group membership in the local user
 * database not reflected in the token.
 * If token_groups or sid is NULL the corresponding check is skipped.
 *
 * Using sid and list of groups in token avoids reference to domains so that
 * this could be completed without access to a Domain Controller.
 *
 * Returns true if the user is in the group, false otherwise.
 */
static BOOL
IsUserInGroup(PSID sid, const PTOKEN_GROUPS token_groups, const WCHAR *group_name)
{
    BOOL ret = FALSE;
    DWORD_PTR resume = 0;
    DWORD err;
    BYTE grp_sid[SECURITY_MAX_SID_SIZE];
    int nloop = 0; /* a counter used to not get stuck in the do .. while() */

    /* first check in the token groups */
    if (token_groups && LookupSID(group_name, (PSID) grp_sid, _countof(grp_sid)))
    {
        for (DWORD i = 0; i < token_groups->GroupCount; ++i)
        {
            if (EqualSid((PSID) grp_sid, token_groups->Groups[i].Sid))
            {
                return TRUE;
            }
        }
    }

    /* check user's SID is a member of the group */
    if (!sid)
    {
        return FALSE;
    }
    do
    {
        DWORD nread, nmax;
        LOCALGROUP_MEMBERS_INFO_0 *members = NULL;
        err = NetLocalGroupGetMembers(NULL, group_name, 0, (LPBYTE *) &members,
                                      MAX_PREFERRED_LENGTH, &nread, &nmax, &resume);
        if ((err != NERR_Success && err != ERROR_MORE_DATA))
        {
            break;
        }
        /* If a match is already found, ret == TRUE and the loop is skipped */
        for (DWORD i = 0; i < nread && !ret; ++i)
        {
            ret = EqualSid(members[i].lgrmi0_sid, sid);
        }
        NetApiBufferFree(members);
        /* MSDN says the lookup should always iterate until err != ERROR_MORE_DATA */
    } while (err == ERROR_MORE_DATA && nloop++ < 100);

    if (err != NERR_Success && err != NERR_GroupNotFound)
    {
        SetLastError(err);
        MsgToEventLog(M_SYSERR, TEXT("In NetLocalGroupGetMembers for group '%s'"), group_name);
    }

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
