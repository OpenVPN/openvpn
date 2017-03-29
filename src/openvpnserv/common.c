/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2011-2017 Heiko Hund <heiko.hund@sophos.com>
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

#include <service.h>
#include <validate.h>
/*
 * These are necessary due to certain buggy implementations of (v)snprintf,
 * that don't guarantee null termination for size > 0.
 */
int
openvpn_vsntprintf(LPTSTR str, size_t size, LPCTSTR format, va_list arglist)
{
    int len = -1;
    if (size > 0)
    {
        len = _vsntprintf(str, size, format, arglist);
        str[size - 1] = 0;
    }
    return (len >= 0 && len < size);
}
int
openvpn_sntprintf(LPTSTR str, size_t size, LPCTSTR format, ...)
{
    va_list arglist;
    int len = -1;
    if (size > 0)
    {
        va_start(arglist, format);
        len = openvpn_vsntprintf(str, size, format, arglist);
        va_end(arglist);
    }
    return len;
}

#define REG_KEY  TEXT("SOFTWARE\\" PACKAGE_NAME)

static DWORD
GetRegString(HKEY key, LPCTSTR value, LPTSTR data, DWORD size)
{
    DWORD type;
    LONG status = RegQueryValueEx(key, value, NULL, &type, (LPBYTE) data, &size);

    if (status == ERROR_SUCCESS && type != REG_SZ)
    {
        status = ERROR_DATATYPE_MISMATCH;
    }

    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return MsgToEventLog(M_SYSERR, TEXT("Error querying registry value: HKLM\\%s\\%s"), REG_KEY, value);
    }

    return ERROR_SUCCESS;
}


DWORD
GetOpenvpnSettings(settings_t *s)
{
    TCHAR priority[64];
    TCHAR append[2];
    DWORD error;
    HKEY key;

    LONG status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_KEY, 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return MsgToEventLog(M_SYSERR, TEXT("Could not open Registry key HKLM\\%s not found"), REG_KEY);
    }

    error = GetRegString(key, TEXT("exe_path"), s->exe_path, sizeof(s->exe_path));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("config_dir"), s->config_dir, sizeof(s->config_dir));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("config_ext"), s->ext_string, sizeof(s->ext_string));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("log_dir"), s->log_dir, sizeof(s->log_dir));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("priority"), priority, sizeof(priority));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("log_append"), append, sizeof(append));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    /* read if present, else use default */
    error = GetRegString(key, TEXT("ovpn_admin_group"), s->ovpn_admin_group, sizeof(s->ovpn_admin_group));
    if (error != ERROR_SUCCESS)
    {
        openvpn_sntprintf(s->ovpn_admin_group, _countof(s->ovpn_admin_group), OVPN_ADMIN_GROUP);
        error = 0; /* this error is not fatal */
    }
    /* set process priority */
    if (!_tcsicmp(priority, TEXT("IDLE_PRIORITY_CLASS")))
    {
        s->priority = IDLE_PRIORITY_CLASS;
    }
    else if (!_tcsicmp(priority, TEXT("BELOW_NORMAL_PRIORITY_CLASS")))
    {
        s->priority = BELOW_NORMAL_PRIORITY_CLASS;
    }
    else if (!_tcsicmp(priority, TEXT("NORMAL_PRIORITY_CLASS")))
    {
        s->priority = NORMAL_PRIORITY_CLASS;
    }
    else if (!_tcsicmp(priority, TEXT("ABOVE_NORMAL_PRIORITY_CLASS")))
    {
        s->priority = ABOVE_NORMAL_PRIORITY_CLASS;
    }
    else if (!_tcsicmp(priority, TEXT("HIGH_PRIORITY_CLASS")))
    {
        s->priority = HIGH_PRIORITY_CLASS;
    }
    else
    {
        SetLastError(ERROR_INVALID_DATA);
        error = MsgToEventLog(M_SYSERR, TEXT("Unknown priority name: %s"), priority);
        goto out;
    }

    /* set log file append/truncate flag */
    if (append[0] == TEXT('0'))
    {
        s->append = FALSE;
    }
    else if (append[0] == TEXT('1'))
    {
        s->append = TRUE;
    }
    else
    {
        SetLastError(ERROR_INVALID_DATA);
        error = MsgToEventLog(M_ERR, TEXT("Log file append flag (given as '%s') must be '0' or '1'"), append);
        goto out;
    }

out:
    RegCloseKey(key);
    return error;
}


LPCTSTR
GetLastErrorText()
{
    static TCHAR buf[256];
    DWORD len;
    LPTSTR tmp = NULL;

    len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                        NULL, GetLastError(), LANG_NEUTRAL, (LPTSTR)&tmp, 0, NULL);

    if (len == 0 || (long) _countof(buf) < (long) len + 14)
    {
        buf[0] = TEXT('\0');
    }
    else
    {
        tmp[_tcslen(tmp) - 2] = TEXT('\0'); /* remove CR/LF characters */
        openvpn_sntprintf(buf, _countof(buf), TEXT("%s (0x%x)"), tmp, GetLastError());
    }

    if (tmp)
    {
        LocalFree(tmp);
    }

    return buf;
}


DWORD
MsgToEventLog(DWORD flags, LPCTSTR format, ...)
{
    HANDLE hEventSource;
    TCHAR msg[2][256];
    DWORD error = 0;
    LPCTSTR err_msg = TEXT("");
    va_list arglist;

    if (flags & MSG_FLAGS_SYS_CODE)
    {
        error = GetLastError();
        err_msg = GetLastErrorText();
    }

    hEventSource = RegisterEventSource(NULL, APPNAME);
    if (hEventSource != NULL)
    {
        openvpn_sntprintf(msg[0], _countof(msg[0]),
                          TEXT("%s%s: %s"), APPNAME,
                          (flags & MSG_FLAGS_ERROR) ? TEXT(" error") : TEXT(""), err_msg);

        va_start(arglist, format);
        openvpn_vsntprintf(msg[1], _countof(msg[1]), format, arglist);
        va_end(arglist);

        const TCHAR *mesg[] = { msg[0], msg[1] };
        ReportEvent(hEventSource, flags & MSG_FLAGS_ERROR ?
                    EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE,
                    0, 0, NULL, 2, 0, mesg, NULL);
        DeregisterEventSource(hEventSource);
    }

    return error;
}

/* Convert a utf8 string to utf16. Caller should free the result */
wchar_t *
utf8to16(const char *utf8)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    wchar_t *utf16 = malloc(n * sizeof(wchar_t));
    if (!utf16)
    {
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, utf16, n);
    return utf16;
}
