/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2011-2021 Heiko Hund <heiko.hund@sophos.com>
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

#include "service.h"
#include "validate.h"

LPCTSTR service_instance = TEXT("");
static wchar_t win_sys_path[MAX_PATH];

/*
 * These are necessary due to certain buggy implementations of (v)snprintf,
 * that don't guarantee null termination for size > 0.
 */
BOOL
openvpn_vswprintf(LPTSTR str, size_t size, LPCTSTR format, va_list arglist)
{
    int len = -1;
    if (size > 0)
    {
        len = vswprintf_s(str, size, format, arglist);
        str[size - 1] = 0;
    }
    return (len >= 0 && (size_t)len < size);
}

BOOL
openvpn_swprintf(LPTSTR str, size_t size, LPCTSTR format, ...)
{
    va_list arglist;
    BOOL res = FALSE;
    if (size > 0)
    {
        va_start(arglist, format);
        res = openvpn_vswprintf(str, size, format, arglist);
        va_end(arglist);
    }
    return res;
}

static DWORD
GetRegString(HKEY key, LPCTSTR value, LPTSTR data, DWORD size, LPCTSTR default_value)
{
    LONG status = RegGetValue(key, NULL, value, RRF_RT_REG_SZ,
                              NULL, (LPBYTE) data, &size);

    if (status == ERROR_FILE_NOT_FOUND && default_value)
    {
        size_t len = size/sizeof(data[0]);
        if (openvpn_swprintf(data, len, default_value))
        {
            status = ERROR_SUCCESS;
        }
    }

    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return MsgToEventLog(M_SYSERR, TEXT("Error querying registry value: HKLM\\SOFTWARE\\" PACKAGE_NAME "%ls\\%ls"), service_instance, value);
    }

    return ERROR_SUCCESS;
}


DWORD
GetOpenvpnSettings(settings_t *s)
{
    TCHAR reg_path[256];
    TCHAR priority[64];
    TCHAR append[2];
    DWORD error;
    HKEY key;
    TCHAR install_path[MAX_PATH];
    TCHAR default_value[MAX_PATH];

    openvpn_swprintf(reg_path, _countof(reg_path), TEXT("SOFTWARE\\" PACKAGE_NAME "%ls"), service_instance);

    LONG status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return MsgToEventLog(M_SYSERR, TEXT("Could not open Registry key HKLM\\%ls not found"), reg_path);
    }

    /* The default value of REG_KEY is the install path */
    status = GetRegString(key, NULL, install_path, sizeof(install_path), NULL);
    if (status != ERROR_SUCCESS)
    {
        error = status;
        goto out;
    }

    openvpn_swprintf(default_value, _countof(default_value), TEXT("%ls\\bin\\openvpn.exe"),
                      install_path);
    error = GetRegString(key, TEXT("exe_path"), s->exe_path, sizeof(s->exe_path), default_value);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    openvpn_swprintf(default_value, _countof(default_value), TEXT("%ls\\config"), install_path);
    error = GetRegString(key, TEXT("config_dir"), s->config_dir, sizeof(s->config_dir),
                         default_value);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("config_ext"), s->ext_string, sizeof(s->ext_string),
                         TEXT(".ovpn"));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    openvpn_swprintf(default_value, _countof(default_value), TEXT("%ls\\log"), install_path);
    error = GetRegString(key, TEXT("log_dir"), s->log_dir, sizeof(s->log_dir), default_value);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("priority"), priority, sizeof(priority),
                         TEXT("NORMAL_PRIORITY_CLASS"));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, TEXT("log_append"), append, sizeof(append), TEXT("0"));
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    /* read if present, else use default */
    error = GetRegString(key, TEXT("ovpn_admin_group"), s->ovpn_admin_group,
                         sizeof(s->ovpn_admin_group), OVPN_ADMIN_GROUP);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }
    /* set process priority */
    if (!_wcsicmp(priority, TEXT("IDLE_PRIORITY_CLASS")))
    {
        s->priority = IDLE_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, TEXT("BELOW_NORMAL_PRIORITY_CLASS")))
    {
        s->priority = BELOW_NORMAL_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, TEXT("NORMAL_PRIORITY_CLASS")))
    {
        s->priority = NORMAL_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, TEXT("ABOVE_NORMAL_PRIORITY_CLASS")))
    {
        s->priority = ABOVE_NORMAL_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, TEXT("HIGH_PRIORITY_CLASS")))
    {
        s->priority = HIGH_PRIORITY_CLASS;
    }
    else
    {
        SetLastError(ERROR_INVALID_DATA);
        error = MsgToEventLog(M_SYSERR, TEXT("Unknown priority name: %ls"), priority);
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
        error = MsgToEventLog(M_ERR, TEXT("Log file append flag (given as '%ls') must be '0' or '1'"), append);
        goto out;
    }

out:
    RegCloseKey(key);
    return error;
}


LPCTSTR
GetLastErrorText()
{
    DWORD error;
    static TCHAR buf[256];
    DWORD len;
    LPTSTR tmp = NULL;

    error = GetLastError();
    len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                        NULL, error, LANG_NEUTRAL, tmp, 0, NULL);

    if (len == 0 || (long) _countof(buf) < (long) len + 14)
    {
        buf[0] = TEXT('\0');
    }
    else
    {
        tmp[wcslen(tmp) - 2] = TEXT('\0'); /* remove CR/LF characters */
        openvpn_swprintf(buf, _countof(buf), TEXT("%ls (0x%x)"), tmp, error);
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
        openvpn_swprintf(msg[0], _countof(msg[0]),
                          TEXT("%ls%ls%ls: %ls"), APPNAME, service_instance,
                          (flags & MSG_FLAGS_ERROR) ? TEXT(" error") : TEXT(""), err_msg);

        va_start(arglist, format);
        openvpn_vswprintf(msg[1], _countof(msg[1]), format, arglist);
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

const wchar_t *
get_win_sys_path(void)
{
    const wchar_t *default_sys_path = L"C:\\Windows\\system32";

    if (!GetSystemDirectoryW(win_sys_path, _countof(win_sys_path)))
    {
        wcscpy_s(win_sys_path, _countof(win_sys_path), default_sys_path);
        win_sys_path[_countof(win_sys_path) - 1] = L'\0';
    }

    return win_sys_path;
}
