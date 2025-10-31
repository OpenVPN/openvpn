/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2011-2025 Heiko Hund <heiko.hund@sophos.com>
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

#include "service.h"
#include "validate.h"
#include "eventmsg.h"

LPCWSTR service_instance = L"";
static wchar_t win_sys_path[MAX_PATH];

static DWORD
GetRegString(HKEY key, LPCWSTR value, LPWSTR data, DWORD size, LPCWSTR default_value)
{
    LONG status = RegGetValue(key, NULL, value, RRF_RT_REG_SZ, NULL, (LPBYTE)data, &size);

    if (status == ERROR_FILE_NOT_FOUND && default_value)
    {
        size_t len = size / sizeof(data[0]);
        if (swprintf(data, len, default_value))
        {
            status = ERROR_SUCCESS;
        }
    }

    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return MsgToEventLog(
            M_SYSERR,
            L"Error querying registry value: HKLM\\SOFTWARE\\" _L(PACKAGE_NAME) L"%ls\\%ls",
            service_instance, value);
    }

    return ERROR_SUCCESS;
}


/**
 * Make sure that a dir path ends with a backslash.
 * If it doesn't, a \ is added to the end of the path, if there's room in the buffer.
 *
 * @param dir       pointer to the wide dir path string buffer
 * @param size      maximum number of wide chars the dir path buffer
 * @return BOOL to indicate success or failure
 */
static BOOL
ensure_trailing_backslash(PWSTR dir, size_t size)
{
    size_t len = wcslen(dir);

    if (dir[len - 1] != '\\')
    {
        if (len + 1 > size)
        {
            return FALSE;
        }
        dir[len] = '\\';
        dir[len + 1] = '\0';
    }

    return TRUE;
}


DWORD
GetOpenvpnSettings(settings_t *s)
{
    WCHAR reg_path[256];
    WCHAR priority[64];
    WCHAR append[2];
    DWORD error;
    HKEY key;
    WCHAR install_path[MAX_PATH];
    WCHAR default_value[MAX_PATH];

    swprintf(reg_path, _countof(reg_path), L"SOFTWARE\\" _L(PACKAGE_NAME) L"%ls", service_instance);

    LONG status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS)
    {
        SetLastError(status);
        return MsgToEventLog(M_SYSERR, L"Could not open Registry key HKLM\\%ls not found",
                             reg_path);
    }

    /* The default value of REG_KEY is the install path */
    status = GetRegString(key, NULL, install_path, sizeof(install_path), NULL);
    if (status != ERROR_SUCCESS)
    {
        error = status;
        goto out;
    }

    swprintf(default_value, _countof(default_value), L"%ls\\bin\\openvpn.exe", install_path);
    error = GetRegString(key, L"exe_path", s->exe_path, sizeof(s->exe_path), default_value);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    swprintf(default_value, _countof(default_value), L"%ls\\config\\", install_path);
    error = GetRegString(key, L"config_dir", s->config_dir, sizeof(s->config_dir), default_value);
    if (error != ERROR_SUCCESS || !ensure_trailing_backslash(s->config_dir, _countof(s->config_dir)))
    {
        goto out;
    }

    swprintf(default_value, _countof(default_value), L"%ls\\bin\\", install_path);
    error = GetRegString(key, L"bin_dir", s->bin_dir, sizeof(s->bin_dir), default_value);
    if (error != ERROR_SUCCESS || !ensure_trailing_backslash(s->bin_dir, _countof(s->bin_dir)))
    {
        goto out;
    }

    error = GetRegString(key, L"config_ext", s->ext_string, sizeof(s->ext_string), L".ovpn");
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    swprintf(default_value, _countof(default_value), L"%ls\\log\\", install_path);
    error = GetRegString(key, L"log_dir", s->log_dir, sizeof(s->log_dir), default_value);
    if (error != ERROR_SUCCESS || !ensure_trailing_backslash(s->log_dir, _countof(s->log_dir)))
    {
        goto out;
    }

    error = GetRegString(key, L"priority", priority, sizeof(priority), L"NORMAL_PRIORITY_CLASS");
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, L"log_append", append, sizeof(append), L"0");
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    /* read if present, else use default */
    error = GetRegString(key, L"ovpn_admin_group", s->ovpn_admin_group, sizeof(s->ovpn_admin_group),
                         OVPN_ADMIN_GROUP);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    error = GetRegString(key, L"ovpn_service_user", s->ovpn_service_user,
                         sizeof(s->ovpn_service_user), OVPN_SERVICE_USER);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    /* set process priority */
    if (!_wcsicmp(priority, L"IDLE_PRIORITY_CLASS"))
    {
        s->priority = IDLE_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, L"BELOW_NORMAL_PRIORITY_CLASS"))
    {
        s->priority = BELOW_NORMAL_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, L"NORMAL_PRIORITY_CLASS"))
    {
        s->priority = NORMAL_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, L"ABOVE_NORMAL_PRIORITY_CLASS"))
    {
        s->priority = ABOVE_NORMAL_PRIORITY_CLASS;
    }
    else if (!_wcsicmp(priority, L"HIGH_PRIORITY_CLASS"))
    {
        s->priority = HIGH_PRIORITY_CLASS;
    }
    else
    {
        SetLastError(ERROR_INVALID_DATA);
        error = MsgToEventLog(M_SYSERR, L"Unknown priority name: %ls", priority);
        goto out;
    }

    /* set log file append/truncate flag */
    if (append[0] == L'0')
    {
        s->append = FALSE;
    }
    else if (append[0] == L'1')
    {
        s->append = TRUE;
    }
    else
    {
        SetLastError(ERROR_INVALID_DATA);
        error = MsgToEventLog(M_ERR, L"Log file append flag (given as '%ls') must be '0' or '1'",
                              append);
        goto out;
    }

out:
    RegCloseKey(key);
    return error;
}


LPCWSTR
GetLastErrorText(void)
{
    DWORD error;
    static WCHAR buf[256];
    DWORD len;
    LPWSTR tmp = NULL;

    error = GetLastError();
    len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                             | FORMAT_MESSAGE_IGNORE_INSERTS,
                         NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&tmp, 0, NULL);

    if (!len || !tmp)
    {
        swprintf(buf, _countof(buf), L"Unknown error (0x%lx)", error);
        if (tmp)
        {
            LocalFree(tmp);
        }
        return buf;
    }

    /* trim trailing CR / LF / spaces safely */
    while (len && (tmp[len - 1] == L'\r' || tmp[len - 1] == L'\n' || tmp[len - 1] == L' '))
    {
        tmp[--len] = L'\0';
    }

    swprintf(buf, _countof(buf), L"%ls (0x%lx)", tmp, error);

    LocalFree(tmp);
    return buf;
}


DWORD
MsgToEventLog(DWORD flags, LPCWSTR format, ...)
{
    HANDLE hEventSource;
    WCHAR msg[2][256];
    DWORD error = 0;
    LPCWSTR err_msg = L"";
    va_list arglist;

    if (flags & MSG_FLAGS_SYS_CODE)
    {
        error = GetLastError();
        err_msg = GetLastErrorText();
    }

    hEventSource = RegisterEventSource(NULL, APPNAME);
    if (hEventSource != NULL)
    {
        swprintf(msg[0], _countof(msg[0]), L"%ls%ls%ls: %ls", APPNAME, service_instance,
                 (flags & MSG_FLAGS_ERROR) ? L" error" : L"", err_msg);

        va_start(arglist, format);
        vswprintf(msg[1], _countof(msg[1]), format, arglist);
        va_end(arglist);

        const WCHAR *mesg[] = { msg[0], msg[1] };
        ReportEvent(hEventSource,
                    flags & MSG_FLAGS_ERROR ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE,
                    0,
                    EVT_TEXT_2,
                    NULL,
                    2,
                    0,
                    mesg,
                    NULL);
        DeregisterEventSource(hEventSource);
    }

    return error;
}

wchar_t *
utf8to16_size(const char *utf8, int size)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, size, NULL, 0);
    if (n == 0)
    {
        return NULL;
    }
    wchar_t *utf16 = malloc(n * sizeof(wchar_t));
    if (!utf16)
    {
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8, 0, utf8, size, utf16, n);
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
