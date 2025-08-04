/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2013-2025 Heiko Hund <heiko.hund@sophos.com>
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

#ifndef _SERVICE_H
#define _SERVICE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>
#include "../tapctl/basic.h"

#define APPNAME  _L(PACKAGE) L"serv"
#define SERVICE_DEPENDENCIES  _L(TAP_WIN_COMPONENT_ID) L"\0Dhcp\0\0"

/*
 * Message handling
 */
#define MSG_FLAGS_ERROR     (1<<0)
#define MSG_FLAGS_SYS_CODE  (1<<1)
#define M_INFO    (0)                                  /* informational */
#define M_SYSERR  (MSG_FLAGS_ERROR|MSG_FLAGS_SYS_CODE) /* error + system code */
#define M_ERR     (MSG_FLAGS_ERROR)                    /* error */

typedef enum {
    interactive,
    _service_max
} openvpn_service_type;

typedef struct {
    openvpn_service_type type;
    WCHAR *name;
    WCHAR *display_name;
    WCHAR *dependencies;
    DWORD start_type;
} openvpn_service_t;

#define MAX_NAME 256
typedef struct {
    WCHAR exe_path[MAX_PATH];
    WCHAR config_dir[MAX_PATH];
    WCHAR bin_dir[MAX_PATH];
    WCHAR ext_string[16];
    WCHAR log_dir[MAX_PATH];
    WCHAR ovpn_admin_group[MAX_NAME];
    WCHAR ovpn_service_user[MAX_NAME];
    DWORD priority;
    BOOL append;
} settings_t;

extern openvpn_service_t interactive_service;
extern LPCWSTR service_instance;

VOID WINAPI ServiceStartInteractiveOwn(DWORD argc, LPWSTR *argv);

VOID WINAPI ServiceStartInteractive(DWORD argc, LPWSTR *argv);

DWORD GetOpenvpnSettings(settings_t *s);

BOOL ReportStatusToSCMgr(SERVICE_STATUS_HANDLE service, SERVICE_STATUS *status);

LPCWSTR GetLastErrorText(void);

DWORD MsgToEventLog(DWORD flags, LPCWSTR lpszMsg, ...);

/**
 * Convert a UTF-8 string to UTF-16
 *
 * The size parameter can be used to convert strings which contain inline NUL
 * characters, like MULTI_SZ strings used as values in the registry do,
 * or (sub)strings that are not zero terminated. If size is -1 the length
 * of the string is determined automatically by the WIN32 API. Make sure
 * you pass a terminated string or else bad things will happen. Note that
 * the size you pass should always include the terminating zero as well.
 *
 * If the returned string is not NULL it must be freed by the caller.
 *
 * @param utf8  const string to be converted
 * @param size  the size of the string
 *
 * @return wchar_t* heap allocated result string
 */
wchar_t *utf8to16_size(const char *utf8, int size);

/**
 * Convert a zero terminated UTF-8 string to UTF-16
 *
 * This is just a wrapper function that always passes -1 as string size
 * to \ref utf8to16_size.
 *
 * @param utf8  const string to be converted
 *
 * @return wchar_t* heap allocated result string
 */
static inline wchar_t *
utf8to16(const char *utf8)
{
    return utf8to16_size(utf8, -1);
}

/* return windows system directory as a pointer to a static string */
const wchar_t *get_win_sys_path(void);

#endif /* ifndef _SERVICE_H */
