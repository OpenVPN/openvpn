/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2013-2023 Heiko Hund <heiko.hund@sophos.com>
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

#ifndef _SERVICE_H
#define _SERVICE_H

/* We do not support non-unicode builds */
#ifndef UNICODE
#define UNICODE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <tchar.h>

#define APPNAME  TEXT(PACKAGE "serv")
#define SERVICE_DEPENDENCIES  TAP_WIN_COMPONENT_ID "\0Dhcp\0\0"

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
    TCHAR *name;
    TCHAR *display_name;
    TCHAR *dependencies;
    DWORD start_type;
} openvpn_service_t;

#define MAX_NAME 256
typedef struct {
    TCHAR exe_path[MAX_PATH];
    TCHAR config_dir[MAX_PATH];
    TCHAR ext_string[16];
    TCHAR log_dir[MAX_PATH];
    TCHAR ovpn_admin_group[MAX_NAME];
    DWORD priority;
    BOOL append;
} settings_t;

extern openvpn_service_t interactive_service;
extern LPCTSTR service_instance;

VOID WINAPI ServiceStartInteractiveOwn(DWORD argc, LPTSTR *argv);

VOID WINAPI ServiceStartInteractive(DWORD argc, LPTSTR *argv);

BOOL openvpn_vsntprintf(LPTSTR str, size_t size, LPCTSTR format, va_list arglist);

BOOL openvpn_sntprintf(LPTSTR str, size_t size, LPCTSTR format, ...);

BOOL openvpn_swprintf(wchar_t *const str, const size_t size, const wchar_t *const format, ...);

DWORD GetOpenvpnSettings(settings_t *s);

BOOL ReportStatusToSCMgr(SERVICE_STATUS_HANDLE service, SERVICE_STATUS *status);

LPCTSTR GetLastErrorText();

DWORD MsgToEventLog(DWORD flags, LPCTSTR lpszMsg, ...);

/* Convert a utf8 string to utf16. Caller should free the result */
wchar_t *utf8to16(const char *utf8);

/* return windows system directory as a pointer to a static string */
const wchar_t *get_win_sys_path(void);

#endif /* ifndef _SERVICE_H */
