/*
 *  openvpnmsica -- Custom Action DLL to provide OpenVPN-specific support to MSI packages
 *                  https://community.openvpn.net/openvpn/wiki/OpenVPNMSICA
 *
 *  Copyright (C) 2018-2023 Simon Rozman <simon@rozman.si>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openvpnmsica.h"
#include "../tapctl/error.h"

#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#ifdef _MSC_VER
#pragma comment(lib, "msi.lib")
#endif
#include <stdio.h>
#include <tchar.h>


DWORD openvpnmsica_thread_data_idx = TLS_OUT_OF_INDEXES;


/**
 * DLL entry point
 */
BOOL WINAPI
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD dwReason,
    _In_ LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            /* Allocate thread local storage index. */
            openvpnmsica_thread_data_idx = TlsAlloc();
            if (openvpnmsica_thread_data_idx == TLS_OUT_OF_INDEXES)
            {
                return FALSE;
            }
        /* Fall through. */

        case DLL_THREAD_ATTACH:
        {
            /* Create thread local storage data. */
            struct openvpnmsica_thread_data *s = (struct openvpnmsica_thread_data *)calloc(1, sizeof(struct openvpnmsica_thread_data));
            if (s == NULL)
            {
                return FALSE;
            }

            TlsSetValue(openvpnmsica_thread_data_idx, s);
            break;
        }

        case DLL_PROCESS_DETACH:
            if (openvpnmsica_thread_data_idx != TLS_OUT_OF_INDEXES)
            {
                /* Free thread local storage data and index. */
                free(TlsGetValue(openvpnmsica_thread_data_idx));
                TlsFree(openvpnmsica_thread_data_idx);
            }
            break;

        case DLL_THREAD_DETACH:
            /* Free thread local storage data. */
            free(TlsGetValue(openvpnmsica_thread_data_idx));
            break;
    }

    return TRUE;
}


bool
dont_mute(unsigned int flags)
{
    UNREFERENCED_PARAMETER(flags);

    return true;
}


void
x_msg_va(const unsigned int flags, const char *format, va_list arglist)
{
    /* Secure last error before it is overridden. */
    DWORD dwResult = (flags & M_ERRNO) != 0 ? GetLastError() : ERROR_SUCCESS;

    struct openvpnmsica_thread_data *s = (struct openvpnmsica_thread_data *)TlsGetValue(openvpnmsica_thread_data_idx);
    if (s->hInstall == 0)
    {
        /* No MSI session, no fun. */
        return;
    }

    /* Prepare the message record. The record will contain up to four fields. */
    MSIHANDLE hRecordProg = MsiCreateRecord(4);

    {
        /* Field 2: The message string. */
        char szBufStack[128];
        int iResultLen = vsnprintf(szBufStack, _countof(szBufStack), format, arglist);
        if (iResultLen < _countof(szBufStack))
        {
            /* Use from stack. */
            MsiRecordSetStringA(hRecordProg, 2, szBufStack);
        }
        else
        {
            /* Allocate on heap and retry. */
            char *szMessage = (char *)malloc(++iResultLen * sizeof(char));
            if (szMessage != NULL)
            {
                vsnprintf(szMessage, iResultLen, format, arglist);
                MsiRecordSetStringA(hRecordProg, 2, szMessage);
                free(szMessage);
            }
            else
            {
                /* Use stack variant anyway, but make sure it's zero-terminated. */
                szBufStack[_countof(szBufStack) - 1] = 0;
                MsiRecordSetStringA(hRecordProg, 2, szBufStack);
            }
        }
    }

    if ((flags & M_ERRNO) == 0)
    {
        /* Field 1: MSI Error Code */
        MsiRecordSetInteger(hRecordProg, 1, ERROR_MSICA);
    }
    else
    {
        /* Field 1: MSI Error Code */
        MsiRecordSetInteger(hRecordProg, 1, ERROR_MSICA_ERRNO);

        /* Field 3: The Windows error number. */
        MsiRecordSetInteger(hRecordProg, 3, dwResult);

        /* Field 4: The Windows error description. */
        LPTSTR szErrMessage = NULL;
        if (FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                0,
                dwResult,
                0,
                (LPTSTR)&szErrMessage,
                0,
                NULL) && szErrMessage)
        {
            /* Trim trailing whitespace. Set terminator after the last non-whitespace character. This prevents excessive trailing line breaks. */
            for (size_t i = 0, i_last = 0;; i++)
            {
                if (szErrMessage[i])
                {
                    if (!_istspace(szErrMessage[i]))
                    {
                        i_last = i + 1;
                    }
                }
                else
                {
                    szErrMessage[i_last] = 0;
                    break;
                }
            }
            MsiRecordSetString(hRecordProg, 4, szErrMessage);
            LocalFree(szErrMessage);
        }
    }

    MsiProcessMessage(s->hInstall, (flags & M_WARN) ? INSTALLMESSAGE_INFO : INSTALLMESSAGE_ERROR, hRecordProg);
    MsiCloseHandle(hRecordProg);
}
