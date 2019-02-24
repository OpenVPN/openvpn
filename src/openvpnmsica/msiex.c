/*
 *  openvpnmsica -- Custom Action DLL to provide OpenVPN-specific support to MSI packages
 *                  https://community.openvpn.net/openvpn/wiki/OpenVPNMSICA
 *
 *  Copyright (C) 2018 Simon Rozman <simon@rozman.si>
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
#elif defined(_MSC_VER)
#include <config-msvc.h>
#endif

#include "msiex.h"
#include "../tapctl/error.h"

#include <windows.h>
#include <malloc.h>
#include <memory.h>
#include <msiquery.h>
#ifdef _MSC_VER
#pragma comment(lib, "msi.lib")
#endif


UINT
msi_get_string(
    _In_ MSIHANDLE hInstall,
    _In_z_ LPCTSTR szName,
    _Out_ LPTSTR *pszValue)
{
    if (pszValue == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Try with stack buffer first. */
    TCHAR szBufStack[128];
    DWORD dwLength = _countof(szBufStack);
    UINT uiResult = MsiGetProperty(hInstall, szName, szBufStack, &dwLength);
    if (uiResult == ERROR_SUCCESS)
    {
        /* Copy from stack. */
        *pszValue = (LPTSTR)malloc(++dwLength * sizeof(TCHAR));
        if (*pszValue == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", dwLength * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        memcpy(*pszValue, szBufStack, dwLength * sizeof(TCHAR));
        return ERROR_SUCCESS;
    }
    else if (uiResult == ERROR_MORE_DATA)
    {
        /* Allocate on heap and retry. */
        LPTSTR szBufHeap = (LPTSTR)malloc(++dwLength * sizeof(TCHAR));
        if (szBufHeap == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwLength * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        uiResult = MsiGetProperty(hInstall, szName, szBufHeap, &dwLength);
        if (uiResult == ERROR_SUCCESS)
        {
            *pszValue = szBufHeap;
        }
        else
        {
            free(szBufHeap);
        }
        return uiResult;
    }
    else
    {
        SetLastError(uiResult); /* MSDN does not mention MsiGetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiGetProperty failed", __FUNCTION__);
        return uiResult;
    }
}


UINT
msi_get_record_string(
    _In_ MSIHANDLE hRecord,
    _In_ unsigned int iField,
    _Out_ LPTSTR *pszValue)
{
    if (pszValue == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Try with stack buffer first. */
    TCHAR szBufStack[128];
    DWORD dwLength = _countof(szBufStack);
    UINT uiResult = MsiRecordGetString(hRecord, iField, szBufStack, &dwLength);
    if (uiResult == ERROR_SUCCESS)
    {
        /* Copy from stack. */
        *pszValue = (LPTSTR)malloc(++dwLength * sizeof(TCHAR));
        if (*pszValue == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwLength * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        memcpy(*pszValue, szBufStack, dwLength * sizeof(TCHAR));
        return ERROR_SUCCESS;
    }
    else if (uiResult == ERROR_MORE_DATA)
    {
        /* Allocate on heap and retry. */
        LPTSTR szBufHeap = (LPTSTR)malloc(++dwLength * sizeof(TCHAR));
        if (szBufHeap == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwLength * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        uiResult = MsiRecordGetString(hRecord, iField, szBufHeap, &dwLength);
        if (uiResult == ERROR_SUCCESS)
        {
            *pszValue = szBufHeap;
        }
        else
        {
            free(szBufHeap);
        }
        return uiResult;
    }
    else
    {
        SetLastError(uiResult); /* MSDN does not mention MsiRecordGetString() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiRecordGetString failed", __FUNCTION__);
        return uiResult;
    }
}


UINT
msi_format_record(
    _In_ MSIHANDLE hInstall,
    _In_ MSIHANDLE hRecord,
    _Out_ LPTSTR *pszValue)
{
    if (pszValue == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Try with stack buffer first. */
    TCHAR szBufStack[128];
    DWORD dwLength = _countof(szBufStack);
    UINT uiResult = MsiFormatRecord(hInstall, hRecord, szBufStack, &dwLength);
    if (uiResult == ERROR_SUCCESS)
    {
        /* Copy from stack. */
        *pszValue = (LPTSTR)malloc(++dwLength * sizeof(TCHAR));
        if (*pszValue == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwLength * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        memcpy(*pszValue, szBufStack, dwLength * sizeof(TCHAR));
        return ERROR_SUCCESS;
    }
    else if (uiResult == ERROR_MORE_DATA)
    {
        /* Allocate on heap and retry. */
        LPTSTR szBufHeap = (LPTSTR)malloc(++dwLength * sizeof(TCHAR));
        if (szBufHeap == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwLength * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        uiResult = MsiFormatRecord(hInstall, hRecord, szBufHeap, &dwLength);
        if (uiResult == ERROR_SUCCESS)
        {
            *pszValue = szBufHeap;
        }
        else
        {
            free(szBufHeap);
        }
        return uiResult;
    }
    else
    {
        SetLastError(uiResult); /* MSDN does not mention MsiFormatRecord() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiFormatRecord failed", __FUNCTION__);
        return uiResult;
    }
}


UINT
msi_format_field(
    _In_ MSIHANDLE hInstall,
    _In_ MSIHANDLE hRecord,
    _In_ unsigned int iField,
    _Out_ LPTSTR *pszValue)
{
    if (pszValue == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Read string to format. */
    LPTSTR szValue = NULL;
    UINT uiResult = msi_get_record_string(hRecord, iField, &szValue);
    if (uiResult != ERROR_SUCCESS)
    {
        return uiResult;
    }
    if (szValue[0] == 0)
    {
        /* The string is empty. There's nothing left to do. */
        *pszValue = szValue;
        return ERROR_SUCCESS;
    }

    /* Create a temporary record. */
    MSIHANDLE hRecordEx = MsiCreateRecord(1);
    if (!hRecordEx)
    {
        uiResult = ERROR_INVALID_HANDLE;
        msg(M_NONFATAL, "%s: MsiCreateRecord failed", __FUNCTION__);
        goto cleanup_szValue;
    }

    /* Populate the record with data. */
    uiResult = MsiRecordSetString(hRecordEx, 0, szValue);
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiRecordSetString() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiRecordSetString failed", __FUNCTION__);
        goto cleanup_hRecordEx;
    }

    /* Do the formatting. */
    uiResult = msi_format_record(hInstall, hRecordEx, pszValue);

cleanup_hRecordEx:
    MsiCloseHandle(hRecordEx);
cleanup_szValue:
    free(szValue);
    return uiResult;
}
