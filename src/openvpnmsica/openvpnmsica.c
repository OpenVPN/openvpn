/*
 *  openvpnmsica -- Custom Action DLL to provide OpenVPN-specific support to MSI packages
 *                  https://community.openvpn.net/openvpn/wiki/OpenVPNMSICA
 *
 *  Copyright (C) 2018-2020 Simon Rozman <simon@rozman.si>
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
#include <winsock2.h> /* Must be included _before_ <windows.h> */

#include "openvpnmsica.h"
#include "msica_arg.h"
#include "msiex.h"

#include "../tapctl/basic.h"
#include "../tapctl/error.h"
#include "../tapctl/tap.h"

#include <windows.h>
#include <iphlpapi.h>
#include <malloc.h>
#include <memory.h>
#include <msiquery.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <stdlib.h>
#include <tchar.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")
#endif


/**
 * Local constants
 */

#define MSICA_INTERFACE_TICK_SIZE (16*1024) /** Amount of tick space to reserve for one TAP/TUN interface creation/deletition. */


/**
 * Joins an argument sequence and sets it to the MSI property.
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @param szProperty    MSI property name to set to the joined argument sequence.
 *
 * @param seq           The argument sequence.
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
static UINT
openvpnmsica_setup_sequence(
    _In_ MSIHANDLE hInstall,
    _In_z_ LPCTSTR szProperty,
    _In_ struct msica_arg_seq *seq)
{
    UINT uiResult;
    LPTSTR szSequence = msica_arg_seq_join(seq);
    uiResult = MsiSetProperty(hInstall, szProperty, szSequence);
    free(szSequence);
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szProperty);
        return uiResult;
    }
    return ERROR_SUCCESS;
}


#ifdef _DEBUG

/**
 * Pops up a message box creating a time window to attach a debugger to the installer process in
 * order to debug custom actions.
 *
 * @param szFunctionName  Function name that triggered the pop-up. Displayed in message box's
 *                        title.
 */
static void
_openvpnmsica_debug_popup(_In_z_ LPCTSTR szFunctionName)
{
    TCHAR szTitle[0x100], szMessage[0x100+MAX_PATH], szProcessPath[MAX_PATH];

    /* Compose pop-up title. The dialog title will contain function name to ease the process
     * locating. Mind that Visual Studio displays window titles on the process list. */
    _stprintf_s(szTitle, _countof(szTitle), TEXT("%s v%s"), szFunctionName, TEXT(PACKAGE_VERSION));

    /* Get process name. */
    GetModuleFileName(NULL, szProcessPath, _countof(szProcessPath));
    LPCTSTR szProcessName = _tcsrchr(szProcessPath, TEXT('\\'));
    szProcessName = szProcessName ? szProcessName + 1 : szProcessPath;

    /* Compose the pop-up message. */
    _stprintf_s(
        szMessage, _countof(szMessage),
        TEXT("The %s process (PID: %u) has started to execute the %s custom action.\r\n")
        TEXT("\r\n")
        TEXT("If you would like to debug the custom action, attach a debugger to this process and set breakpoints before dismissing this dialog.\r\n")
        TEXT("\r\n")
        TEXT("If you are not debugging this custom action, you can safely ignore this message."),
        szProcessName,
        GetCurrentProcessId(),
        szFunctionName);

    MessageBox(NULL, szMessage, szTitle, MB_OK);
}

#define openvpnmsica_debug_popup(f) _openvpnmsica_debug_popup(f)
#else  /* ifdef _DEBUG */
#define openvpnmsica_debug_popup(f)
#endif /* ifdef _DEBUG */


/**
 * Detects if the OpenVPNService service is in use (running or paused) and sets
 * OPENVPNSERVICE to the service process PID, or its path if it is set to
 * auto-start, but not running.
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 *         See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072.aspx
 */
static UINT
openvpnmsica_set_openvpnserv_state(_In_ MSIHANDLE hInstall)
{
    UINT uiResult;

    /* Get Service Control Manager handle. */
    SC_HANDLE hSCManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (hSCManager == NULL)
    {
        uiResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: OpenSCManager() failed", __FUNCTION__);
        return uiResult;
    }

    /* Get OpenVPNService service handle. */
    SC_HANDLE hService = OpenService(hSCManager, TEXT("OpenVPNService"), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (hService == NULL)
    {
        uiResult = GetLastError();
        if (uiResult == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            /* This is not actually an error. */
            goto cleanup_OpenSCManager;
        }
        msg(M_NONFATAL | M_ERRNO, "%s: OpenService(\"OpenVPNService\") failed", __FUNCTION__);
        goto cleanup_OpenSCManager;
    }

    /* Query service status. */
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBufSize;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBufSize))
    {
        switch (ssp.dwCurrentState)
        {
            case SERVICE_START_PENDING:
            case SERVICE_RUNNING:
            case SERVICE_STOP_PENDING:
            case SERVICE_PAUSE_PENDING:
            case SERVICE_PAUSED:
            case SERVICE_CONTINUE_PENDING:
            {
                /* Service is started (kind of). Set OPENVPNSERVICE property to service PID. */
                TCHAR szPID[10 /*MAXDWORD in decimal*/ + 1 /*terminator*/];
                _stprintf_s(
                    szPID, _countof(szPID),
                    TEXT("%u"),
                    ssp.dwProcessId);

                uiResult = MsiSetProperty(hInstall, TEXT("OPENVPNSERVICE"), szPID);
                if (uiResult != ERROR_SUCCESS)
                {
                    SetLastError(uiResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
                    msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"OPENVPNSERVICE\") failed", __FUNCTION__);
                }

                /* We know user is using the service. Skip auto-start setting check. */
                goto cleanup_OpenService;
            }
            break;
        }
    }
    else
    {
        uiResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: QueryServiceStatusEx(\"OpenVPNService\") failed", __FUNCTION__);
    }

    /* Service is not started. Is it set to auto-start? */
    /* MSDN describes the maximum buffer size for QueryServiceConfig() to be 8kB. */
    /* This is small enough to fit on stack. */
    BYTE _buffer_8k[8192];
    LPQUERY_SERVICE_CONFIG pQsc = (LPQUERY_SERVICE_CONFIG)_buffer_8k;
    dwBufSize = sizeof(_buffer_8k);
    if (!QueryServiceConfig(hService, pQsc, dwBufSize, &dwBufSize))
    {
        uiResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: QueryServiceStatusEx(\"QueryServiceConfig\") failed", __FUNCTION__);
        goto cleanup_OpenService;
    }

    if (pQsc->dwStartType <= SERVICE_AUTO_START)
    {
        /* Service is set to auto-start. Set OPENVPNSERVICE property to its path. */
        uiResult = MsiSetProperty(hInstall, TEXT("OPENVPNSERVICE"), pQsc->lpBinaryPathName);
        if (uiResult != ERROR_SUCCESS)
        {
            SetLastError(uiResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"OPENVPNSERVICE\") failed", __FUNCTION__);
            goto cleanup_OpenService;
        }
    }

    uiResult = ERROR_SUCCESS;

cleanup_OpenService:
    CloseServiceHandle(hService);
cleanup_OpenSCManager:
    CloseServiceHandle(hSCManager);
    return uiResult;
}


UINT __stdcall
FindSystemInfo(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    openvpnmsica_debug_popup(TEXT(__FUNCTION__));

    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    openvpnmsica_set_openvpnserv_state(hInstall);

    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return ERROR_SUCCESS;
}


UINT __stdcall
FindTAPInterfaces(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    openvpnmsica_debug_popup(TEXT(__FUNCTION__));

    UINT uiResult;
    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    /* Get all TUN/TAP network interfaces. */
    struct tap_interface_node *pInterfaceList = NULL;
    uiResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, FALSE);
    if (uiResult != ERROR_SUCCESS)
    {
        goto cleanup_CoInitialize;
    }

    /* Get IPv4/v6 info for all network interfaces. Actually, we're interested in link status only: up/down? */
    PIP_ADAPTER_ADDRESSES pAdapterAdresses = NULL;
    ULONG ulAdapterAdressesSize = 16*1024;
    for (size_t iteration = 0; iteration < 2; iteration++)
    {
        pAdapterAdresses = (PIP_ADAPTER_ADDRESSES)malloc(ulAdapterAdressesSize);
        if (pAdapterAdresses == NULL)
        {
            msg(M_NONFATAL, "%s: malloc(%u) failed", __FUNCTION__, ulAdapterAdressesSize);
            uiResult = ERROR_OUTOFMEMORY; goto cleanup_tap_list_interfaces;
        }

        ULONG ulResult = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_INCLUDE_ALL_INTERFACES,
            NULL,
            pAdapterAdresses,
            &ulAdapterAdressesSize);

        if (ulResult == ERROR_SUCCESS)
        {
            break;
        }

        free(pAdapterAdresses);
        if (ulResult != ERROR_BUFFER_OVERFLOW)
        {
            SetLastError(ulResult); /* MSDN does not mention GetAdaptersAddresses() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_NONFATAL | M_ERRNO, "%s: GetAdaptersAddresses() failed", __FUNCTION__);
            uiResult = ulResult; goto cleanup_tap_list_interfaces;
        }
    }

    if (pInterfaceList != NULL)
    {
        /* Count interfaces. */
        size_t interface_count = 0;
        for (struct tap_interface_node *pInterface = pInterfaceList; pInterface; pInterface = pInterface->pNext)
        {
            interface_count++;
        }

        /* Prepare semicolon delimited list of TAP interface ID(s) and active TAP interface ID(s). */
        LPTSTR
            szTAPInterfaces     = (LPTSTR)malloc(interface_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR)),
            szTAPInterfacesTail = szTAPInterfaces;
        if (szTAPInterfaces == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, interface_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR));
            uiResult = ERROR_OUTOFMEMORY; goto cleanup_pAdapterAdresses;
        }

        LPTSTR
            szTAPInterfacesActive     = (LPTSTR)malloc(interface_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR)),
            szTAPInterfacesActiveTail = szTAPInterfacesActive;
        if (szTAPInterfacesActive == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, interface_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR));
            uiResult = ERROR_OUTOFMEMORY; goto cleanup_szTAPInterfaces;
        }

        for (struct tap_interface_node *pInterface = pInterfaceList; pInterface; pInterface = pInterface->pNext)
        {
            /* Convert interface GUID to UTF-16 string. (LPOLESTR defaults to LPWSTR) */
            LPOLESTR szInterfaceId = NULL;
            StringFromIID((REFIID)&pInterface->guid, &szInterfaceId);

            /* Append to the list of TAP interface ID(s). */
            if (szTAPInterfaces < szTAPInterfacesTail)
            {
                *(szTAPInterfacesTail++) = TEXT(';');
            }
            memcpy(szTAPInterfacesTail, szInterfaceId, 38 * sizeof(TCHAR));
            szTAPInterfacesTail += 38;

            /* If this interface is active (connected), add it to the list of active TAP interface ID(s). */
            for (PIP_ADAPTER_ADDRESSES p = pAdapterAdresses; p; p = p->Next)
            {
                OLECHAR szId[38 /*GUID*/ + 1 /*terminator*/];
                GUID guid;
                if (MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, p->AdapterName, -1, szId, _countof(szId)) > 0
                    && SUCCEEDED(IIDFromString(szId, &guid))
                    && memcmp(&guid, &pInterface->guid, sizeof(GUID)) == 0)
                {
                    if (p->OperStatus == IfOperStatusUp)
                    {
                        /* This TAP interface is active (connected). */
                        if (szTAPInterfacesActive < szTAPInterfacesActiveTail)
                        {
                            *(szTAPInterfacesActiveTail++) = TEXT(';');
                        }
                        memcpy(szTAPInterfacesActiveTail, szInterfaceId, 38 * sizeof(TCHAR));
                        szTAPInterfacesActiveTail += 38;
                    }
                    break;
                }
            }
            CoTaskMemFree(szInterfaceId);
        }
        szTAPInterfacesTail      [0] = 0;
        szTAPInterfacesActiveTail[0] = 0;

        /* Set Installer TAPINTERFACES property. */
        uiResult = MsiSetProperty(hInstall, TEXT("TAPINTERFACES"), szTAPInterfaces);
        if (uiResult != ERROR_SUCCESS)
        {
            SetLastError(uiResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"TAPINTERFACES\") failed", __FUNCTION__);
            goto cleanup_szTAPInterfacesActive;
        }

        /* Set Installer ACTIVETAPINTERFACES property. */
        uiResult = MsiSetProperty(hInstall, TEXT("ACTIVETAPINTERFACES"), szTAPInterfacesActive);
        if (uiResult != ERROR_SUCCESS)
        {
            SetLastError(uiResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"ACTIVETAPINTERFACES\") failed", __FUNCTION__);
            goto cleanup_szTAPInterfacesActive;
        }

cleanup_szTAPInterfacesActive:
        free(szTAPInterfacesActive);
cleanup_szTAPInterfaces:
        free(szTAPInterfaces);
    }
    else
    {
        uiResult = ERROR_SUCCESS;
    }

cleanup_pAdapterAdresses:
    free(pAdapterAdresses);
cleanup_tap_list_interfaces:
    tap_free_interface_list(pInterfaceList);
cleanup_CoInitialize:
    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return uiResult;
}


UINT __stdcall
CloseOpenVPNGUI(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif
    UNREFERENCED_PARAMETER(hInstall); /* This CA is does not interact with MSI session (report errors, access properties, tables, etc.). */

    openvpnmsica_debug_popup(TEXT(__FUNCTION__));

    /* Find OpenVPN GUI window. */
    HWND hWnd = FindWindow(TEXT("OpenVPN-GUI"), NULL);
    if (hWnd)
    {
        /* Ask it to close and wait for 100ms. Unfortunately, this will succeed only for recent OpenVPN GUI that do not run elevated. */
        SendMessage(hWnd, WM_CLOSE, 0, 0);
        Sleep(100);
    }

    return ERROR_SUCCESS;
}


UINT __stdcall
StartOpenVPNGUI(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    openvpnmsica_debug_popup(TEXT(__FUNCTION__));

    UINT uiResult;
    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    /* Create and populate a MSI record. */
    MSIHANDLE hRecord = MsiCreateRecord(1);
    if (!hRecord)
    {
        uiResult = ERROR_INVALID_HANDLE;
        msg(M_NONFATAL, "%s: MsiCreateRecord failed", __FUNCTION__);
        goto cleanup_CoInitialize;
    }
    uiResult = MsiRecordSetString(hRecord, 0, TEXT("\"[#bin.openvpn_gui.exe]\""));
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiRecordSetString() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiRecordSetString failed", __FUNCTION__);
        goto cleanup_MsiCreateRecord;
    }

    /* Format string. */
    TCHAR szStackBuf[MAX_PATH];
    DWORD dwPathSize = _countof(szStackBuf);
    LPTSTR szPath = szStackBuf;
    uiResult = MsiFormatRecord(hInstall, hRecord, szPath, &dwPathSize);
    if (uiResult == ERROR_MORE_DATA)
    {
        /* Allocate buffer on heap (+1 for terminator), and retry. */
        szPath = (LPTSTR)malloc((++dwPathSize) * sizeof(TCHAR));
        if (szPath == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwPathSize * sizeof(TCHAR));
            uiResult = ERROR_OUTOFMEMORY; goto cleanup_MsiCreateRecord;
        }

        uiResult = MsiFormatRecord(hInstall, hRecord, szPath, &dwPathSize);
    }
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiFormatRecord() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiFormatRecord failed", __FUNCTION__);
        goto cleanup_malloc_szPath;
    }

    /* Launch the OpenVPN GUI. */
    SHELLEXECUTEINFO sei = {
        .cbSize = sizeof(SHELLEXECUTEINFO),
        .fMask  = SEE_MASK_FLAG_NO_UI, /* Don't show error UI, we'll display it. */
        .lpFile = szPath,
        .nShow  = SW_SHOWNORMAL
    };
    if (!ShellExecuteEx(&sei))
    {
        uiResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: ShellExecuteEx(%s) failed", __FUNCTION__, szPath);
        goto cleanup_malloc_szPath;
    }

    uiResult = ERROR_SUCCESS;

cleanup_malloc_szPath:
    if (szPath != szStackBuf)
    {
        free(szPath);
    }
cleanup_MsiCreateRecord:
    MsiCloseHandle(hRecord);
cleanup_CoInitialize:
    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return uiResult;
}


/**
 * Schedules interface creation.
 *
 * When the rollback is enabled, the interface deletition is scheduled on rollback.
 *
 * @param seq           The argument sequence to pass to InstallTAPInterfaces custom action
 *
 * @param seqRollback   The argument sequence to pass to InstallTAPInterfacesRollback custom
 *                      action. NULL when rollback is disabled.
 *
 * @param szDisplayName  Interface display name.
 *
 * @param iTicks        Pointer to an integer that represents amount of work (on progress
 *                      indicator) the InstallTAPInterfaces will take. This function increments it
 *                      by MSICA_INTERFACE_TICK_SIZE for each interface to create.
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
static DWORD
openvpnmsica_schedule_interface_create(_Inout_ struct msica_arg_seq *seq, _Inout_opt_ struct msica_arg_seq *seqRollback, _In_z_ LPCTSTR szDisplayName, _Inout_ int *iTicks)
{
    /* Get all available network interfaces. */
    struct tap_interface_node *pInterfaceList = NULL;
    DWORD dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, TRUE);
    if (dwResult != ERROR_SUCCESS)
    {
        return dwResult;
    }

    /* Does interface exist? */
    for (struct tap_interface_node *pInterfaceOther = pInterfaceList;; pInterfaceOther = pInterfaceOther->pNext)
    {
        if (pInterfaceOther == NULL)
        {
            /* No interface with a same name found. */
            TCHAR szArgument[10 /*create=""|deleteN=""*/ + MAX_PATH /*szDisplayName*/ + 1 /*terminator*/];

            /* InstallTAPInterfaces will create the interface. */
            _stprintf_s(
                szArgument, _countof(szArgument),
                TEXT("create=\"%.*s\""),
                MAX_PATH, szDisplayName);
            msica_arg_seq_add_tail(seq, szArgument);

            if (seqRollback)
            {
                /* InstallTAPInterfacesRollback will delete the interface. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("deleteN=\"%.*s\""),
                    MAX_PATH, szDisplayName);
                msica_arg_seq_add_head(seqRollback, szArgument);
            }

            *iTicks += MSICA_INTERFACE_TICK_SIZE;
            break;
        }
        else if (_tcsicmp(szDisplayName, pInterfaceOther->szName) == 0)
        {
            /* Interface with a same name found. */
            for (LPCTSTR hwid = pInterfaceOther->szzHardwareIDs;; hwid += _tcslen(hwid) + 1)
            {
                if (hwid[0] == 0)
                {
                    /* This is not a TAP interface. */
                    msg(M_NONFATAL, "%s: Interface with name \"%" PRIsLPTSTR "\" already exists", __FUNCTION__, pInterfaceOther->szName);
                    dwResult = ERROR_ALREADY_EXISTS;
                    goto cleanup_pInterfaceList;
                }
                else if (
                    _tcsicmp(hwid, TEXT(TAP_WIN_COMPONENT_ID)) == 0
                    || _tcsicmp(hwid, TEXT("root\\") TEXT(TAP_WIN_COMPONENT_ID)) == 0)
                {
                    /* This is a TAP-Windows6 interface. We already have what we want! */
                    break;
                }
            }
            break; /* Interface names are unique. There should be no other interface with this name. */
        }
    }

cleanup_pInterfaceList:
    tap_free_interface_list(pInterfaceList);
    return dwResult;
}


/**
 * Schedules interface deletion.
 *
 * When the rollback is enabled, the interface deletition is scheduled as: disable in
 * UninstallTAPInterfaces, enable on rollback, delete on commit.
 *
 * When rollback is disabled, the interface deletition is scheduled as delete in
 * UninstallTAPInterfaces.
 *
 * @param seq           The argument sequence to pass to UninstallTAPInterfaces custom action
 *
 * @param seqCommit     The argument sequence to pass to UninstallTAPInterfacesCommit custom
 *                      action. NULL when rollback is disabled.
 *
 * @param seqRollback   The argument sequence to pass to UninstallTAPInterfacesRollback custom
 *                      action. NULL when rollback is disabled.
 *
 * @param szDisplayName  Interface display name.
 *
 * @param iTicks        Pointer to an integer that represents amount of work (on progress
 *                      indicator) the UninstallTAPInterfaces will take. This function increments
 *                      it by MSICA_INTERFACE_TICK_SIZE for each interface to delete.
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
static DWORD
openvpnmsica_schedule_interface_delete(_Inout_ struct msica_arg_seq *seq, _Inout_opt_ struct msica_arg_seq *seqCommit, _Inout_opt_ struct msica_arg_seq *seqRollback, _In_z_ LPCTSTR szDisplayName, _Inout_ int *iTicks)
{
    /* Get available TUN/TAP interfaces. */
    struct tap_interface_node *pInterfaceList = NULL;
    DWORD dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, FALSE);
    if (dwResult != ERROR_SUCCESS)
    {
        return dwResult;
    }

    /* Does interface exist? */
    for (struct tap_interface_node *pInterface = pInterfaceList; pInterface != NULL; pInterface = pInterface->pNext)
    {
        if (_tcsicmp(szDisplayName, pInterface->szName) == 0)
        {
            /* Interface found. */
            TCHAR szArgument[8 /*disable=|enable=|delete=*/ + 38 /*{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}*/ + 1 /*terminator*/];
            if (seqCommit && seqRollback)
            {
                /* UninstallTAPInterfaces will disable the interface. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("disable=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pInterface->guid));
                msica_arg_seq_add_tail(seq, szArgument);

                /* UninstallTAPInterfacesRollback will re-enable the interface. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("enable=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pInterface->guid));
                msica_arg_seq_add_head(seqRollback, szArgument);

                /* UninstallTAPInterfacesCommit will delete the interface. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("delete=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pInterface->guid));
                msica_arg_seq_add_tail(seqCommit, szArgument);
            }
            else
            {
                /* UninstallTAPInterfaces will delete the interface. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("delete=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pInterface->guid));
                msica_arg_seq_add_tail(seq, szArgument);
            }

            iTicks += MSICA_INTERFACE_TICK_SIZE;
            break; /* Interface names are unique. There should be no other interface with this name. */
        }
    }

    tap_free_interface_list(pInterfaceList);
    return dwResult;
}


UINT __stdcall
EvaluateTAPInterfaces(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    openvpnmsica_debug_popup(TEXT(__FUNCTION__));

    UINT uiResult;
    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    struct msica_arg_seq
        seqInstallTAPInterfaces,
        seqInstallTAPInterfacesCommit,
        seqInstallTAPInterfacesRollback,
        seqUninstallTAPInterfaces,
        seqUninstallTAPInterfacesCommit,
        seqUninstallTAPInterfacesRollback;
    msica_arg_seq_init(&seqInstallTAPInterfaces);
    msica_arg_seq_init(&seqInstallTAPInterfacesCommit);
    msica_arg_seq_init(&seqInstallTAPInterfacesRollback);
    msica_arg_seq_init(&seqUninstallTAPInterfaces);
    msica_arg_seq_init(&seqUninstallTAPInterfacesCommit);
    msica_arg_seq_init(&seqUninstallTAPInterfacesRollback);

    /* Check rollback state. */
    bool bRollbackEnabled = MsiEvaluateCondition(hInstall, TEXT("RollbackDisabled")) != MSICONDITION_TRUE;

    /* Open MSI database. */
    MSIHANDLE hDatabase = MsiGetActiveDatabase(hInstall);
    if (hDatabase == 0)
    {
        msg(M_NONFATAL, "%s: MsiGetActiveDatabase failed", __FUNCTION__);
        uiResult = ERROR_INVALID_HANDLE;
        goto cleanup_exec_seq;
    }

    /* Check if TAPInterface table exists. If it doesn't exist, there's nothing to do. */
    switch (MsiDatabaseIsTablePersistent(hDatabase, TEXT("TAPInterface")))
    {
        case MSICONDITION_FALSE:
        case MSICONDITION_TRUE: break;

        default:
            uiResult = ERROR_SUCCESS;
            goto cleanup_hDatabase;
    }

    /* Prepare a query to get a list/view of interfaces. */
    MSIHANDLE hViewST = 0;
    LPCTSTR szQuery = TEXT("SELECT `Interface`,`DisplayName`,`Condition`,`Component_` FROM `TAPInterface`");
    uiResult = MsiDatabaseOpenView(hDatabase, szQuery, &hViewST);
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiDatabaseOpenView() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiDatabaseOpenView(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szQuery);
        goto cleanup_hDatabase;
    }

    /* Execute query! */
    uiResult = MsiViewExecute(hViewST, 0);
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiViewExecute() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiViewExecute(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szQuery);
        goto cleanup_hViewST;
    }

    /* Create a record to report progress with. */
    MSIHANDLE hRecordProg = MsiCreateRecord(2);
    if (!hRecordProg)
    {
        uiResult = ERROR_INVALID_HANDLE;
        msg(M_NONFATAL, "%s: MsiCreateRecord failed", __FUNCTION__);
        goto cleanup_hViewST_close;
    }

    for (;; )
    {
        /* Fetch one record from the view. */
        MSIHANDLE hRecord = 0;
        uiResult = MsiViewFetch(hViewST, &hRecord);
        if (uiResult == ERROR_NO_MORE_ITEMS)
        {
            uiResult = ERROR_SUCCESS;
            break;
        }
        else if (uiResult != ERROR_SUCCESS)
        {
            SetLastError(uiResult); /* MSDN does not mention MsiViewFetch() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_NONFATAL | M_ERRNO, "%s: MsiViewFetch failed", __FUNCTION__);
            goto cleanup_hRecordProg;
        }

        INSTALLSTATE iInstalled, iAction;
        {
            /* Read interface component ID (`Component_` is field #4). */
            LPTSTR szValue = NULL;
            uiResult = msi_get_record_string(hRecord, 4, &szValue);
            if (uiResult != ERROR_SUCCESS)
            {
                goto cleanup_hRecord;
            }

            /* Get the component state. */
            uiResult = MsiGetComponentState(hInstall, szValue, &iInstalled, &iAction);
            if (uiResult != ERROR_SUCCESS)
            {
                SetLastError(uiResult); /* MSDN does not mention MsiGetComponentState() to set GetLastError(). But we do have an error code. Set last error manually. */
                msg(M_NONFATAL | M_ERRNO, "%s: MsiGetComponentState(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szValue);
                free(szValue);
                goto cleanup_hRecord;
            }
            free(szValue);
        }

        /* Get interface display name (`DisplayName` is field #2). */
        LPTSTR szDisplayName = NULL;
        uiResult = msi_format_field(hInstall, hRecord, 2, &szDisplayName);
        if (uiResult != ERROR_SUCCESS)
        {
            goto cleanup_hRecord;
        }
        /* `DisplayName` field type is [Filename](https://docs.microsoft.com/en-us/windows/win32/msi/filename), which is either "8.3|long name" or "8.3". */
        LPTSTR szDisplayNameEx = _tcschr(szDisplayName, TEXT('|'));
        szDisplayNameEx = szDisplayNameEx != NULL ? szDisplayNameEx + 1 : szDisplayName;

        if (iAction > INSTALLSTATE_BROKEN)
        {
            int iTicks = 0;

            if (iAction >= INSTALLSTATE_LOCAL)
            {
                /* Read and evaluate interface condition (`Condition` is field #3). */
                LPTSTR szValue = NULL;
                uiResult = msi_get_record_string(hRecord, 3, &szValue);
                if (uiResult != ERROR_SUCCESS)
                {
                    goto cleanup_szDisplayName;
                }
#ifdef __GNUC__
/*
 * warning: enumeration value ‘MSICONDITION_TRUE’ not handled in switch
 * warning: enumeration value ‘MSICONDITION_NONE’ not handled in switch
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
#endif
                switch (MsiEvaluateCondition(hInstall, szValue))
                {
                    case MSICONDITION_FALSE:
                        free(szValue);
                        goto cleanup_szDisplayName;

                    case MSICONDITION_ERROR:
                        uiResult = ERROR_INVALID_FIELD;
                        msg(M_NONFATAL | M_ERRNO, "%s: MsiEvaluateCondition(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szValue);
                        free(szValue);
                        goto cleanup_szDisplayName;
                }
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
                free(szValue);

                /* Component is or should be installed. Schedule interface creation. */
                if (openvpnmsica_schedule_interface_create(
                        &seqInstallTAPInterfaces,
                        bRollbackEnabled ? &seqInstallTAPInterfacesRollback : NULL,
                        szDisplayNameEx,
                        &iTicks) != ERROR_SUCCESS)
                {
                    uiResult = ERROR_INSTALL_FAILED;
                    goto cleanup_szDisplayName;
                }
            }
            else
            {
                /* Component is installed, but should be degraded to advertised/removed. Schedule interface deletition.
                 *
                 * Note: On interface removal (product is being uninstalled), we tolerate dwResult error.
                 * Better a partial uninstallation than no uninstallation at all.
                 */
                openvpnmsica_schedule_interface_delete(
                    &seqUninstallTAPInterfaces,
                    bRollbackEnabled ? &seqUninstallTAPInterfacesCommit : NULL,
                    bRollbackEnabled ? &seqUninstallTAPInterfacesRollback : NULL,
                    szDisplayNameEx,
                    &iTicks);
            }

            /* Arrange the amount of tick space to add to the progress indicator.
             * Do this within the loop to poll for user cancellation. */
            MsiRecordSetInteger(hRecordProg, 1, 3 /* OP3 = Add ticks to the expected total number of progress of the progress bar */);
            MsiRecordSetInteger(hRecordProg, 2, iTicks);
            if (MsiProcessMessage(hInstall, INSTALLMESSAGE_PROGRESS, hRecordProg) == IDCANCEL)
            {
                uiResult = ERROR_INSTALL_USEREXIT;
                goto cleanup_szDisplayName;
            }
        }

cleanup_szDisplayName:
        free(szDisplayName);
cleanup_hRecord:
        MsiCloseHandle(hRecord);
        if (uiResult != ERROR_SUCCESS)
        {
            goto cleanup_hRecordProg;
        }
    }

    /* Store deferred custom action parameters. */
    if ((uiResult = openvpnmsica_setup_sequence(hInstall, TEXT("InstallTAPInterfaces"          ), &seqInstallTAPInterfaces          )) != ERROR_SUCCESS
        || (uiResult = openvpnmsica_setup_sequence(hInstall, TEXT("InstallTAPInterfacesCommit"    ), &seqInstallTAPInterfacesCommit    )) != ERROR_SUCCESS
        || (uiResult = openvpnmsica_setup_sequence(hInstall, TEXT("InstallTAPInterfacesRollback"  ), &seqInstallTAPInterfacesRollback  )) != ERROR_SUCCESS
        || (uiResult = openvpnmsica_setup_sequence(hInstall, TEXT("UninstallTAPInterfaces"        ), &seqUninstallTAPInterfaces        )) != ERROR_SUCCESS
        || (uiResult = openvpnmsica_setup_sequence(hInstall, TEXT("UninstallTAPInterfacesCommit"  ), &seqUninstallTAPInterfacesCommit  )) != ERROR_SUCCESS
        || (uiResult = openvpnmsica_setup_sequence(hInstall, TEXT("UninstallTAPInterfacesRollback"), &seqUninstallTAPInterfacesRollback)) != ERROR_SUCCESS)
    {
        goto cleanup_hRecordProg;
    }

    uiResult = ERROR_SUCCESS;

cleanup_hRecordProg:
    MsiCloseHandle(hRecordProg);
cleanup_hViewST_close:
    MsiViewClose(hViewST);
cleanup_hViewST:
    MsiCloseHandle(hViewST);
cleanup_hDatabase:
    MsiCloseHandle(hDatabase);
cleanup_exec_seq:
    msica_arg_seq_free(&seqInstallTAPInterfaces);
    msica_arg_seq_free(&seqInstallTAPInterfacesCommit);
    msica_arg_seq_free(&seqInstallTAPInterfacesRollback);
    msica_arg_seq_free(&seqUninstallTAPInterfaces);
    msica_arg_seq_free(&seqUninstallTAPInterfacesCommit);
    msica_arg_seq_free(&seqUninstallTAPInterfacesRollback);
    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return uiResult;
}


/**
 * Parses string encoded GUID.
 *
 * @param szArg         Zero terminated string where the GUID string starts
 *
 * @param guid          Pointer to GUID that receives parsed value
 *
 * @return TRUE on success; FALSE otherwise
 */
static BOOL
openvpnmsica_parse_guid(_In_z_ LPCWSTR szArg, _Out_ GUID *guid)
{
    if (swscanf_s(szArg, _L(PRIXGUID), PRIGUID_PARAM_REF(*guid)) != 11)
    {
        msg(M_NONFATAL | M_ERRNO, "%s: swscanf_s(\"%ls\") failed", __FUNCTION__, szArg);
        return FALSE;
    }
    return TRUE;
}


UINT __stdcall
ProcessDeferredAction(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    openvpnmsica_debug_popup(TEXT(__FUNCTION__));

    UINT uiResult;
    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    BOOL bIsCleanup = MsiGetMode(hInstall, MSIRUNMODE_COMMIT) || MsiGetMode(hInstall, MSIRUNMODE_ROLLBACK);

    /* Get sequence arguments. Always Unicode as CommandLineToArgvW() is available as Unicode-only. */
    LPWSTR szSequence = NULL;
    uiResult = msi_get_string(hInstall, L"CustomActionData", &szSequence);
    if (uiResult != ERROR_SUCCESS)
    {
        goto cleanup_CoInitialize;
    }
    int nArgs;
    LPWSTR *szArg = CommandLineToArgvW(szSequence, &nArgs);
    if (szArg == NULL)
    {
        uiResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: CommandLineToArgvW(\"%ls\") failed", __FUNCTION__, szSequence);
        goto cleanup_szSequence;
    }

    /* Tell the installer to use explicit progress messages. */
    MSIHANDLE hRecordProg = MsiCreateRecord(3);
    MsiRecordSetInteger(hRecordProg, 1, 1);
    MsiRecordSetInteger(hRecordProg, 2, 1);
    MsiRecordSetInteger(hRecordProg, 3, 0);
    MsiProcessMessage(hInstall, INSTALLMESSAGE_PROGRESS, hRecordProg);

    /* Prepare hRecordProg for progress messages. */
    MsiRecordSetInteger(hRecordProg, 1, 2);
    MsiRecordSetInteger(hRecordProg, 3, 0);

    BOOL bRebootRequired = FALSE;

    for (int i = 1 /*CommandLineToArgvW injects msiexec.exe as szArg[0]*/; i < nArgs; ++i)
    {
        DWORD dwResult = ERROR_SUCCESS;

        if (wcsncmp(szArg[i], L"create=", 7) == 0)
        {
            /* Create an interface with a given name. */
            LPCWSTR szName = szArg[i] + 7;

            {
                /* Report the name of the interface to installer. */
                MSIHANDLE hRecord = MsiCreateRecord(3);
                MsiRecordSetString(hRecord, 1, TEXT("Creating interface"));
                MsiRecordSetString(hRecord, 2, szName);
                int iResult = MsiProcessMessage(hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
                MsiCloseHandle(hRecord);
                if (iResult == IDCANCEL)
                {
                    uiResult = ERROR_INSTALL_USEREXIT;
                    goto cleanup;
                }
            }

            GUID guidInterface;
            dwResult = tap_create_interface(NULL, NULL, NULL, &bRebootRequired, &guidInterface);
            if (dwResult == ERROR_SUCCESS)
            {
                /* Set interface name. */
                dwResult = tap_set_interface_name(&guidInterface, szName);
                if (dwResult != ERROR_SUCCESS)
                {
                    tap_delete_interface(NULL, &guidInterface, &bRebootRequired);
                }
            }
        }
        else if (wcsncmp(szArg[i], L"deleteN=", 8) == 0)
        {
            /* Delete the interface by name. */
            LPCWSTR szName = szArg[i] + 8;

            {
                /* Report the name of the interface to installer. */
                MSIHANDLE hRecord = MsiCreateRecord(3);
                MsiRecordSetString(hRecord, 1, TEXT("Deleting interface"));
                MsiRecordSetString(hRecord, 2, szName);
                int iResult = MsiProcessMessage(hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
                MsiCloseHandle(hRecord);
                if (iResult == IDCANCEL)
                {
                    uiResult = ERROR_INSTALL_USEREXIT;
                    goto cleanup;
                }
            }

            /* Get available TUN/TAP interfaces. */
            struct tap_interface_node *pInterfaceList = NULL;
            dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, FALSE);
            if (dwResult == ERROR_SUCCESS)
            {
                /* Does the interface exist? */
                for (struct tap_interface_node *pInterface = pInterfaceList; pInterface != NULL; pInterface = pInterface->pNext)
                {
                    if (_tcsicmp(szName, pInterface->szName) == 0)
                    {
                        /* Interface found. */
                        dwResult = tap_delete_interface(NULL, &pInterface->guid, &bRebootRequired);
                        break;
                    }
                }

                tap_free_interface_list(pInterfaceList);
            }
        }
        else if (wcsncmp(szArg[i], L"delete=", 7) == 0)
        {
            /* Delete the interface by GUID. */
            GUID guid;
            if (!openvpnmsica_parse_guid(szArg[i] + 7, &guid))
            {
                goto invalid_argument;
            }
            dwResult = tap_delete_interface(NULL, &guid, &bRebootRequired);
        }
        else if (wcsncmp(szArg[i], L"enable=", 7) == 0)
        {
            /* Enable the interface. */
            GUID guid;
            if (!openvpnmsica_parse_guid(szArg[i] + 7, &guid))
            {
                goto invalid_argument;
            }
            dwResult = tap_enable_interface(NULL, &guid, TRUE, &bRebootRequired);
        }
        else if (wcsncmp(szArg[i], L"disable=", 8) == 0)
        {
            /* Disable the interface. */
            GUID guid;
            if (!openvpnmsica_parse_guid(szArg[i] + 8, &guid))
            {
                goto invalid_argument;
            }
            dwResult = tap_enable_interface(NULL, &guid, FALSE, &bRebootRequired);
        }
        else
        {
            goto invalid_argument;
        }

        if (dwResult != ERROR_SUCCESS && !bIsCleanup /* Ignore errors in case of commit/rollback to do as much work as possible. */)
        {
            uiResult = ERROR_INSTALL_FAILURE;
            goto cleanup;
        }

        /* Report progress and check for user cancellation. */
        MsiRecordSetInteger(hRecordProg, 2, MSICA_INTERFACE_TICK_SIZE);
        if (MsiProcessMessage(hInstall, INSTALLMESSAGE_PROGRESS, hRecordProg) == IDCANCEL)
        {
            dwResult = ERROR_INSTALL_USEREXIT;
            goto cleanup;
        }

        continue;

invalid_argument:
        msg(M_NONFATAL, "%s: Ignoring invalid argument: %ls", __FUNCTION__, szArg[i]);
    }

cleanup:
    if (bRebootRequired)
    {
        MsiSetMode(hInstall, MSIRUNMODE_REBOOTATEND, TRUE);
    }
    MsiCloseHandle(hRecordProg);
    LocalFree(szArg);
cleanup_szSequence:
    free(szSequence);
cleanup_CoInitialize:
    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return uiResult;
}
