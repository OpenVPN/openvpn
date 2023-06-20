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
#include <setupapi.h>
#include <newdev.h>
#include <initguid.h>
#include <devguid.h>

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

#define MSICA_ADAPTER_TICK_SIZE (16*1024) /** Amount of tick space to reserve for one TAP/TUN adapter creation/deletition. */

#define FILE_NEED_REBOOT        L".ovpn_need_reboot"

#define OPENVPN_CONNECT_ADAPTER_SUBSTR L"OpenVPN Connect"

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
setup_sequence(
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
_debug_popup(_In_z_ LPCSTR szFunctionName)
{
    TCHAR szTitle[0x100], szMessage[0x100+MAX_PATH], szProcessPath[MAX_PATH];

    /* Compose pop-up title. The dialog title will contain function name to ease the process
     * locating. Mind that Visual Studio displays window titles on the process list. */
    _stprintf_s(szTitle, _countof(szTitle), TEXT("%hs v%") TEXT(PRIsLPTSTR),
                szFunctionName, TEXT(PACKAGE_VERSION));

    /* Get process name. */
    GetModuleFileName(NULL, szProcessPath, _countof(szProcessPath));
    LPCTSTR szProcessName = _tcsrchr(szProcessPath, TEXT('\\'));
    szProcessName = szProcessName ? szProcessName + 1 : szProcessPath;

    /* Compose the pop-up message. */
    _stprintf_s(
        szMessage, _countof(szMessage),
        TEXT("The %") TEXT(PRIsLPTSTR) TEXT(" process (PID: %u) has started to execute the %hs")
        TEXT(" custom action.\r\n")
        TEXT("\r\n")
        TEXT("If you would like to debug the custom action, attach a debugger to this process and set breakpoints before dismissing this dialog.\r\n")
        TEXT("\r\n")
        TEXT("If you are not debugging this custom action, you can safely ignore this message."),
        szProcessName,
        GetCurrentProcessId(),
        szFunctionName);

    MessageBox(NULL, szMessage, szTitle, MB_OK);
}

#define debug_popup(f) _debug_popup(f)
#else  /* ifdef _DEBUG */
#define debug_popup(f)
#endif /* ifdef _DEBUG */

static void
find_adapters(
    _In_ MSIHANDLE hInstall,
    _In_z_ LPCTSTR szzHardwareIDs,
    _In_z_ LPCTSTR szAdaptersPropertyName,
    _In_z_ LPCTSTR szActiveAdaptersPropertyName)
{
    UINT uiResult;

    /* Get network adapters with given hardware ID. */
    struct tap_adapter_node *pAdapterList = NULL;
    uiResult = tap_list_adapters(NULL, szzHardwareIDs, &pAdapterList);
    if (uiResult != ERROR_SUCCESS)
    {
        return;
    }
    else if (pAdapterList == NULL)
    {
        /* No adapters - no fun. */
        return;
    }

    /* Get IPv4/v6 info for all network adapters. Actually, we're interested in link status only: up/down? */
    PIP_ADAPTER_ADDRESSES pAdapterAdresses = NULL;
    ULONG ulAdapterAdressesSize = 16*1024;
    for (size_t iteration = 0; iteration < 2; iteration++)
    {
        pAdapterAdresses = (PIP_ADAPTER_ADDRESSES)malloc(ulAdapterAdressesSize);
        if (pAdapterAdresses == NULL)
        {
            msg(M_NONFATAL, "%s: malloc(%u) failed", __FUNCTION__, ulAdapterAdressesSize);
            uiResult = ERROR_OUTOFMEMORY; goto cleanup_pAdapterList;
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
            uiResult = ulResult; goto cleanup_pAdapterList;
        }
    }

    /* Count adapters. */
    size_t adapter_count = 0;
    for (struct tap_adapter_node *pAdapter = pAdapterList; pAdapter; pAdapter = pAdapter->pNext)
    {
        adapter_count++;
    }

    /* Prepare semicolon delimited list of TAP adapter ID(s) and active TAP adapter ID(s). */
    LPTSTR
        szAdapters     = (LPTSTR)malloc(adapter_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR)),
        szAdaptersTail = szAdapters;
    if (szAdapters == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, adapter_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR));
        uiResult = ERROR_OUTOFMEMORY; goto cleanup_pAdapterAdresses;
    }

    LPTSTR
        szAdaptersActive     = (LPTSTR)malloc(adapter_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR)),
        szAdaptersActiveTail = szAdaptersActive;
    if (szAdaptersActive == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, adapter_count * (38 /*GUID*/ + 1 /*separator/terminator*/) * sizeof(TCHAR));
        uiResult = ERROR_OUTOFMEMORY; goto cleanup_szAdapters;
    }

    for (struct tap_adapter_node *pAdapter = pAdapterList; pAdapter; pAdapter = pAdapter->pNext)
    {
        /* exclude adapters created by OpenVPN Connect, since they're removed on Connect uninstallation */
        if (_tcsstr(pAdapter->szName, OPENVPN_CONNECT_ADAPTER_SUBSTR))
        {
            msg(M_WARN, "%s: skip OpenVPN Connect adapter '%ls'", __FUNCTION__, pAdapter->szName);
            continue;
        }

        /* Convert adapter GUID to UTF-16 string. (LPOLESTR defaults to LPWSTR) */
        LPOLESTR szAdapterId = NULL;
        StringFromIID((REFIID)&pAdapter->guid, &szAdapterId);

        /* Append to the list of TAP adapter ID(s). */
        if (szAdapters < szAdaptersTail)
        {
            *(szAdaptersTail++) = TEXT(';');
        }
        memcpy(szAdaptersTail, szAdapterId, 38 * sizeof(TCHAR));
        szAdaptersTail += 38;

        /* If this adapter is active (connected), add it to the list of active TAP adapter ID(s). */
        for (PIP_ADAPTER_ADDRESSES p = pAdapterAdresses; p; p = p->Next)
        {
            OLECHAR szId[38 /*GUID*/ + 1 /*terminator*/];
            GUID guid;
            if (MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, p->AdapterName, -1, szId, _countof(szId)) > 0
                && SUCCEEDED(IIDFromString(szId, &guid))
                && memcmp(&guid, &pAdapter->guid, sizeof(GUID)) == 0)
            {
                if (p->OperStatus == IfOperStatusUp)
                {
                    /* This TAP adapter is active (connected). */
                    if (szAdaptersActive < szAdaptersActiveTail)
                    {
                        *(szAdaptersActiveTail++) = TEXT(';');
                    }
                    memcpy(szAdaptersActiveTail, szAdapterId, 38 * sizeof(TCHAR));
                    szAdaptersActiveTail += 38;
                }
                break;
            }
        }
        CoTaskMemFree(szAdapterId);
    }
    szAdaptersTail      [0] = 0;
    szAdaptersActiveTail[0] = 0;

    /* Set Installer properties. */
    uiResult = MsiSetProperty(hInstall, szAdaptersPropertyName, szAdapters);
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"%s\") failed", __FUNCTION__, szAdaptersPropertyName);
        goto cleanup_szAdaptersActive;
    }
    uiResult = MsiSetProperty(hInstall, szActiveAdaptersPropertyName, szAdaptersActive);
    if (uiResult != ERROR_SUCCESS)
    {
        SetLastError(uiResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"%s\") failed", __FUNCTION__, szActiveAdaptersPropertyName);
        goto cleanup_szAdaptersActive;
    }

cleanup_szAdaptersActive:
    free(szAdaptersActive);
cleanup_szAdapters:
    free(szAdapters);
cleanup_pAdapterAdresses:
    free(pAdapterAdresses);
cleanup_pAdapterList:
    tap_free_adapter_list(pAdapterList);
}


UINT __stdcall
FindSystemInfo(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    debug_popup(__FUNCTION__);

    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    find_adapters(
        hInstall,
        TEXT("root\\") TEXT(TAP_WIN_COMPONENT_ID) TEXT("\0") TEXT(TAP_WIN_COMPONENT_ID) TEXT("\0"),
        TEXT("TAPWINDOWS6ADAPTERS"),
        TEXT("ACTIVETAPWINDOWS6ADAPTERS"));
    find_adapters(
        hInstall,
        TEXT("Wintun") TEXT("\0"),
        TEXT("WINTUNADAPTERS"),
        TEXT("ACTIVEWINTUNADAPTERS"));
    find_adapters(
        hInstall,
        TEXT("ovpn-dco") TEXT("\0"),
        TEXT("OVPNDCOADAPTERS"),
        TEXT("ACTIVEOVPNDCOADAPTERS"));

    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return ERROR_SUCCESS;
}


UINT __stdcall
CloseOpenVPNGUI(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif
    UNREFERENCED_PARAMETER(hInstall); /* This CA is does not interact with MSI session (report errors, access properties, tables, etc.). */

    debug_popup(__FUNCTION__);

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

    debug_popup(__FUNCTION__);

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
 * Schedules adapter creation.
 *
 * When the rollback is enabled, the adapter deletition is scheduled on rollback.
 *
 * @param seq           The argument sequence to pass to InstallTUNTAPAdapters custom action
 *
 * @param seqRollback   The argument sequence to pass to InstallTUNTAPAdaptersRollback custom
 *                      action. NULL when rollback is disabled.
 *
 * @param szDisplayName  Adapter display name
 *
 * @param szHardwareId  Adapter hardware ID
 *
 * @param iTicks        Pointer to an integer that represents amount of work (on progress
 *                      indicator) the InstallTUNTAPAdapters will take. This function increments it
 *                      by MSICA_ADAPTER_TICK_SIZE for each adapter to create.
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
static DWORD
schedule_adapter_create(
    _Inout_ struct msica_arg_seq *seq,
    _Inout_opt_ struct msica_arg_seq *seqRollback,
    _In_z_ LPCTSTR szDisplayName,
    _In_z_ LPCTSTR szHardwareId,
    _Inout_ int *iTicks)
{
    /* Get existing network adapters. */
    struct tap_adapter_node *pAdapterList = NULL;
    DWORD dwResult = tap_list_adapters(NULL, NULL, &pAdapterList);
    if (dwResult != ERROR_SUCCESS)
    {
        return dwResult;
    }

    /* Does adapter exist? */
    for (struct tap_adapter_node *pAdapterOther = pAdapterList;; pAdapterOther = pAdapterOther->pNext)
    {
        if (pAdapterOther == NULL)
        {
            /* No adapter with a same name found. */
            TCHAR szArgument[10 /*create=""|deleteN=""*/ + MAX_PATH /*szDisplayName*/ + 1 /*|*/ + MAX_PATH /*szHardwareId*/ + 1 /*terminator*/];

            /* InstallTUNTAPAdapters will create the adapter. */
            _stprintf_s(
                szArgument, _countof(szArgument),
                TEXT("create=\"%.*s|%.*s\""),
                MAX_PATH, szDisplayName,
                MAX_PATH, szHardwareId);
            msica_arg_seq_add_tail(seq, szArgument);

            if (seqRollback)
            {
                /* InstallTUNTAPAdaptersRollback will delete the adapter. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("deleteN=\"%.*s\""),
                    MAX_PATH, szDisplayName);
                msica_arg_seq_add_head(seqRollback, szArgument);
            }

            *iTicks += MSICA_ADAPTER_TICK_SIZE;
            break;
        }
        else if (_tcsicmp(szDisplayName, pAdapterOther->szName) == 0)
        {
            /* Adapter with a same name found. */
            for (LPCTSTR hwid = pAdapterOther->szzHardwareIDs;; hwid += _tcslen(hwid) + 1)
            {
                if (hwid[0] == 0)
                {
                    /* This adapter has a different hardware ID. */
                    msg(M_NONFATAL, "%s: Adapter with name \"%" PRIsLPTSTR "\" already exists", __FUNCTION__, pAdapterOther->szName);
                    dwResult = ERROR_ALREADY_EXISTS;
                    goto cleanup_pAdapterList;
                }
                else if (_tcsicmp(hwid, szHardwareId) == 0)
                {
                    /* This is an adapter with the requested hardware ID. We already have what we want! */
                    break;
                }
            }
            break; /* Adapter names are unique. There should be no other adapter with this name. */
        }
    }

cleanup_pAdapterList:
    tap_free_adapter_list(pAdapterList);
    return dwResult;
}


/**
 * Schedules adapter deletion.
 *
 * When the rollback is enabled, the adapter deletition is scheduled as: disable in
 * UninstallTUNTAPAdapters, enable on rollback, delete on commit.
 *
 * When rollback is disabled, the adapter deletition is scheduled as delete in
 * UninstallTUNTAPAdapters.
 *
 * @param seq           The argument sequence to pass to UninstallTUNTAPAdapters custom action
 *
 * @param seqCommit     The argument sequence to pass to UninstallTUNTAPAdaptersCommit custom
 *                      action. NULL when rollback is disabled.
 *
 * @param seqRollback   The argument sequence to pass to UninstallTUNTAPAdaptersRollback custom
 *                      action. NULL when rollback is disabled.
 *
 * @param szDisplayName  Adapter display name
 *
 * @param szzHardwareIDs  String of strings with acceptable adapter hardware IDs
 *
 * @param iTicks        Pointer to an integer that represents amount of work (on progress
 *                      indicator) the UninstallTUNTAPAdapters will take. This function increments
 *                      it by MSICA_ADAPTER_TICK_SIZE for each adapter to delete.
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
static DWORD
schedule_adapter_delete(
    _Inout_ struct msica_arg_seq *seq,
    _Inout_opt_ struct msica_arg_seq *seqCommit,
    _Inout_opt_ struct msica_arg_seq *seqRollback,
    _In_z_ LPCTSTR szDisplayName,
    _In_z_ LPCTSTR szzHardwareIDs,
    _Inout_ int *iTicks)
{
    /* Get adapters with given hardware ID. */
    struct tap_adapter_node *pAdapterList = NULL;
    DWORD dwResult = tap_list_adapters(NULL, szzHardwareIDs, &pAdapterList);
    if (dwResult != ERROR_SUCCESS)
    {
        return dwResult;
    }

    /* Does adapter exist? */
    for (struct tap_adapter_node *pAdapter = pAdapterList; pAdapter != NULL; pAdapter = pAdapter->pNext)
    {
        if (_tcsicmp(szDisplayName, pAdapter->szName) == 0)
        {
            /* Adapter found. */
            TCHAR szArgument[8 /*disable=|enable=|delete=*/ + 38 /*{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}*/ + 1 /*terminator*/];
            if (seqCommit && seqRollback)
            {
                /* UninstallTUNTAPAdapters will disable the adapter. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("disable=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pAdapter->guid));
                msica_arg_seq_add_tail(seq, szArgument);

                /* UninstallTUNTAPAdaptersRollback will re-enable the adapter. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("enable=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pAdapter->guid));
                msica_arg_seq_add_head(seqRollback, szArgument);

                /* UninstallTUNTAPAdaptersCommit will delete the adapter. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("delete=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pAdapter->guid));
                msica_arg_seq_add_tail(seqCommit, szArgument);
            }
            else
            {
                /* UninstallTUNTAPAdapters will delete the adapter. */
                _stprintf_s(
                    szArgument, _countof(szArgument),
                    TEXT("delete=") TEXT(PRIXGUID),
                    PRIGUID_PARAM(pAdapter->guid));
                msica_arg_seq_add_tail(seq, szArgument);
            }

            iTicks += MSICA_ADAPTER_TICK_SIZE;
            break; /* Adapter names are unique. There should be no other adapter with this name. */
        }
    }

    tap_free_adapter_list(pAdapterList);
    return dwResult;
}


UINT __stdcall
EvaluateTUNTAPAdapters(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    debug_popup(__FUNCTION__);

    UINT uiResult;
    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    struct msica_arg_seq
        seqInstall,
        seqInstallCommit,
        seqInstallRollback,
        seqUninstall,
        seqUninstallCommit,
        seqUninstallRollback;
    msica_arg_seq_init(&seqInstall);
    msica_arg_seq_init(&seqInstallCommit);
    msica_arg_seq_init(&seqInstallRollback);
    msica_arg_seq_init(&seqUninstall);
    msica_arg_seq_init(&seqUninstallCommit);
    msica_arg_seq_init(&seqUninstallRollback);

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

    /* Check if TUNTAPAdapter table exists. If it doesn't exist, there's nothing to do. */
    switch (MsiDatabaseIsTablePersistent(hDatabase, TEXT("TUNTAPAdapter")))
    {
        case MSICONDITION_FALSE:
        case MSICONDITION_TRUE: break;

        default:
            uiResult = ERROR_SUCCESS;
            goto cleanup_hDatabase;
    }

    /* Prepare a query to get a list/view of adapters. */
    MSIHANDLE hViewST = 0;
    LPCTSTR szQuery = TEXT("SELECT `Adapter`,`DisplayName`,`Condition`,`Component_`,`HardwareId` FROM `TUNTAPAdapter`");
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
            /* Read adapter component ID (`Component_` is field #4). */
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

        /* Get adapter display name (`DisplayName` is field #2). */
        LPTSTR szDisplayName = NULL;
        uiResult = msi_format_field(hInstall, hRecord, 2, &szDisplayName);
        if (uiResult != ERROR_SUCCESS)
        {
            goto cleanup_hRecord;
        }
        /* `DisplayName` field type is [Filename](https://docs.microsoft.com/en-us/windows/win32/msi/filename), which is either "8.3|long name" or "8.3". */
        LPTSTR szDisplayNameEx = _tcschr(szDisplayName, TEXT('|'));
        szDisplayNameEx = szDisplayNameEx != NULL ? szDisplayNameEx + 1 : szDisplayName;

        /* Get adapter hardware ID (`HardwareId` is field #5). */
        TCHAR szzHardwareIDs[0x100] = { 0 };
        {
            LPTSTR szHwId = NULL;
            uiResult = msi_get_record_string(hRecord, 5, &szHwId);
            if (uiResult != ERROR_SUCCESS)
            {
                goto cleanup_szDisplayName;
            }
            memcpy_s(szzHardwareIDs, sizeof(szzHardwareIDs) - 2*sizeof(TCHAR) /*requires double zero termination*/, szHwId, _tcslen(szHwId)*sizeof(TCHAR));
            free(szHwId);
        }

        if (iAction > INSTALLSTATE_BROKEN)
        {
            int iTicks = 0;

            if (iAction >= INSTALLSTATE_LOCAL)
            {
                /* Read and evaluate adapter condition (`Condition` is field #3). */
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

                /* Component is or should be installed. Schedule adapter creation. */
                if (schedule_adapter_create(
                        &seqInstall,
                        bRollbackEnabled ? &seqInstallRollback : NULL,
                        szDisplayNameEx,
                        szzHardwareIDs,
                        &iTicks) != ERROR_SUCCESS)
                {
                    uiResult = ERROR_INSTALL_FAILED;
                    goto cleanup_szDisplayName;
                }
            }
            else
            {
                /* Component is installed, but should be degraded to advertised/removed. Schedule adapter deletition.
                 *
                 * Note: On adapter removal (product is being uninstalled), we tolerate dwResult error.
                 * Better a partial uninstallation than no uninstallation at all.
                 */
                schedule_adapter_delete(
                    &seqUninstall,
                    bRollbackEnabled ? &seqUninstallCommit : NULL,
                    bRollbackEnabled ? &seqUninstallRollback : NULL,
                    szDisplayNameEx,
                    szzHardwareIDs,
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

    /* save path to user's temp dir to be used later by deferred actions */
    TCHAR tmpDir[MAX_PATH];
    GetTempPath(MAX_PATH, tmpDir);

    TCHAR str[MAX_PATH + 7];
    _stprintf_s(str, _countof(str), TEXT("tmpdir=%") TEXT(PRIsLPTSTR), tmpDir);
    msica_arg_seq_add_tail(&seqInstall, str);
    msica_arg_seq_add_tail(&seqInstallCommit, str);
    msica_arg_seq_add_tail(&seqInstallRollback, str);
    msica_arg_seq_add_tail(&seqUninstall, str);
    msica_arg_seq_add_tail(&seqUninstallCommit, str);
    msica_arg_seq_add_tail(&seqUninstallRollback, str);

    /* Store deferred custom action parameters. */
    if ((uiResult = setup_sequence(hInstall, TEXT("InstallTUNTAPAdapters"          ), &seqInstall          )) != ERROR_SUCCESS
        || (uiResult = setup_sequence(hInstall, TEXT("InstallTUNTAPAdaptersCommit"    ), &seqInstallCommit    )) != ERROR_SUCCESS
        || (uiResult = setup_sequence(hInstall, TEXT("InstallTUNTAPAdaptersRollback"  ), &seqInstallRollback  )) != ERROR_SUCCESS
        || (uiResult = setup_sequence(hInstall, TEXT("UninstallTUNTAPAdapters"        ), &seqUninstall        )) != ERROR_SUCCESS
        || (uiResult = setup_sequence(hInstall, TEXT("UninstallTUNTAPAdaptersCommit"  ), &seqUninstallCommit  )) != ERROR_SUCCESS
        || (uiResult = setup_sequence(hInstall, TEXT("UninstallTUNTAPAdaptersRollback"), &seqUninstallRollback)) != ERROR_SUCCESS)
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
    msica_arg_seq_free(&seqInstall);
    msica_arg_seq_free(&seqInstallCommit);
    msica_arg_seq_free(&seqInstallRollback);
    msica_arg_seq_free(&seqUninstall);
    msica_arg_seq_free(&seqUninstallCommit);
    msica_arg_seq_free(&seqUninstallRollback);
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
parse_guid(
    _In_z_ LPCWSTR szArg,
    _Out_ GUID *guid)
{
    if (swscanf_s(szArg, _L(PRIXGUID), PRIGUID_PARAM_REF(*guid)) != 11)
    {
        msg(M_NONFATAL | M_ERRNO, "%s: swscanf_s(\"%ls\") failed", __FUNCTION__, szArg);
        return FALSE;
    }
    return TRUE;
}


/**
 * Create empty file in user's temp directory. The existence of this file
 * is checked in the end of installation by ScheduleReboot immediate custom action
 * which schedules reboot.
 *
 * @param szTmpDir path to user's temp dirctory
 *
 */
static void
CreateRebootFile(_In_z_ LPCWSTR szTmpDir)
{
    WCHAR path[MAX_PATH];
    swprintf_s(path, _countof(path), L"%s%s", szTmpDir, FILE_NEED_REBOOT);

    msg(M_WARN, "%s: Reboot required, create reboot indication file \"%ls\"", __FUNCTION__, path);

    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        msg(M_NONFATAL | M_ERRNO, "%s: CreateFile(\"%ls\") failed", __FUNCTION__, path);
    }
    else
    {
        CloseHandle(file);
    }
}

UINT __stdcall
ProcessDeferredAction(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    debug_popup(__FUNCTION__);

    UINT uiResult;
    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));
    WCHAR tmpDir[MAX_PATH] = {0};

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
            /* Create an adapter with a given name and hardware ID. */
            LPWSTR szName = szArg[i] + 7;
            LPWSTR szHardwareId = wcschr(szName, L'|');
            if (szHardwareId == NULL)
            {
                goto invalid_argument;
            }
            szHardwareId[0] = 0;
            ++szHardwareId;

            {
                /* Report the name of the adapter to installer. */
                MSIHANDLE hRecord = MsiCreateRecord(4);
                MsiRecordSetString(hRecord, 1, TEXT("Creating adapter"));
                MsiRecordSetString(hRecord, 2, szName);
                MsiRecordSetString(hRecord, 3, szHardwareId);
                int iResult = MsiProcessMessage(hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
                MsiCloseHandle(hRecord);
                if (iResult == IDCANCEL)
                {
                    uiResult = ERROR_INSTALL_USEREXIT;
                    goto cleanup;
                }
            }

            GUID guidAdapter;
            dwResult = tap_create_adapter(NULL, NULL, szHardwareId, &bRebootRequired, &guidAdapter);
            if (dwResult == ERROR_SUCCESS)
            {
                /* Set adapter name. May fail on some machines, but that is not critical - use silent
                 * flag to mute messagebox and print error only to log */
                tap_set_adapter_name(&guidAdapter, szName, TRUE);
            }
        }
        else if (wcsncmp(szArg[i], L"deleteN=", 8) == 0)
        {
            /* Delete the adapter by name. */
            LPCWSTR szName = szArg[i] + 8;

            {
                /* Report the name of the adapter to installer. */
                MSIHANDLE hRecord = MsiCreateRecord(3);
                MsiRecordSetString(hRecord, 1, TEXT("Deleting adapter"));
                MsiRecordSetString(hRecord, 2, szName);
                int iResult = MsiProcessMessage(hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
                MsiCloseHandle(hRecord);
                if (iResult == IDCANCEL)
                {
                    uiResult = ERROR_INSTALL_USEREXIT;
                    goto cleanup;
                }
            }

            /* Get existing adapters. */
            struct tap_adapter_node *pAdapterList = NULL;
            dwResult = tap_list_adapters(NULL, NULL, &pAdapterList);
            if (dwResult == ERROR_SUCCESS)
            {
                /* Does the adapter exist? */
                for (struct tap_adapter_node *pAdapter = pAdapterList; pAdapter != NULL; pAdapter = pAdapter->pNext)
                {
                    if (_tcsicmp(szName, pAdapter->szName) == 0)
                    {
                        /* Adapter found. */
                        dwResult = tap_delete_adapter(NULL, &pAdapter->guid, &bRebootRequired);
                        break;
                    }
                }

                tap_free_adapter_list(pAdapterList);
            }
        }
        else if (wcsncmp(szArg[i], L"delete=", 7) == 0)
        {
            /* Delete the adapter by GUID. */
            GUID guid;
            if (!parse_guid(szArg[i] + 7, &guid))
            {
                goto invalid_argument;
            }
            dwResult = tap_delete_adapter(NULL, &guid, &bRebootRequired);
        }
        else if (wcsncmp(szArg[i], L"enable=", 7) == 0)
        {
            /* Enable the adapter. */
            GUID guid;
            if (!parse_guid(szArg[i] + 7, &guid))
            {
                goto invalid_argument;
            }
            dwResult = tap_enable_adapter(NULL, &guid, TRUE, &bRebootRequired);
        }
        else if (wcsncmp(szArg[i], L"disable=", 8) == 0)
        {
            /* Disable the adapter. */
            GUID guid;
            if (!parse_guid(szArg[i] + 8, &guid))
            {
                goto invalid_argument;
            }
            dwResult = tap_enable_adapter(NULL, &guid, FALSE, &bRebootRequired);
        }
        else if (wcsncmp(szArg[i], L"tmpdir=", 7) == 0)
        {
            wcscpy_s(tmpDir, _countof(tmpDir), szArg[i] + 7);
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
        MsiRecordSetInteger(hRecordProg, 2, MSICA_ADAPTER_TICK_SIZE);
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
    if (bRebootRequired && wcslen(tmpDir) > 0)
    {
        CreateRebootFile(tmpDir);
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

UINT __stdcall
CheckAndScheduleReboot(_In_ MSIHANDLE hInstall)
{
#ifdef _MSC_VER
#pragma comment(linker, DLLEXP_EXPORT)
#endif

    debug_popup(__FUNCTION__);

    BOOL bIsCoInitialized = SUCCEEDED(CoInitialize(NULL));

    OPENVPNMSICA_SAVE_MSI_SESSION(hInstall);

    /* get user-specific temp path, to where we create reboot indication file */
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    /* check if reboot file exists */
    WCHAR path[MAX_PATH];
    swprintf_s(path, _countof(path), L"%s%s", tempPath, FILE_NEED_REBOOT);
    WIN32_FIND_DATA data = { 0 };
    HANDLE searchHandle = FindFirstFileW(path, &data);
    if (searchHandle != INVALID_HANDLE_VALUE)
    {
        msg(M_WARN, "%s: Reboot file exists, schedule reboot", __FUNCTION__);

        FindClose(searchHandle);
        DeleteFileW(path);

        MsiSetMode(hInstall, MSIRUNMODE_REBOOTATEND, TRUE);
    }

    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return ERROR_SUCCESS;
}
