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
#include "msica_op.h"
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
 * Cleanup actions
 */
static const struct {
    LPCTSTR szName;               /** Name of the cleanup action. This name is appended to the deferred custom action name (e.g. "InstallTAPInterfaces" >> "InstallTAPInterfacesCommit"). */
    TCHAR szSuffix[3];            /** Two-character suffix to append to the cleanup operation sequence filename */
} openvpnmsica_cleanup_action_seqs[MSICA_CLEANUP_ACTION_COUNT] =
{
    { TEXT("Commit"  ), TEXT("cm") }, /* MSICA_CLEANUP_ACTION_COMMIT   */
    { TEXT("Rollback"), TEXT("rb") }, /* MSICA_CLEANUP_ACTION_ROLLBACK */
};


/**
 * Creates a new sequence file in the current user's temporary folder and sets MSI property
 * to its absolute path.
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @param szProperty    MSI property name to set to the absolute path of the sequence file.
 *
 * @param szFilename    String of minimum MAXPATH+1 characters where the zero-terminated
 *                      file absolute path is stored.
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
static DWORD
openvpnmsica_setup_sequence_filename(
    _In_ MSIHANDLE hInstall,
    _In_z_ LPCTSTR szProperty,
    _Out_z_cap_(MAXPATH + 1) LPTSTR szFilename)
{
    DWORD dwResult;

    if (szFilename == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Generate a random filename in the temporary folder. */
    if (GetTempPath(MAX_PATH + 1, szFilename) == 0)
    {
        dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: GetTempPath failed", __FUNCTION__);
        return dwResult;
    }
    if (GetTempFileName(szFilename, szProperty, 0, szFilename) == 0)
    {
        dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: GetTempFileName failed", __FUNCTION__);
        return dwResult;
    }

    /* Store sequence filename to property for deferred custom action. */
    dwResult = MsiSetProperty(hInstall, szProperty, szFilename);
    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szProperty);
        return dwResult;
    }

    /* Generate and store cleanup operation sequence filenames to properties. */
    LPTSTR szExtension = PathFindExtension(szFilename);
    TCHAR szFilenameEx[MAX_PATH + 1 /*dash*/ + 2 /*suffix*/ + 1 /*terminator*/];
    size_t len_property_name = _tcslen(szProperty);
    for (size_t i = 0; i < MSICA_CLEANUP_ACTION_COUNT; i++)
    {
        size_t len_action_name_z = _tcslen(openvpnmsica_cleanup_action_seqs[i].szName) + 1;
        TCHAR *szPropertyEx = (TCHAR *)malloc((len_property_name + len_action_name_z) * sizeof(TCHAR));
        if (szPropertyEx == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, (len_property_name + len_action_name_z) * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        memcpy(szPropertyEx, szProperty, len_property_name * sizeof(TCHAR));
        memcpy(szPropertyEx + len_property_name, openvpnmsica_cleanup_action_seqs[i].szName, len_action_name_z * sizeof(TCHAR));
        _stprintf_s(
            szFilenameEx, _countof(szFilenameEx),
            TEXT("%.*s-%.2s%s"),
            (int)(szExtension - szFilename), szFilename,
            openvpnmsica_cleanup_action_seqs[i].szSuffix,
            szExtension);
        dwResult = MsiSetProperty(hInstall, szPropertyEx, szFilenameEx);
        if (dwResult != ERROR_SUCCESS)
        {
            SetLastError(dwResult); /* MSDN does not mention MsiSetProperty() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_NONFATAL | M_ERRNO, "%s: MsiSetProperty(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szPropertyEx);
            free(szPropertyEx);
            return dwResult;
        }
        free(szPropertyEx);
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

    /* List of deferred custom actions EvaluateTAPInterfaces prepares operation sequence for. */
    static const LPCTSTR szActionNames[] =
    {
        TEXT("InstallTAPInterfaces"),
        TEXT("UninstallTAPInterfaces"),
    };
    struct msica_op_seq exec_seq[_countof(szActionNames)];
    for (size_t i = 0; i < _countof(szActionNames); i++)
    {
        msica_op_seq_init(&exec_seq[i]);
    }

    {
        /* Check and store the rollback enabled state. */
        TCHAR szValue[128];
        DWORD dwLength = _countof(szValue);
        bool enable_rollback = MsiGetProperty(hInstall, TEXT("RollbackDisabled"), szValue, &dwLength) == ERROR_SUCCESS ?
                               _ttoi(szValue) || _totlower(szValue[0]) == TEXT('y') ? false : true :
                               true;
        for (size_t i = 0; i < _countof(szActionNames); i++)
        {
            msica_op_seq_add_tail(
                &exec_seq[i],
                msica_op_create_bool(
                    msica_op_rollback_enable,
                    0,
                    NULL,
                    enable_rollback));
        }
    }

    /* Open MSI database. */
    MSIHANDLE hDatabase = MsiGetActiveDatabase(hInstall);
    if (hDatabase == 0)
    {
        msg(M_NONFATAL, "%s: MsiGetActiveDatabase failed", __FUNCTION__);
        uiResult = ERROR_INVALID_HANDLE; goto cleanup_exec_seq;
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
                msica_op_seq_add_tail(
                    &exec_seq[0],
                    msica_op_create_string(
                        msica_op_tap_interface_create,
                        MSICA_INTERFACE_TICK_SIZE,
                        NULL,
                        szDisplayNameEx));
            }
            else
            {
                /* Component is installed, but should be degraded to advertised/removed. Schedule interface deletition. */
                msica_op_seq_add_tail(
                    &exec_seq[1],
                    msica_op_create_string(
                        msica_op_tap_interface_delete_by_name,
                        MSICA_INTERFACE_TICK_SIZE,
                        NULL,
                        szDisplayNameEx));
            }

            /* The amount of tick space to add for each interface to progress indicator. */
            MsiRecordSetInteger(hRecordProg, 1, 3 /* OP3 = Add ticks to the expected total number of progress of the progress bar */);
            MsiRecordSetInteger(hRecordProg, 2, MSICA_INTERFACE_TICK_SIZE);
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

    /*
     * Write sequence files.
     * The InstallTAPInterfaces and UninstallTAPInterfaces are deferred custom actions, thus all this information
     * will be unavailable to them. Therefore save all required operations and their info to sequence files.
     */
    TCHAR szSeqFilename[_countof(szActionNames)][MAX_PATH + 1];
    for (size_t i = 0; i < _countof(szActionNames); i++)
    {
        szSeqFilename[i][0] = 0;
    }
    for (size_t i = 0; i < _countof(szActionNames); i++)
    {
        uiResult = openvpnmsica_setup_sequence_filename(hInstall, szActionNames[i], szSeqFilename[i]);
        if (uiResult != ERROR_SUCCESS)
        {
            goto cleanup_szSeqFilename;
        }
        HANDLE hSeqFile = CreateFile(
            szSeqFilename[i],
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            NULL);
        if (hSeqFile == INVALID_HANDLE_VALUE)
        {
            uiResult = GetLastError();
            msg(M_NONFATAL | M_ERRNO, "%s: CreateFile(\"%.*" PRIsLPTSTR "\") failed", __FUNCTION__, _countof(szSeqFilename[i]), szSeqFilename[i]);
            goto cleanup_szSeqFilename;
        }
        uiResult = msica_op_seq_save(&exec_seq[i], hSeqFile);
        CloseHandle(hSeqFile);
        if (uiResult != ERROR_SUCCESS)
        {
            goto cleanup_szSeqFilename;
        }
    }

    uiResult = ERROR_SUCCESS;

cleanup_szSeqFilename:
    if (uiResult != ERROR_SUCCESS)
    {
        /* Clean-up sequence files. */
        for (size_t i = _countof(szActionNames); i--; )
        {
            if (szSeqFilename[i][0])
            {
                DeleteFile(szSeqFilename[i]);
            }
        }
    }
cleanup_hRecordProg:
    MsiCloseHandle(hRecordProg);
cleanup_hViewST_close:
    MsiViewClose(hViewST);
cleanup_hViewST:
    MsiCloseHandle(hViewST);
cleanup_hDatabase:
    MsiCloseHandle(hDatabase);
cleanup_exec_seq:
    for (size_t i = 0; i < _countof(szActionNames); i++)
    {
        msica_op_seq_free(&exec_seq[i]);
    }
    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return uiResult;
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

    /* Get sequence filename and open the file. */
    LPTSTR szSeqFilename = NULL;
    uiResult = msi_get_string(hInstall, TEXT("CustomActionData"), &szSeqFilename);
    if (uiResult != ERROR_SUCCESS)
    {
        goto cleanup_CoInitialize;
    }
    struct msica_op_seq seq = { .head = NULL, .tail = NULL };
    {
        HANDLE hSeqFile = CreateFile(
            szSeqFilename,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            NULL);
        if (hSeqFile == INVALID_HANDLE_VALUE)
        {
            uiResult = GetLastError();
            if (uiResult == ERROR_FILE_NOT_FOUND && bIsCleanup)
            {
                /*
                 * Sequence file not found and this is rollback/commit action. Either of the following scenarios are possible:
                 * - The delayed action failed to save the rollback/commit sequence to file. The delayed action performed cleanup itself. No further operation is required.
                 * - Somebody removed the rollback/commit file between delayed action and rollback/commit action. No further operation is possible.
                 */
                uiResult = ERROR_SUCCESS;
                goto cleanup_szSeqFilename;
            }
            msg(M_NONFATAL | M_ERRNO, "%s: CreateFile(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, szSeqFilename);
            goto cleanup_szSeqFilename;
        }

        /* Load sequence. */
        uiResult = msica_op_seq_load(&seq, hSeqFile);
        CloseHandle(hSeqFile);
        if (uiResult != ERROR_SUCCESS)
        {
            goto cleanup_seq;
        }
    }

    /* Prepare session context. */
    struct msica_session session;
    openvpnmsica_session_init(
        &session,
        hInstall,
        bIsCleanup, /* In case of commit/rollback, continue sequence on error, to do as much cleanup as possible. */
        false);

    /* Execute sequence. */
    uiResult = msica_op_seq_process(&seq, &session);
    if (!bIsCleanup)
    {
        /*
         * Save cleanup scripts of delayed action regardless of action's execution status.
         * Rollback action MUST be scheduled in InstallExecuteSequence before this action! Otherwise cleanup won't be performed in case this action execution failed.
         */
        DWORD dwResultEx; /* Don't overwrite uiResult. */
        LPCTSTR szExtension = PathFindExtension(szSeqFilename);
        TCHAR szFilenameEx[MAX_PATH + 1 /*dash*/ + 2 /*suffix*/ + 1 /*terminator*/];
        for (size_t i = 0; i < MSICA_CLEANUP_ACTION_COUNT; i++)
        {
            _stprintf_s(
                szFilenameEx, _countof(szFilenameEx),
                TEXT("%.*s-%.2s%s"),
                (int)(szExtension - szSeqFilename), szSeqFilename,
                openvpnmsica_cleanup_action_seqs[i].szSuffix,
                szExtension);

            /* After commit, delete rollback file. After rollback, delete commit file. */
            msica_op_seq_add_tail(
                &session.seq_cleanup[MSICA_CLEANUP_ACTION_COUNT - 1 - i],
                msica_op_create_string(
                    msica_op_file_delete,
                    0,
                    NULL,
                    szFilenameEx));
        }
        for (size_t i = 0; i < MSICA_CLEANUP_ACTION_COUNT; i++)
        {
            _stprintf_s(
                szFilenameEx, _countof(szFilenameEx),
                TEXT("%.*s-%.2s%s"),
                (int)(szExtension - szSeqFilename), szSeqFilename,
                openvpnmsica_cleanup_action_seqs[i].szSuffix,
                szExtension);

            /* Save the cleanup sequence file. */
            HANDLE hSeqFile = CreateFile(
                szFilenameEx,
                GENERIC_WRITE,
                FILE_SHARE_READ,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                NULL);
            if (hSeqFile == INVALID_HANDLE_VALUE)
            {
                dwResultEx = GetLastError();
                msg(M_NONFATAL | M_ERRNO, "%s: CreateFile(\"%.*" PRIsLPTSTR "\") failed", __FUNCTION__, _countof(szFilenameEx), szFilenameEx);
                goto cleanup_session;
            }
            dwResultEx = msica_op_seq_save(&session.seq_cleanup[i], hSeqFile);
            CloseHandle(hSeqFile);
            if (dwResultEx != ERROR_SUCCESS)
            {
                goto cleanup_session;
            }
        }

cleanup_session:
        if (dwResultEx != ERROR_SUCCESS)
        {
            /* The commit and/or rollback scripts were not written to file successfully. Perform the cleanup immediately. */
            struct msica_session session_cleanup;
            openvpnmsica_session_init(
                &session_cleanup,
                hInstall,
                true,
                false);
            msica_op_seq_process(&session.seq_cleanup[MSICA_CLEANUP_ACTION_ROLLBACK], &session_cleanup);

            szExtension = PathFindExtension(szSeqFilename);
            for (size_t i = 0; i < MSICA_CLEANUP_ACTION_COUNT; i++)
            {
                _stprintf_s(
                    szFilenameEx, _countof(szFilenameEx),
                    TEXT("%.*s-%.2s%s"),
                    (int)(szExtension - szSeqFilename), szSeqFilename,
                    openvpnmsica_cleanup_action_seqs[i].szSuffix,
                    szExtension);
                DeleteFile(szFilenameEx);
            }
        }
    }
    else
    {
        /* No cleanup after cleanup support. */
        uiResult = ERROR_SUCCESS;
    }

    for (size_t i = MSICA_CLEANUP_ACTION_COUNT; i--; )
    {
        msica_op_seq_free(&session.seq_cleanup[i]);
    }
    DeleteFile(szSeqFilename);
cleanup_seq:
    msica_op_seq_free(&seq);
cleanup_szSeqFilename:
    free(szSeqFilename);
cleanup_CoInitialize:
    if (bIsCoInitialized)
    {
        CoUninitialize();
    }
    return uiResult;
}
