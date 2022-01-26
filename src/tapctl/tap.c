/*
 *  tapctl -- Utility to manipulate TUN/TAP adapters on Windows
 *            https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2018-2022 Simon Rozman <simon@rozman.si>
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

#include "tap.h"
#include "error.h"

#include <windows.h>
#include <cfgmgr32.h>
#include <objbase.h>
#include <setupapi.h>
#include <stdio.h>
#include <tchar.h>
#include <newdev.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")
#endif


const static GUID GUID_DEVCLASS_NET = { 0x4d36e972L, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

const static TCHAR szAdapterRegKeyPathTemplate[] = TEXT("SYSTEM\\CurrentControlSet\\Control\\Network\\%") TEXT(PRIsLPOLESTR) TEXT("\\%") TEXT(PRIsLPOLESTR) TEXT("\\Connection");
#define ADAPTER_REGKEY_PATH_MAX (_countof(TEXT("SYSTEM\\CurrentControlSet\\Control\\Network\\")) - 1 + 38 + _countof(TEXT("\\")) - 1 + 38 + _countof(TEXT("\\Connection")))

/**
 * Dynamically load a library and find a function in it
 *
 * @param libname     Name of the library to load
 * @param funcname    Name of the function to find
 * @param m           Pointer to a module. On return this is set to the
 *                    the handle to the loaded library. The caller must
 *                    free it by calling FreeLibrary() if not NULL.
 *
 * @return            Pointer to the function
 *                    NULL on error -- use GetLastError() to find the error code.
 *
 **/
static void *
find_function(const WCHAR *libname, const char *funcname, HMODULE *m)
{
    WCHAR libpath[MAX_PATH];
    void *fptr = NULL;

    /* Make sure the dll is loaded from the system32 folder */
    if (!GetSystemDirectoryW(libpath, _countof(libpath)))
    {
       return NULL;
    }

    size_t len = _countof(libpath) - wcslen(libpath) - 1;
    if (len < wcslen(libname) + 1)
    {
       SetLastError(ERROR_INSUFFICIENT_BUFFER);
       return NULL;
    }
    wcsncat(libpath, L"\\", len);
    wcsncat(libpath, libname, len-1);

    *m = LoadLibraryW(libpath);
    if (*m == NULL)
    {
       return NULL;
    }
    fptr = GetProcAddress(*m, funcname);
    if (!fptr)
    {
       FreeLibrary(*m);
       *m = NULL;
       return NULL;
    }
    return fptr;
}

/**
 * Returns length of string of strings
 *
 * @param szz           Pointer to a string of strings (terminated by an empty string)
 *
 * @return Number of characters not counting the final zero terminator
 **/
static inline size_t
_tcszlen(_In_z_ LPCTSTR szz)
{
    LPCTSTR s;
    for (s = szz; s[0]; s += _tcslen(s) + 1)
    {
    }
    return s - szz;
}


/**
 * Checks if string is contained in the string of strings. Comparison is made case-insensitive.
 *
 * @param szzHay        Pointer to a string of strings (terminated by an empty string) we are
 *                      looking in
 *
 * @param szNeedle      The string we are searching for
 *
 * @return Pointer to the string in szzHay that matches szNeedle is found; NULL otherwise
 */
static LPCTSTR
_tcszistr(_In_z_ LPCTSTR szzHay, _In_z_ LPCTSTR szNeedle)
{
    for (LPCTSTR s = szzHay; s[0]; s += _tcslen(s) + 1)
    {
        if (_tcsicmp(s, szNeedle) == 0)
        {
            return s;
        }
    }

    return NULL;
}


/**
 * Function that performs a specific task on a device
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
typedef DWORD (*devop_func_t)(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _Inout_ LPBOOL pbRebootRequired);


/**
 * Checks device install parameters if a system reboot is required.
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
check_reboot(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _Inout_ LPBOOL pbRebootRequired)
{
    if (pbRebootRequired == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    SP_DEVINSTALL_PARAMS devinstall_params = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS) };
    if (!SetupDiGetDeviceInstallParams(
            hDeviceInfoSet,
            pDeviceInfoData,
            &devinstall_params))
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiGetDeviceInstallParams failed", __FUNCTION__);
        return dwResult;
    }

    if ((devinstall_params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0)
    {
        *pbRebootRequired = TRUE;
    }

    return ERROR_SUCCESS;
}


/**
 * Deletes the device.
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
delete_device(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _Inout_ LPBOOL pbRebootRequired)
{
    SP_REMOVEDEVICE_PARAMS params =
    {
        .ClassInstallHeader =
        {
            .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
            .InstallFunction = DIF_REMOVE,
        },
        .Scope = DI_REMOVEDEVICE_GLOBAL,
        .HwProfile = 0,
    };

    /* Set class installer parameters for DIF_REMOVE. */
    if (!SetupDiSetClassInstallParams(
            hDeviceInfoSet,
            pDeviceInfoData,
            &params.ClassInstallHeader,
            sizeof(SP_REMOVEDEVICE_PARAMS)))
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiSetClassInstallParams failed", __FUNCTION__);
        return dwResult;
    }

    /* Call appropriate class installer. */
    if (!SetupDiCallClassInstaller(
            DIF_REMOVE,
            hDeviceInfoSet,
            pDeviceInfoData))
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiCallClassInstaller(DIF_REMOVE) failed", __FUNCTION__);
        return dwResult;
    }

    /* Check if a system reboot is required. */
    check_reboot(hDeviceInfoSet, pDeviceInfoData, pbRebootRequired);
    return ERROR_SUCCESS;
}


/**
 * Changes the device state.
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param bEnable       TRUE to enable the device; FALSE to disable.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
change_device_state(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _In_ BOOL bEnable,
    _Inout_ LPBOOL pbRebootRequired)
{
    SP_PROPCHANGE_PARAMS params =
    {
        .ClassInstallHeader =
        {
            .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
            .InstallFunction = DIF_PROPERTYCHANGE,
        },
        .StateChange = bEnable ? DICS_ENABLE : DICS_DISABLE,
        .Scope = DICS_FLAG_GLOBAL,
        .HwProfile = 0,
    };

    /* Set class installer parameters for DIF_PROPERTYCHANGE. */
    if (!SetupDiSetClassInstallParams(
            hDeviceInfoSet,
            pDeviceInfoData,
            &params.ClassInstallHeader,
            sizeof(SP_PROPCHANGE_PARAMS)))
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiSetClassInstallParams failed", __FUNCTION__);
        return dwResult;
    }

    /* Call appropriate class installer. */
    if (!SetupDiCallClassInstaller(
            DIF_PROPERTYCHANGE,
            hDeviceInfoSet,
            pDeviceInfoData))
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiCallClassInstaller(DIF_PROPERTYCHANGE) failed", __FUNCTION__);
        return dwResult;
    }

    /* Check if a system reboot is required. */
    check_reboot(hDeviceInfoSet, pDeviceInfoData, pbRebootRequired);
    return ERROR_SUCCESS;
}


/**
 * Enables the device.
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
enable_device(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _Inout_ LPBOOL pbRebootRequired)
{
    return change_device_state(hDeviceInfoSet, pDeviceInfoData, TRUE, pbRebootRequired);
}


/**
 * Disables the device.
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
disable_device(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _Inout_ LPBOOL pbRebootRequired)
{
    return change_device_state(hDeviceInfoSet, pDeviceInfoData, FALSE, pbRebootRequired);
}


/**
 * Reads string value from registry key.
 *
 * @param hKey          Handle of the registry key to read from. Must be opened with read
 *                      access.
 *
 * @param szName        Name of the value to read.
 *
 * @param pszValue      Pointer to string to retrieve registry value. If the value type is
 *                      REG_EXPAND_SZ the value is expanded using ExpandEnvironmentStrings().
 *                      The string must be released with free() after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static DWORD
get_reg_string(
    _In_ HKEY hKey,
    _In_ LPCTSTR szName,
    _Out_ LPTSTR *pszValue)
{
    if (pszValue == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    DWORD dwValueType = REG_NONE, dwSize = 0;
    DWORD dwResult = RegQueryValueEx(
        hKey,
        szName,
        NULL,
        &dwValueType,
        NULL,
        &dwSize);
    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult); /* MSDN does not mention RegQueryValueEx() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: enumerating \"%" PRIsLPTSTR "\" registry value failed", __FUNCTION__, szName);
        return dwResult;
    }

    switch (dwValueType)
    {
        case REG_SZ:
        case REG_EXPAND_SZ:
        {
            /* Read value. */
            LPTSTR szValue = (LPTSTR)malloc(dwSize);
            if (szValue == NULL)
            {
                msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwSize);
                return ERROR_OUTOFMEMORY;
            }

            dwResult = RegQueryValueEx(
                hKey,
                szName,
                NULL,
                NULL,
                (LPBYTE)szValue,
                &dwSize);
            if (dwResult != ERROR_SUCCESS)
            {
                SetLastError(dwResult); /* MSDN does not mention RegQueryValueEx() to set GetLastError(). But we do have an error code. Set last error manually. */
                msg(M_NONFATAL | M_ERRNO, "%s: reading \"%" PRIsLPTSTR "\" registry value failed", __FUNCTION__, szName);
                free(szValue);
                return dwResult;
            }

            if (dwValueType == REG_EXPAND_SZ)
            {
                /* Expand the environment strings. */
                DWORD
                    dwSizeExp = dwSize * 2,
                    dwCountExp =
#ifdef UNICODE
                    dwSizeExp / sizeof(TCHAR);
#else
                    dwSizeExp / sizeof(TCHAR) - 1;     /* Note: ANSI version requires one extra char. */
#endif
                LPTSTR szValueExp = (LPTSTR)malloc(dwSizeExp);
                if (szValueExp == NULL)
                {
                    free(szValue);
                    msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwSizeExp);
                    return ERROR_OUTOFMEMORY;
                }

                DWORD dwCountExpResult = ExpandEnvironmentStrings(
                    szValue,
                    szValueExp, dwCountExp
                    );
                if (dwCountExpResult == 0)
                {
                    msg(M_NONFATAL | M_ERRNO, "%s: expanding \"%" PRIsLPTSTR "\" registry value failed", __FUNCTION__, szName);
                    free(szValueExp);
                    free(szValue);
                    return dwResult;
                }
                else if (dwCountExpResult <= dwCountExp)
                {
                    /* The buffer was big enough. */
                    free(szValue);
                    *pszValue = szValueExp;
                    return ERROR_SUCCESS;
                }
                else
                {
                    /* Retry with a bigger buffer. */
                    free(szValueExp);
#ifdef UNICODE
                    dwSizeExp = dwCountExpResult * sizeof(TCHAR);
#else
                    /* Note: ANSI version requires one extra char. */
                    dwSizeExp = (dwCountExpResult + 1) * sizeof(TCHAR);
#endif
                    dwCountExp = dwCountExpResult;
                    szValueExp = (LPTSTR)malloc(dwSizeExp);
                    if (szValueExp == NULL)
                    {
                        free(szValue);
                        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwSizeExp);
                        return ERROR_OUTOFMEMORY;
                    }

                    dwCountExpResult = ExpandEnvironmentStrings(
                        szValue,
                        szValueExp, dwCountExp);
                    free(szValue);
                    *pszValue = szValueExp;
                    return ERROR_SUCCESS;
                }
            }
            else
            {
                *pszValue = szValue;
                return ERROR_SUCCESS;
            }
        }

        default:
            msg(M_NONFATAL, "%s: \"%" PRIsLPTSTR "\" registry value is not string (type %u)", __FUNCTION__, dwValueType);
            return ERROR_UNSUPPORTED_TYPE;
    }
}


/**
 * Returns network adapter ID.
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param iNumAttempts  After the device is created, it might take some time before the
 *                      registry key is populated. This parameter specifies the number of
 *                      attempts to read NetCfgInstanceId value from registry. A 1sec sleep
 *                      is inserted between retry attempts.
 *
 * @param pguidAdapter  A pointer to GUID that receives network adapter ID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
get_net_adapter_guid(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _In_ int iNumAttempts,
    _Out_ LPGUID pguidAdapter)
{
    DWORD dwResult = ERROR_BAD_ARGUMENTS;

    if (pguidAdapter == NULL || iNumAttempts < 1)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY hKey = SetupDiOpenDevRegKey(
        hDeviceInfoSet,
        pDeviceInfoData,
        DICS_FLAG_GLOBAL,
        0,
        DIREG_DRV,
        KEY_READ);
    if (hKey == INVALID_HANDLE_VALUE)
    {
        dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiOpenDevRegKey failed", __FUNCTION__);
        return dwResult;
    }

    while (iNumAttempts > 0)
    {
        /* Query the NetCfgInstanceId value. Using get_reg_string() right on might clutter the output with error messages while the registry is still being populated. */
        LPTSTR szCfgGuidString = NULL;
        dwResult = RegQueryValueEx(hKey, TEXT("NetCfgInstanceId"), NULL, NULL, NULL, NULL);
        if (dwResult != ERROR_SUCCESS)
        {
            if (dwResult == ERROR_FILE_NOT_FOUND && --iNumAttempts > 0)
            {
                /* Wait and retry. */
                Sleep(1000);
                continue;
            }

            SetLastError(dwResult); /* MSDN does not mention RegQueryValueEx() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_NONFATAL | M_ERRNO, "%s: querying \"NetCfgInstanceId\" registry value failed", __FUNCTION__);
            break;
        }

        /* Read the NetCfgInstanceId value now. */
        dwResult = get_reg_string(
            hKey,
            TEXT("NetCfgInstanceId"),
            &szCfgGuidString);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }

        dwResult = SUCCEEDED(CLSIDFromString(szCfgGuidString, (LPCLSID)pguidAdapter)) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
        free(szCfgGuidString);
        break;
    }

    RegCloseKey(hKey);
    return dwResult;
}


/**
 * Returns a specified Plug and Play device property.
 *
 * @param hDeviceInfoSet  A handle to a device information set that contains a device
 *                      information element that represents the device.
 *
 * @param pDeviceInfoData  A pointer to an SP_DEVINFO_DATA structure that specifies the
 *                      device information element in hDeviceInfoSet.
 *
 * @param dwProperty     Specifies the property to be retrieved. See
 *                       https://msdn.microsoft.com/en-us/library/windows/hardware/ff551967.aspx
 *
 * @pdwPropertyRegDataType  A pointer to a variable that receives the data type of the
 *                       property that is being retrieved. This is one of the standard
 *                       registry data types. This parameter is optional and can be NULL.
 *
 * @param ppData         A pointer to pointer to data that receives the device property. The
 *                       data must be released with free() after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
get_device_reg_property(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _In_ DWORD dwProperty,
    _Out_opt_ LPDWORD pdwPropertyRegDataType,
    _Out_ LPVOID *ppData)
{
    DWORD dwResult = ERROR_BAD_ARGUMENTS;

    if (ppData == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Try with stack buffer first. */
    BYTE bBufStack[128];
    DWORD dwRequiredSize = 0;
    if (SetupDiGetDeviceRegistryProperty(
            hDeviceInfoSet,
            pDeviceInfoData,
            dwProperty,
            pdwPropertyRegDataType,
            bBufStack,
            sizeof(bBufStack),
            &dwRequiredSize))
    {
        /* Copy from stack. */
        *ppData = malloc(dwRequiredSize);
        if (*ppData == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwRequiredSize);
            return ERROR_OUTOFMEMORY;
        }

        memcpy(*ppData, bBufStack, dwRequiredSize);
        return ERROR_SUCCESS;
    }
    else
    {
        dwResult = GetLastError();
        if (dwResult == ERROR_INSUFFICIENT_BUFFER)
        {
            /* Allocate on heap and retry. */
            *ppData = malloc(dwRequiredSize);
            if (*ppData == NULL)
            {
                msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, dwRequiredSize);
                return ERROR_OUTOFMEMORY;
            }

            if (SetupDiGetDeviceRegistryProperty(
                    hDeviceInfoSet,
                    pDeviceInfoData,
                    dwProperty,
                    pdwPropertyRegDataType,
                    *ppData,
                    dwRequiredSize,
                    &dwRequiredSize))
            {
                return ERROR_SUCCESS;
            }
            else
            {
                dwResult = GetLastError();
                msg(M_NONFATAL | M_ERRNO, "%s: SetupDiGetDeviceRegistryProperty(%u) failed", __FUNCTION__, dwProperty);
                return dwResult;
            }
        }
        else
        {
            msg(M_NONFATAL | M_ERRNO, "%s: SetupDiGetDeviceRegistryProperty(%u) failed", __FUNCTION__, dwProperty);
            return dwResult;
        }
    }
}


DWORD
tap_create_adapter(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szDeviceDescription,
    _In_ LPCTSTR szHwId,
    _Inout_ LPBOOL pbRebootRequired,
    _Out_ LPGUID pguidAdapter)
{
    DWORD dwResult;
    HMODULE libnewdev = NULL;

    if (szHwId == NULL
        || pbRebootRequired == NULL
        || pguidAdapter == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Create an empty device info set for network adapter device class. */
    HDEVINFO hDevInfoList = SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, hwndParent);
    if (hDevInfoList == INVALID_HANDLE_VALUE)
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiCreateDeviceInfoList failed", __FUNCTION__);
        return dwResult;
    }

    /* Get the device class name from GUID. */
    TCHAR szClassName[MAX_CLASS_NAME_LEN];
    if (!SetupDiClassNameFromGuid(
            &GUID_DEVCLASS_NET,
            szClassName,
            _countof(szClassName),
            NULL))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiClassNameFromGuid failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    /* Create a new device info element and add it to the device info set. */
    SP_DEVINFO_DATA devinfo_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
    if (!SetupDiCreateDeviceInfo(
            hDevInfoList,
            szClassName,
            &GUID_DEVCLASS_NET,
            szDeviceDescription,
            hwndParent,
            DICD_GENERATE_ID,
            &devinfo_data))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiCreateDeviceInfo failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    /* Set a device information element as the selected member of a device information set. */
    if (!SetupDiSetSelectedDevice(
            hDevInfoList,
            &devinfo_data))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiSetSelectedDevice failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    /* Set Plug&Play device hardware ID property. */
    if (!SetupDiSetDeviceRegistryProperty(
            hDevInfoList,
            &devinfo_data,
            SPDRP_HARDWAREID,
            (const BYTE *)szHwId, (DWORD)((_tcslen(szHwId) + 1) * sizeof(TCHAR))))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiSetDeviceRegistryProperty failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    /* Register the device instance with the PnP Manager */
    if (!SetupDiCallClassInstaller(
            DIF_REGISTERDEVICE,
            hDevInfoList,
            &devinfo_data))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    /* Install the device using DiInstallDevice()
     * We instruct the system to use the best driver in the driver store
     * by setting the drvinfo argument of DiInstallDevice as NULL. This
     * assumes a driver is already installed in the driver store.
     */
#ifdef HAVE_DIINSTALLDEVICE
    if (!DiInstallDevice(hwndParent, hDevInfoList, &devinfo_data, NULL, 0, pbRebootRequired))
#else
    /* mingw does not resolve DiInstallDevice, so load it at run time. */
    typedef BOOL (WINAPI *DiInstallDeviceFn) (HWND, HDEVINFO, SP_DEVINFO_DATA *,
                                                  SP_DRVINFO_DATA *, DWORD, BOOL *);
    DiInstallDeviceFn installfn
           = find_function (L"newdev.dll", "DiInstallDevice", &libnewdev);

    if (!installfn)
    {
        dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: Failed to locate DiInstallDevice()", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    if (!installfn(hwndParent, hDevInfoList, &devinfo_data, NULL, 0, pbRebootRequired))
#endif
    {
        dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: DiInstallDevice failed", __FUNCTION__);
        goto cleanup_remove_device;
    }

    /* Get network adapter ID from registry. Retry for max 30sec. */
    dwResult = get_net_adapter_guid(hDevInfoList, &devinfo_data, 30, pguidAdapter);

cleanup_remove_device:
    if (dwResult != ERROR_SUCCESS)
    {
        /* The adapter was installed. But, the adapter ID was unobtainable. Clean-up. */
        SP_REMOVEDEVICE_PARAMS removedevice_params =
        {
            .ClassInstallHeader =
            {
                .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                .InstallFunction = DIF_REMOVE,
            },
            .Scope = DI_REMOVEDEVICE_GLOBAL,
            .HwProfile = 0,
        };

        /* Set class installer parameters for DIF_REMOVE. */
        if (SetupDiSetClassInstallParams(
                hDevInfoList,
                &devinfo_data,
                &removedevice_params.ClassInstallHeader,
                sizeof(SP_REMOVEDEVICE_PARAMS)))
        {
            /* Call appropriate class installer. */
            if (SetupDiCallClassInstaller(
                    DIF_REMOVE,
                    hDevInfoList,
                    &devinfo_data))
            {
                /* Check if a system reboot is required. */
                check_reboot(hDevInfoList, &devinfo_data, pbRebootRequired);
            }
            else
            {
                msg(M_NONFATAL | M_ERRNO, "%s: SetupDiCallClassInstaller(DIF_REMOVE) failed", __FUNCTION__);
            }
        }
        else
        {
            msg(M_NONFATAL | M_ERRNO, "%s: SetupDiSetClassInstallParams failed", __FUNCTION__);
        }
    }

cleanup_hDevInfoList:
    if (libnewdev)
    {
        FreeLibrary(libnewdev);
    }
    SetupDiDestroyDeviceInfoList(hDevInfoList);
    return dwResult;
}


/**
 * Performs a given task on an adapter.
 *
 * @param hwndParent    A handle to the top-level window to use for any user adapter that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param pguidAdapter  A pointer to GUID that contains network adapter ID.
 *
 * @param funcOperation  A pointer for the function to perform specific task on the adapter.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
execute_on_first_adapter(
    _In_opt_ HWND hwndParent,
    _In_ LPCGUID pguidAdapter,
    _In_ devop_func_t funcOperation,
    _Inout_ LPBOOL pbRebootRequired)
{
    DWORD dwResult;

    if (pguidAdapter == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Create a list of network devices. */
    HDEVINFO hDevInfoList = SetupDiGetClassDevsEx(
        &GUID_DEVCLASS_NET,
        NULL,
        hwndParent,
        DIGCF_PRESENT,
        NULL,
        NULL,
        NULL);
    if (hDevInfoList == INVALID_HANDLE_VALUE)
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiGetClassDevsEx failed", __FUNCTION__);
        return dwResult;
    }

    /* Retrieve information associated with a device information set. */
    SP_DEVINFO_LIST_DETAIL_DATA devinfo_list_detail_data = { .cbSize = sizeof(SP_DEVINFO_LIST_DETAIL_DATA) };
    if (!SetupDiGetDeviceInfoListDetail(hDevInfoList, &devinfo_list_detail_data))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiGetDeviceInfoListDetail failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    /* Iterate. */
    for (DWORD dwIndex = 0;; dwIndex++)
    {
        /* Get the device from the list. */
        SP_DEVINFO_DATA devinfo_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(
                hDevInfoList,
                dwIndex,
                &devinfo_data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                LPOLESTR szAdapterId = NULL;
                StringFromIID((REFIID)pguidAdapter, &szAdapterId);
                msg(M_NONFATAL, "%s: Adapter %" PRIsLPOLESTR " not found", __FUNCTION__, szAdapterId);
                CoTaskMemFree(szAdapterId);
                dwResult = ERROR_FILE_NOT_FOUND;
                goto cleanup_hDevInfoList;
            }
            else
            {
                /* Something is wrong with this device. Skip it. */
                msg(M_WARN | M_ERRNO, "%s: SetupDiEnumDeviceInfo(%u) failed", __FUNCTION__, dwIndex);
                continue;
            }
        }

        /* Get adapter GUID. */
        GUID guidAdapter;
        dwResult = get_net_adapter_guid(hDevInfoList, &devinfo_data, 1, &guidAdapter);
        if (dwResult != ERROR_SUCCESS)
        {
            /* Something is wrong with this device. Skip it. */
            continue;
        }

        /* Compare GUIDs. */
        if (memcmp(pguidAdapter, &guidAdapter, sizeof(GUID)) == 0)
        {
            dwResult = funcOperation(hDevInfoList, &devinfo_data, pbRebootRequired);
            break;
        }
    }

cleanup_hDevInfoList:
    SetupDiDestroyDeviceInfoList(hDevInfoList);
    return dwResult;
}


DWORD
tap_delete_adapter(
    _In_opt_ HWND hwndParent,
    _In_ LPCGUID pguidAdapter,
    _Inout_ LPBOOL pbRebootRequired)
{
    return execute_on_first_adapter(hwndParent, pguidAdapter, delete_device, pbRebootRequired);
}


DWORD
tap_enable_adapter(
    _In_opt_ HWND hwndParent,
    _In_ LPCGUID pguidAdapter,
    _In_ BOOL bEnable,
    _Inout_ LPBOOL pbRebootRequired)
{
    return execute_on_first_adapter(hwndParent, pguidAdapter, bEnable ? enable_device : disable_device, pbRebootRequired);
}

/* stripped version of ExecCommand in interactive.c */
static DWORD
ExecCommand(const WCHAR* cmdline)
{
    DWORD exit_code;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD proc_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    WCHAR* cmdline_dup = NULL;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

    /* CreateProcess needs a modifiable cmdline: make a copy */
    cmdline_dup = _wcsdup(cmdline);
    if (cmdline_dup && CreateProcessW(NULL, cmdline_dup, NULL, NULL, FALSE,
        proc_flags, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        if (!GetExitCodeProcess(pi.hProcess, &exit_code))
        {
            exit_code = GetLastError();
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        exit_code = GetLastError();
    }

    free(cmdline_dup);
    return exit_code;
}

DWORD
tap_set_adapter_name(
    _In_ LPCGUID pguidAdapter,
    _In_ LPCTSTR szName,
    _In_ BOOL bSilent)
{
    DWORD dwResult;
    int msg_flag = bSilent ? M_WARN : M_NONFATAL;
    msg_flag |= M_ERRNO;

    if (pguidAdapter == NULL || szName == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Get the device class GUID as string. */
    LPOLESTR szDevClassNetId = NULL;
    StringFromIID((REFIID)&GUID_DEVCLASS_NET, &szDevClassNetId);

    /* Get the adapter GUID as string. */
    LPOLESTR szAdapterId = NULL;
    StringFromIID((REFIID)pguidAdapter, &szAdapterId);

    /* Render registry key path. */
    TCHAR szRegKey[ADAPTER_REGKEY_PATH_MAX];
    _stprintf_s(
        szRegKey, _countof(szRegKey),
        szAdapterRegKeyPathTemplate,
        szDevClassNetId,
        szAdapterId);

    /* Open network adapter registry key. */
    HKEY hKey = NULL;
    dwResult = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        szRegKey,
        0,
        KEY_QUERY_VALUE,
        &hKey);
    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult); /* MSDN does not mention RegOpenKeyEx() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(msg_flag, "%s: RegOpenKeyEx(HKLM, \"%" PRIsLPTSTR "\") failed", __FUNCTION__, szRegKey);
        goto cleanup_szAdapterId;
    }

    LPTSTR szOldName = NULL;
    dwResult = get_reg_string(hKey, TEXT("Name"), &szOldName);
    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult);
        msg(msg_flag, "%s: Error reading adapter name", __FUNCTION__);
        goto cleanup_hKey;
    }

    /* rename adapter via netsh call */
    const TCHAR* szFmt = _T("netsh interface set interface name=\"%s\" newname=\"%s\"");
    size_t ncmdline = _tcslen(szFmt) + _tcslen(szOldName) + _tcslen(szName) + 1;
    WCHAR* szCmdLine = malloc(ncmdline * sizeof(TCHAR));
    _stprintf_s(szCmdLine, ncmdline, szFmt, szOldName, szName);

    free(szOldName);

    dwResult = ExecCommand(szCmdLine);
    free(szCmdLine);

    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult);
        msg(msg_flag, "%s: Error renaming adapter", __FUNCTION__);
        goto cleanup_hKey;
    }

cleanup_hKey:
    RegCloseKey(hKey);
cleanup_szAdapterId:
    CoTaskMemFree(szAdapterId);
    CoTaskMemFree(szDevClassNetId);
    return dwResult;
}


DWORD
tap_list_adapters(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szzHwIDs,
    _Out_ struct tap_adapter_node **ppAdapter)
{
    DWORD dwResult;

    if (ppAdapter == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Create a list of network devices. */
    HDEVINFO hDevInfoList = SetupDiGetClassDevsEx(
        &GUID_DEVCLASS_NET,
        NULL,
        hwndParent,
        DIGCF_PRESENT,
        NULL,
        NULL,
        NULL);
    if (hDevInfoList == INVALID_HANDLE_VALUE)
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiGetClassDevsEx failed", __FUNCTION__);
        return dwResult;
    }

    /* Retrieve information associated with a device information set. */
    SP_DEVINFO_LIST_DETAIL_DATA devinfo_list_detail_data = { .cbSize = sizeof(SP_DEVINFO_LIST_DETAIL_DATA) };
    if (!SetupDiGetDeviceInfoListDetail(hDevInfoList, &devinfo_list_detail_data))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiGetDeviceInfoListDetail failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }

    /* Get the device class GUID as string. */
    LPOLESTR szDevClassNetId = NULL;
    StringFromIID((REFIID)&GUID_DEVCLASS_NET, &szDevClassNetId);

    /* Iterate. */
    *ppAdapter = NULL;
    struct tap_adapter_node *pAdapterTail = NULL;
    for (DWORD dwIndex = 0;; dwIndex++)
    {
        /* Get the device from the list. */
        SP_DEVINFO_DATA devinfo_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(
                hDevInfoList,
                dwIndex,
                &devinfo_data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else
            {
                /* Something is wrong with this device. Skip it. */
                msg(M_WARN | M_ERRNO, "%s: SetupDiEnumDeviceInfo(%u) failed", __FUNCTION__, dwIndex);
                continue;
            }
        }

        /* Get device hardware ID(s). */
        DWORD dwDataType = REG_NONE;
        LPTSTR szzDeviceHardwareIDs = NULL;
        dwResult = get_device_reg_property(
            hDevInfoList,
            &devinfo_data,
            SPDRP_HARDWAREID,
            &dwDataType,
            (LPVOID)&szzDeviceHardwareIDs);
        if (dwResult != ERROR_SUCCESS)
        {
            /* Something is wrong with this device. Skip it. */
            continue;
        }

        /* Check that hardware ID is REG_SZ/REG_MULTI_SZ, and optionally if it matches ours. */
        if (dwDataType == REG_SZ)
        {
            if (szzHwIDs && !_tcszistr(szzHwIDs, szzDeviceHardwareIDs))
            {
                /* This is not our device. Skip it. */
                goto cleanup_szzDeviceHardwareIDs;
            }
        }
        else if (dwDataType == REG_MULTI_SZ)
        {
            if (szzHwIDs)
            {
                for (LPTSTR s = szzDeviceHardwareIDs;; s += _tcslen(s) + 1)
                {
                    if (s[0] == 0)
                    {
                        /* This is not our device. Skip it. */
                        goto cleanup_szzDeviceHardwareIDs;
                    }
                    else if (_tcszistr(szzHwIDs, s))
                    {
                        /* This is our device. */
                        break;
                    }
                }
            }
        }
        else
        {
            /* Unexpected hardware ID format. Skip device. */
            goto cleanup_szzDeviceHardwareIDs;
        }

        /* Get adapter GUID. */
        GUID guidAdapter;
        dwResult = get_net_adapter_guid(hDevInfoList, &devinfo_data, 1, &guidAdapter);
        if (dwResult != ERROR_SUCCESS)
        {
            /* Something is wrong with this device. Skip it. */
            goto cleanup_szzDeviceHardwareIDs;
        }

        /* Get the adapter GUID as string. */
        LPOLESTR szAdapterId = NULL;
        StringFromIID((REFIID)&guidAdapter, &szAdapterId);

        /* Render registry key path. */
        TCHAR szRegKey[ADAPTER_REGKEY_PATH_MAX];
        _stprintf_s(
            szRegKey, _countof(szRegKey),
            szAdapterRegKeyPathTemplate,
            szDevClassNetId,
            szAdapterId);

        /* Open network adapter registry key. */
        HKEY hKey = NULL;
        dwResult = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            szRegKey,
            0,
            KEY_READ,
            &hKey);
        if (dwResult != ERROR_SUCCESS)
        {
            SetLastError(dwResult); /* MSDN does not mention RegOpenKeyEx() to set GetLastError(). But we do have an error code. Set last error manually. */
            msg(M_WARN | M_ERRNO, "%s: RegOpenKeyEx(HKLM, \"%" PRIsLPTSTR "\") failed", __FUNCTION__, szRegKey);
            goto cleanup_szAdapterId;
        }

        /* Read adapter name. */
        LPTSTR szName = NULL;
        dwResult = get_reg_string(
            hKey,
            TEXT("Name"),
            &szName);
        if (dwResult != ERROR_SUCCESS)
        {
            SetLastError(dwResult);
            msg(M_WARN | M_ERRNO, "%s: Cannot determine %" PRIsLPOLESTR " adapter name", __FUNCTION__, szAdapterId);
            goto cleanup_hKey;
        }

        /* Append to the list. */
        size_t hwid_size = (_tcszlen(szzDeviceHardwareIDs) + 1) * sizeof(TCHAR);
        size_t name_size = (_tcslen(szName) + 1) * sizeof(TCHAR);
        struct tap_adapter_node *node = (struct tap_adapter_node *)malloc(sizeof(struct tap_adapter_node) + hwid_size + name_size);
        if (node == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct tap_adapter_node) + hwid_size + name_size);
            dwResult = ERROR_OUTOFMEMORY; goto cleanup_szName;
        }

        memcpy(&node->guid, &guidAdapter, sizeof(GUID));
        node->szzHardwareIDs = (LPTSTR)(node + 1);
        memcpy(node->szzHardwareIDs, szzDeviceHardwareIDs, hwid_size);
        node->szName = (LPTSTR)((LPBYTE)node->szzHardwareIDs + hwid_size);
        memcpy(node->szName, szName, name_size);
        node->pNext = NULL;
        if (pAdapterTail)
        {
            pAdapterTail->pNext = node;
            pAdapterTail = node;
        }
        else
        {
            *ppAdapter = pAdapterTail = node;
        }

cleanup_szName:
        free(szName);
cleanup_hKey:
        RegCloseKey(hKey);
cleanup_szAdapterId:
        CoTaskMemFree(szAdapterId);
cleanup_szzDeviceHardwareIDs:
        free(szzDeviceHardwareIDs);
    }

    dwResult = ERROR_SUCCESS;

    CoTaskMemFree(szDevClassNetId);
cleanup_hDevInfoList:
    SetupDiDestroyDeviceInfoList(hDevInfoList);
    return dwResult;
}


void
tap_free_adapter_list(
    _In_ struct tap_adapter_node *pAdapterList)
{
    /* Iterate over all nodes of the list. */
    while (pAdapterList)
    {
        struct tap_adapter_node *node = pAdapterList;
        pAdapterList = pAdapterList->pNext;

        /* Free the adapter node. */
        free(node);
    }
}
