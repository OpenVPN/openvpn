/*
 *  tapctl -- Utility to manipulate TUN/TAP interfaces on Windows
 *            https://community.openvpn.net/openvpn/wiki/Tapctl
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

#include "tap.h"
#include "error.h"

#include <windows.h>
#include <cfgmgr32.h>
#include <objbase.h>
#include <setupapi.h>
#include <tchar.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "setupapi.lib")
#endif

const static GUID GUID_DEVCLASS_NET = { 0x4d36e972L, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

const static TCHAR szzDefaultHardwareIDs[] = TEXT("root\\") TEXT(TAP_WIN_COMPONENT_ID) TEXT("\0");

const static TCHAR szInterfaceRegKeyPathTemplate[] = TEXT("SYSTEM\\CurrentControlSet\\Control\\Network\\%") TEXT(PRIsLPOLESTR) TEXT("\\%") TEXT(PRIsLPOLESTR) TEXT("\\Connection");
#define INTERFACE_REGKEY_PATH_MAX (_countof(TEXT("SYSTEM\\CurrentControlSet\\Control\\Network\\")) - 1 + 38 + _countof(TEXT("\\")) - 1 + 38 + _countof(TEXT("\\Connection")))


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
 *                      interface manipulations.
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
 * Returns network interface ID.
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
 * @param pguidInterface  A pointer to GUID that receives network interface ID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
static DWORD
get_net_interface_guid(
    _In_ HDEVINFO hDeviceInfoSet,
    _In_ PSP_DEVINFO_DATA pDeviceInfoData,
    _In_ int iNumAttempts,
    _Out_ LPGUID pguidInterface)
{
    DWORD dwResult = ERROR_BAD_ARGUMENTS;

    if (pguidInterface == NULL || iNumAttempts < 1)
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

        dwResult = SUCCEEDED(CLSIDFromString(szCfgGuidString, (LPCLSID)pguidInterface)) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
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


/**
 * Returns length of list of strings
 *
 * @param str              Pointer to a list of strings terminated by an empty string.
 *
 * @return Number of characters not counting the final zero terminator
 **/
static inline size_t
_tcszlen(_In_ LPCTSTR str)
{
    LPCTSTR s;
    for (s = str; s[0]; s += _tcslen(s) + 1)
    {
    }
    return s - str;
}


DWORD
tap_create_interface(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szDeviceDescription,
    _In_opt_ LPCTSTR szHwId,
    _Inout_ LPBOOL pbRebootRequired,
    _Out_ LPGUID pguidInterface)
{
    DWORD dwResult;

    if (pbRebootRequired == NULL
        || pguidInterface == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    if (szHwId == NULL)
    {
        szHwId = szzDefaultHardwareIDs;
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

    /* Search for the driver. */
    if (!SetupDiBuildDriverInfoList(
            hDevInfoList,
            &devinfo_data,
            SPDIT_CLASSDRIVER))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiBuildDriverInfoList failed", __FUNCTION__);
        goto cleanup_hDevInfoList;
    }
    DWORDLONG dwlDriverVersion = 0;
    DWORD drvinfo_detail_data_size = sizeof(SP_DRVINFO_DETAIL_DATA) + 0x100;
    SP_DRVINFO_DETAIL_DATA *drvinfo_detail_data = (SP_DRVINFO_DETAIL_DATA *)malloc(drvinfo_detail_data_size);
    if (drvinfo_detail_data == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, drvinfo_detail_data_size);
        dwResult = ERROR_OUTOFMEMORY; goto cleanup_DriverInfoList;
    }

    for (DWORD dwIndex = 0;; dwIndex++)
    {
        /* Get a driver from the list. */
        SP_DRVINFO_DATA drvinfo_data = { .cbSize = sizeof(SP_DRVINFO_DATA) };
        if (!SetupDiEnumDriverInfo(
                hDevInfoList,
                &devinfo_data,
                SPDIT_CLASSDRIVER,
                dwIndex,
                &drvinfo_data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else
            {
                /* Something is wrong with this driver. Skip it. */
                msg(M_WARN | M_ERRNO, "%s: SetupDiEnumDriverInfo(%u) failed", __FUNCTION__, dwIndex);
                continue;
            }
        }

        /* Get driver info details. */
        DWORD dwSize;
        drvinfo_detail_data->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA);
        if (!SetupDiGetDriverInfoDetail(
                hDevInfoList,
                &devinfo_data,
                &drvinfo_data,
                drvinfo_detail_data,
                drvinfo_detail_data_size,
                &dwSize))
        {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                /* (Re)allocate buffer. */
                if (drvinfo_detail_data)
                {
                    free(drvinfo_detail_data);
                }

                drvinfo_detail_data_size = dwSize;
                drvinfo_detail_data = (SP_DRVINFO_DETAIL_DATA *)malloc(drvinfo_detail_data_size);
                if (drvinfo_detail_data == NULL)
                {
                    msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, drvinfo_detail_data_size);
                    dwResult = ERROR_OUTOFMEMORY; goto cleanup_DriverInfoList;
                }

                /* Re-get driver info details. */
                drvinfo_detail_data->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA);
                if (!SetupDiGetDriverInfoDetail(
                        hDevInfoList,
                        &devinfo_data,
                        &drvinfo_data,
                        drvinfo_detail_data,
                        drvinfo_detail_data_size,
                        &dwSize))
                {
                    /* Something is wrong with this driver. Skip it. */
                    continue;
                }
            }
            else
            {
                /* Something is wrong with this driver. Skip it. */
                msg(M_WARN | M_ERRNO, "%s: SetupDiGetDriverInfoDetail(\"%hs\") failed", __FUNCTION__, drvinfo_data.Description);
                continue;
            }
        }

        /* Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for any driver versioned prior our best match. */
        if (dwlDriverVersion < drvinfo_data.DriverVersion)
        {
            /* Search the list of hardware IDs. */
            for (LPTSTR szHwdID = drvinfo_detail_data->HardwareID; szHwdID && szHwdID[0]; szHwdID += _tcslen(szHwdID) + 1)
            {
                if (_tcsicmp(szHwdID, szHwId) == 0)
                {
                    /* Matching hardware ID found. Select the driver. */
                    if (!SetupDiSetSelectedDriver(
                            hDevInfoList,
                            &devinfo_data,
                            &drvinfo_data))
                    {
                        /* Something is wrong with this driver. Skip it. */
                        msg(M_WARN | M_ERRNO, "%s: SetupDiSetSelectedDriver(\"%hs\") failed", __FUNCTION__, drvinfo_data.Description);
                        break;
                    }

                    dwlDriverVersion = drvinfo_data.DriverVersion;
                    break;
                }
            }
        }
    }
    if (drvinfo_detail_data)
    {
        free(drvinfo_detail_data);
    }

    if (dwlDriverVersion == 0)
    {
        dwResult = ERROR_NOT_FOUND;
        msg(M_NONFATAL, "%s: No driver for device \"%" PRIsLPTSTR "\" installed.", __FUNCTION__, szHwId);
        goto cleanup_DriverInfoList;
    }

    /* Call appropriate class installer. */
    if (!SetupDiCallClassInstaller(
            DIF_REGISTERDEVICE,
            hDevInfoList,
            &devinfo_data))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL, "%s: SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed", __FUNCTION__);
        goto cleanup_DriverInfoList;
    }

    /* Register device co-installers if any. */
    if (!SetupDiCallClassInstaller(
            DIF_REGISTER_COINSTALLERS,
            hDevInfoList,
            &devinfo_data))
    {
        dwResult = GetLastError();
        msg(M_WARN | M_ERRNO, "%s: SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS) failed", __FUNCTION__);
    }

    /* Install interfaces if any. */
    if (!SetupDiCallClassInstaller(
            DIF_INSTALLINTERFACES,
            hDevInfoList,
            &devinfo_data))
    {
        dwResult = GetLastError();
        msg(M_WARN | M_ERRNO, "%s: SetupDiCallClassInstaller(DIF_INSTALLINTERFACES) failed", __FUNCTION__);
    }

    /* Install the device. */
    if (!SetupDiCallClassInstaller(
            DIF_INSTALLDEVICE,
            hDevInfoList,
            &devinfo_data))
    {
        dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: SetupDiCallClassInstaller(DIF_INSTALLDEVICE) failed", __FUNCTION__);
        goto cleanup_remove_device;
    }

    /* Check if a system reboot is required. (Ignore errors) */
    check_reboot(hDevInfoList, &devinfo_data, pbRebootRequired);

    /* Get network interface ID from registry. Retry for max 30sec. */
    dwResult = get_net_interface_guid(hDevInfoList, &devinfo_data, 30, pguidInterface);

cleanup_remove_device:
    if (dwResult != ERROR_SUCCESS)
    {
        /* The interface was installed. But, the interface ID was unobtainable. Clean-up. */
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

cleanup_DriverInfoList:
    SetupDiDestroyDriverInfoList(
        hDevInfoList,
        &devinfo_data,
        SPDIT_CLASSDRIVER);

cleanup_hDevInfoList:
    SetupDiDestroyDeviceInfoList(hDevInfoList);
    return dwResult;
}


DWORD
tap_delete_interface(
    _In_opt_ HWND hwndParent,
    _In_ LPCGUID pguidInterface,
    _Inout_ LPBOOL pbRebootRequired)
{
    DWORD dwResult;

    if (pguidInterface == NULL)
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
                LPOLESTR szInterfaceId = NULL;
                StringFromIID((REFIID)pguidInterface, &szInterfaceId);
                msg(M_NONFATAL, "%s: Interface %" PRIsLPOLESTR " not found", __FUNCTION__, szInterfaceId);
                CoTaskMemFree(szInterfaceId);
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

        /* Get interface GUID. */
        GUID guidInterface;
        dwResult = get_net_interface_guid(hDevInfoList, &devinfo_data, 1, &guidInterface);
        if (dwResult != ERROR_SUCCESS)
        {
            /* Something is wrong with this device. Skip it. */
            continue;
        }

        /* Compare GUIDs. */
        if (memcmp(pguidInterface, &guidInterface, sizeof(GUID)) == 0)
        {
            /* Remove the device. */
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
            if (!SetupDiSetClassInstallParams(
                    hDevInfoList,
                    &devinfo_data,
                    &removedevice_params.ClassInstallHeader,
                    sizeof(SP_REMOVEDEVICE_PARAMS)))
            {
                dwResult = GetLastError();
                msg(M_NONFATAL, "%s: SetupDiSetClassInstallParams failed", __FUNCTION__);
                goto cleanup_hDevInfoList;
            }

            /* Call appropriate class installer. */
            if (!SetupDiCallClassInstaller(
                    DIF_REMOVE,
                    hDevInfoList,
                    &devinfo_data))
            {
                dwResult = GetLastError();
                msg(M_NONFATAL, "%s: SetupDiCallClassInstaller(DIF_REMOVE) failed", __FUNCTION__);
                goto cleanup_hDevInfoList;
            }

            /* Check if a system reboot is required. */
            check_reboot(hDevInfoList, &devinfo_data, pbRebootRequired);
            dwResult = ERROR_SUCCESS;
            break;
        }
    }

cleanup_hDevInfoList:
    SetupDiDestroyDeviceInfoList(hDevInfoList);
    return dwResult;
}


DWORD
tap_set_interface_name(
    _In_ LPCGUID pguidInterface,
    _In_ LPCTSTR szName)
{
    DWORD dwResult;

    if (pguidInterface == NULL || szName == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Get the device class GUID as string. */
    LPOLESTR szDevClassNetId = NULL;
    StringFromIID((REFIID)&GUID_DEVCLASS_NET, &szDevClassNetId);

    /* Get the interface GUID as string. */
    LPOLESTR szInterfaceId = NULL;
    StringFromIID((REFIID)pguidInterface, &szInterfaceId);

    /* Render registry key path. */
    TCHAR szRegKey[INTERFACE_REGKEY_PATH_MAX];
    _stprintf_s(
        szRegKey, _countof(szRegKey),
        szInterfaceRegKeyPathTemplate,
        szDevClassNetId,
        szInterfaceId);

    /* Open network interface registry key. */
    HKEY hKey = NULL;
    dwResult = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        szRegKey,
        0,
        KEY_SET_VALUE,
        &hKey);
    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult); /* MSDN does not mention RegOpenKeyEx() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: RegOpenKeyEx(HKLM, \"%" PRIsLPTSTR "\") failed", __FUNCTION__, szRegKey);
        goto cleanup_szInterfaceId;
    }

    /* Set the interface name. */
    size_t sizeName = ((_tcslen(szName) + 1) * sizeof(TCHAR));
#ifdef _WIN64
    if (sizeName > DWORD_MAX)
    {
        dwResult = ERROR_BAD_ARGUMENTS;
        msg(M_NONFATAL, "%s: string too big (size %u).", __FUNCTION__, sizeName);
        goto cleanup_hKey;
    }
#endif
    dwResult = RegSetKeyValue(
        hKey,
        NULL,
        TEXT("Name"),
        REG_SZ,
        szName,
        (DWORD)sizeName);
    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult); /* MSDN does not mention RegSetKeyValue() to set GetLastError(). But we do have an error code. Set last error manually. */
        msg(M_NONFATAL | M_ERRNO, "%s: RegSetKeyValue(\"Name\") failed", __FUNCTION__);
        goto cleanup_hKey;
    }

cleanup_hKey:
    RegCloseKey(hKey);
cleanup_szInterfaceId:
    CoTaskMemFree(szInterfaceId);
    CoTaskMemFree(szDevClassNetId);
    return dwResult;
}


DWORD
tap_list_interfaces(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szHwId,
    _Out_ struct tap_interface_node **ppInterface,
    _In_ BOOL bAll)
{
    DWORD dwResult;

    if (ppInterface == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    if (szHwId == NULL)
    {
        szHwId = szzDefaultHardwareIDs;
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
    *ppInterface = NULL;
    struct tap_interface_node *pInterfaceTail = NULL;
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
            if (!bAll && _tcsicmp(szzDeviceHardwareIDs, szHwId) != 0)
            {
                /* This is not our device. Skip it. */
                goto cleanup_szzDeviceHardwareIDs;
            }
        }
        else if (dwDataType == REG_MULTI_SZ)
        {
            if (!bAll)
            {
                for (LPTSTR szHwdID = szzDeviceHardwareIDs;; szHwdID += _tcslen(szHwdID) + 1)
                {
                    if (szHwdID[0] == 0)
                    {
                        /* This is not our device. Skip it. */
                        goto cleanup_szzDeviceHardwareIDs;
                    }
                    else if (_tcsicmp(szHwdID, szHwId) == 0)
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

        /* Get interface GUID. */
        GUID guidInterface;
        dwResult = get_net_interface_guid(hDevInfoList, &devinfo_data, 1, &guidInterface);
        if (dwResult != ERROR_SUCCESS)
        {
            /* Something is wrong with this device. Skip it. */
            goto cleanup_szzDeviceHardwareIDs;
        }

        /* Get the interface GUID as string. */
        LPOLESTR szInterfaceId = NULL;
        StringFromIID((REFIID)&guidInterface, &szInterfaceId);

        /* Render registry key path. */
        TCHAR szRegKey[INTERFACE_REGKEY_PATH_MAX];
        _stprintf_s(
            szRegKey, _countof(szRegKey),
            szInterfaceRegKeyPathTemplate,
            szDevClassNetId,
            szInterfaceId);

        /* Open network interface registry key. */
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
            goto cleanup_szInterfaceId;
        }

        /* Read interface name. */
        LPTSTR szName = NULL;
        dwResult = get_reg_string(
            hKey,
            TEXT("Name"),
            &szName);
        if (dwResult != ERROR_SUCCESS)
        {
            SetLastError(dwResult);
            msg(M_WARN | M_ERRNO, "%s: Cannot determine %" PRIsLPOLESTR " interface name", __FUNCTION__, szInterfaceId);
            goto cleanup_hKey;
        }

        /* Append to the list. */
        size_t hwid_size = (_tcszlen(szzDeviceHardwareIDs) + 1) * sizeof(TCHAR);
        size_t name_size = (_tcslen(szName) + 1) * sizeof(TCHAR);
        struct tap_interface_node *node = (struct tap_interface_node *)malloc(sizeof(struct tap_interface_node) + hwid_size + name_size);
        if (node == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct tap_interface_node) + hwid_size + name_size);
            dwResult = ERROR_OUTOFMEMORY; goto cleanup_szName;
        }

        memcpy(&node->guid, &guidInterface, sizeof(GUID));
        node->szzHardwareIDs = (LPTSTR)(node + 1);
        memcpy(node->szzHardwareIDs, szzDeviceHardwareIDs, hwid_size);
        node->szName = (LPTSTR)((LPBYTE)node->szzHardwareIDs + hwid_size);
        memcpy(node->szName, szName, name_size);
        node->pNext = NULL;
        if (pInterfaceTail)
        {
            pInterfaceTail->pNext = node;
            pInterfaceTail = node;
        }
        else
        {
            *ppInterface = pInterfaceTail = node;
        }

cleanup_szName:
        free(szName);
cleanup_hKey:
        RegCloseKey(hKey);
cleanup_szInterfaceId:
        CoTaskMemFree(szInterfaceId);
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
tap_free_interface_list(
    _In_ struct tap_interface_node *pInterfaceList)
{
    /* Iterate over all nodes of the list. */
    while (pInterfaceList)
    {
        struct tap_interface_node *node = pInterfaceList;
        pInterfaceList = pInterfaceList->pNext;

        /* Free the interface node. */
        free(node);
    }
}
