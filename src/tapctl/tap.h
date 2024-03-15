/*
 *  tapctl -- Utility to manipulate TUN/TAP adapters on Windows
 *            https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2018-2024 Simon Rozman <simon@rozman.si>
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

#ifndef TAP_H
#define TAP_H

#include <windows.h>
#include "basic.h"


/**
 * Creates a TUN/TAP adapter.
 *
 * @param hwndParent    A handle to the top-level window to use for any user adapter that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param szDeviceDescription  A pointer to a NULL-terminated string that supplies the text
 *                      description of the device. This pointer is optional and can be NULL.
 *
 * @param szHwId        A pointer to a NULL-terminated string that supplies the hardware id
 *                      of the device (e.g. "root\\tap0901", "Wintun").
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @param pguidAdapter  A pointer to GUID that receives network adapter ID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
DWORD
tap_create_adapter(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szDeviceDescription,
    _In_ LPCTSTR szHwId,
    _Inout_ LPBOOL pbRebootRequired,
    _Out_ LPGUID pguidAdapter);


/**
 * Deletes an adapter.
 *
 * @param hwndParent    A handle to the top-level window to use for any user adapter that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param pguidAdapter  A pointer to GUID that contains network adapter ID.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
DWORD
tap_delete_adapter(
    _In_opt_ HWND hwndParent,
    _In_ LPCGUID pguidAdapter,
    _Inout_ LPBOOL pbRebootRequired);


/**
 * Enables or disables an adapter.
 *
 * @param hwndParent    A handle to the top-level window to use for any user adapter that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param pguidAdapter  A pointer to GUID that contains network adapter ID.
 *
 * @param bEnable       TRUE to enable; FALSE to disable
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      adapter manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
DWORD
tap_enable_adapter(
    _In_opt_ HWND hwndParent,
    _In_ LPCGUID pguidAdapter,
    _In_ BOOL bEnable,
    _Inout_ LPBOOL pbRebootRequired);


/**
 * Sets adapter name.
 *
 * @param pguidAdapter  A pointer to GUID that contains network adapter ID.
 *
 * @param szName        New adapter name - must be unique
 *
 * @param bSilent       If true, MSI installer won't display message box and
 *                      only print error to log.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
DWORD
tap_set_adapter_name(
    _In_ LPCGUID pguidAdapter,
    _In_ LPCTSTR szName,
    _In_ BOOL bSilent);


/**
 * Network adapter list node
 */
struct tap_adapter_node
{
    GUID guid;             /** Adapter GUID */
    LPTSTR szzHardwareIDs; /** Device hardware ID(s) */
    LPTSTR szName;         /** Adapter name */

    struct tap_adapter_node *pNext; /** Pointer to next adapter */
};


/**
 * Creates a list of existing network adapters.
 *
 * @param hwndParent    A handle to the top-level window to use for any user adapter that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param szzHwIDs      A string of strings that supplies the list of hardware IDs of the device.
 *                      This pointer is optional and can be NULL. When NULL, all network adapters
 *                      found are added to the list.
 *
 * @param ppAdapterList  A pointer to the list to receive pointer to the first adapter in
 *                      the list. After the list is no longer required, free it using
 *                      tap_free_adapter_list().
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
DWORD
tap_list_adapters(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szzHwIDs,
    _Out_ struct tap_adapter_node **ppAdapterList);


/**
 * Frees a list of network adapters.
 *
 * @param pAdapterList  A pointer to the first adapter in the list to free.
 */
void
tap_free_adapter_list(
    _In_ struct tap_adapter_node *pAdapterList);

#endif /* ifndef TAP_H */
