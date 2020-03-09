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

#ifndef TAP_H
#define TAP_H

#include <windows.h>
#include "basic.h"


/**
 * Creates a TUN/TAP interface.
 *
 * @param hwndParent    A handle to the top-level window to use for any user interface that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param szDeviceDescription  A pointer to a NULL-terminated string that supplies the text
 *                      description of the device. This pointer is optional and can be NULL.
 *
 * @param szHwId        A pointer to a NULL-terminated string that supplies the hardware id
 *                      of the device. This pointer is optional and can be NULL. Default value
 *                      is root\tap0901.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      interface manipulations.
 *
 * @param pguidInterface  A pointer to GUID that receives network interface ID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
DWORD
tap_create_interface(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szDeviceDescription,
    _In_opt_ LPCTSTR szHwId,
    _Inout_ LPBOOL pbRebootRequired,
    _Out_ LPGUID pguidInterface);


/**
 * Deletes an interface.
 *
 * @param hwndParent    A handle to the top-level window to use for any user interface that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param pguidInterface  A pointer to GUID that contains network interface ID.
 *
 * @param pbRebootRequired  A pointer to a BOOL flag. If the device requires a system restart,
 *                      this flag is set to TRUE. Otherwise, the flag is left unmodified. This
 *                      allows the flag to be globally initialized to FALSE and reused for multiple
 *                      interface manipulations.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
DWORD
tap_delete_interface(
    _In_opt_ HWND hwndParent,
    _In_ LPCGUID pguidInterface,
    _Inout_ LPBOOL pbRebootRequired);


/**
 * Sets interface name.
 *
 * @param pguidInterface  A pointer to GUID that contains network interface ID.
 *
 * @param szName        New interface name - must be unique
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 **/
DWORD
tap_set_interface_name(
    _In_ LPCGUID pguidInterface,
    _In_ LPCTSTR szName);


/**
 * Network interface list node
 */
struct tap_interface_node
{
    GUID guid;             /** Interface GUID */
    LPTSTR szzHardwareIDs; /** Device hardware ID(s) */
    LPTSTR szName;         /** Interface name */

    struct tap_interface_node *pNext; /** Pointer to next interface */
};


/**
 * Creates a list of available network interfaces.
 *
 * @param hwndParent    A handle to the top-level window to use for any user interface that is
 *                      related to non-device-specific actions (such as a select-device dialog
 *                      box that uses the global class driver list). This handle is optional
 *                      and can be NULL. If a specific top-level window is not required, set
 *                      hwndParent to NULL.
 *
 * @param szHwId        A pointer to a NULL-terminated string that supplies the hardware id
 *                      of the device. This pointer is optional and can be NULL. Default value
 *                      is root\tap0901.
 *
 * @param ppInterfaceList  A pointer to the list to receive pointer to the first interface in
 *                      the list. After the list is no longer required, free it using
 *                      tap_free_interface_list().
 *
 * @param bAll          When TRUE, all network interfaces found are added to the list. When
 *                      FALSE, only TUN/TAP interfaces found are added.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
DWORD
tap_list_interfaces(
    _In_opt_ HWND hwndParent,
    _In_opt_ LPCTSTR szHwId,
    _Out_ struct tap_interface_node **ppInterfaceList,
    _In_ BOOL bAll);


/**
 * Frees a list of network interfaces.
 *
 * @param pInterfaceList  A pointer to the first interface in the list to free.
 */
void
tap_free_interface_list(
    _In_ struct tap_interface_node *pInterfaceList);

#endif /* ifndef TAP_H */
