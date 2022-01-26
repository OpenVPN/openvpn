/*
 *  openvpnmsica -- Custom Action DLL to provide OpenVPN-specific support to MSI packages
 *                  https://community.openvpn.net/openvpn/wiki/OpenVPNMSICA
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

#ifndef MSICA_H
#define MSICA_H

#include <windows.h>
#include <msi.h>
#include "../tapctl/basic.h"


/*
 * Error codes (next unused 2552L)
 */
#define ERROR_MSICA       2550L
#define ERROR_MSICA_ERRNO 2551L


/**
 * Thread local storage data
 */
struct openvpnmsica_thread_data
{
    MSIHANDLE hInstall; /** Handle to the installation session. */
};


/**
 * MSI session handle thread local storage index
 */
extern DWORD openvpnmsica_thread_data_idx;


/**
 * Set MSI session handle in thread local storage.
 */
#define OPENVPNMSICA_SAVE_MSI_SESSION(hInstall) \
{ \
    struct openvpnmsica_thread_data *s = (struct openvpnmsica_thread_data *)TlsGetValue(openvpnmsica_thread_data_idx); \
    s->hInstall = (hInstall); \
}


/*
 * Exported DLL Functions
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#define DLLEXP_DECL __declspec(dllexport)
#else
#define DLLEXP_DECL
#define DLLEXP_EXPORT "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__
#endif


/**
 * Determines Windows information:
 *
 * - Sets `OPENVPNSERVICE` MSI property to PID of OpenVPN Service if running, or its EXE path if
 *   configured for auto-start.
 *
 * - Finds existing TAP-Windows6 adapters and set TAPWINDOWS6ADAPTERS and
 *   ACTIVETAPWINDOWS6ADAPTERS properties with semicolon delimited list of all installed adapter
 *   GUIDs and active adapter GUIDs respectively.
 *
 * - Finds existing Wintun adapters and set WINTUNADAPTERS and ACTIVEWINTUNADAPTERS properties
 *   with semicolon delimited list of all installed adapter GUIDs and active adapter GUIDs
 *   respectively.
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 *         See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072.aspx
 */
DLLEXP_DECL UINT __stdcall
FindSystemInfo(_In_ MSIHANDLE hInstall);


/**
 * Find OpenVPN GUI window and send it a WM_CLOSE message.
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 *         See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072.aspx
 */
DLLEXP_DECL UINT __stdcall
CloseOpenVPNGUI(_In_ MSIHANDLE hInstall);


/**
 * Launches OpenVPN GUI. It's path is obtained by expanding the `[#bin.openvpn_gui.exe]`
 * therefore, its Id field in File table must be "bin.openvpn_gui.exe".
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 *         See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072.aspx
 */
DLLEXP_DECL UINT __stdcall
StartOpenVPNGUI(_In_ MSIHANDLE hInstall);


/**
 * Evaluate the TUNTAPAdapter table of the MSI package database and prepare a list of TAP
 * adapters to install/remove.
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 *         See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072.aspx
 */
DLLEXP_DECL UINT __stdcall
EvaluateTUNTAPAdapters(_In_ MSIHANDLE hInstall);


/**
 * Perform scheduled deferred action.
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 *         See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072.aspx
 */
DLLEXP_DECL UINT __stdcall
ProcessDeferredAction(_In_ MSIHANDLE hInstall);


/**
 * Schedule reboot after installation if reboot
 * indication file is found in user's temp directory
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 *         See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa368072.aspx
 */
DLLEXP_DECL UINT __stdcall
CheckAndScheduleReboot(_In_ MSIHANDLE hInstall);

#ifdef __cplusplus
}
#endif

#endif /* ifndef MSICA_H */
