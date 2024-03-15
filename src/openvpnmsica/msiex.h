/*
 *  openvpnmsica -- Custom Action DLL to provide OpenVPN-specific support to MSI packages
 *                  https://community.openvpn.net/openvpn/wiki/OpenVPNMSICA
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

#ifndef MSIHLP_H
#define MSIHLP_H

#include <windows.h>
#include <msi.h>
#include "../tapctl/basic.h"


/**
 * Gets MSI property value
 *
 * @param hInstall      Handle to the installation provided to the DLL custom action
 *
 * @param szName        Property name
 *
 * @param pszValue      Pointer to string to retrieve property value. The string must
 *                      be released with free() after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
UINT
msi_get_string(
    _In_ MSIHANDLE hInstall,
    _In_z_ LPCTSTR szName,
    _Out_ LPTSTR *pszValue);


/**
 * Gets MSI record string value
 *
 * @param hRecord       Handle to the record
 *
 * @param iField        Field index
 *
 * @param pszValue      Pointer to string to retrieve field value. The string must be
 *                      released with free() after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
UINT
msi_get_record_string(
    _In_ MSIHANDLE hRecord,
    _In_ unsigned int iField,
    _Out_ LPTSTR *pszValue);


/**
 * Formats MSI record
 *
 * @param hInstall      Handle to the installation. This may be omitted, in which case only the
 *                      record field parameters are processed and properties are not available
 *                      for substitution.
 *
 * @param hRecord       Handle to the record to format. The template string must be stored in
 *                      record field 0 followed by referenced data parameters.
 *
 * @param pszValue      Pointer to string to retrieve formatted value. The string must be
 *                      released with free() after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
UINT
msi_format_record(
    _In_ MSIHANDLE hInstall,
    _In_ MSIHANDLE hRecord,
    _Out_ LPTSTR *pszValue);


/**
 * Formats MSI record field
 *
 * @param hInstall      Handle to the installation. This may be omitted, in which case only the
 *                      record field parameters are processed and properties are not available
 *                      for substitution.
 *
 * @param hRecord       Handle to the field record
 *
 * @param iField        Field index
 *
 * @param pszValue      Pointer to string to retrieve formatted value. The string must be
 *                      released with free() after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
UINT
msi_format_field(
    _In_ MSIHANDLE hInstall,
    _In_ MSIHANDLE hRecord,
    _In_ unsigned int iField,
    _Out_ LPTSTR *pszValue);

#endif /* ifndef MSIHLP_H */
