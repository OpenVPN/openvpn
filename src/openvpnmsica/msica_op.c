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

#include "msica_op.h"
#include "../tapctl/error.h"
#include "../tapctl/tap.h"

#include <windows.h>
#include <malloc.h>
#include <msiquery.h>
#include <objbase.h>

#ifdef _MSC_VER
#pragma comment(lib, "msi.lib")
#pragma comment(lib, "ole32.lib")
#endif


/**
 * Operation data persist header
 */
struct msica_op_hdr
{
    enum msica_op_type type;  /** Action type */
    int ticks;                /** Number of ticks on the progress indicator this operation represents */
    DWORD size_data;          /** Size of the operation data (DWORD to better align with Win32 API) */
};


void
msica_op_seq_init(_Inout_ struct msica_op_seq *seq)
{
    seq->head = NULL;
    seq->tail = NULL;
}


void
msica_op_seq_free(_Inout_ struct msica_op_seq *seq)
{
    while (seq->head)
    {
        struct msica_op *op = seq->head;
        seq->head = seq->head->next;
        free(op);
    }
    seq->tail = NULL;
}


struct msica_op *
msica_op_create_bool(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ bool value)
{
    if (MSICA_OP_TYPE_DATA(type) != 0x1)
    {
        msg(M_NONFATAL, "%s: Operation data type not bool (%x)", __FUNCTION__, MSICA_OP_TYPE_DATA(type));
        return NULL;
    }

    /* Create and fill operation struct. */
    struct msica_op_bool *op = (struct msica_op_bool *)malloc(sizeof(struct msica_op_bool));
    if (op == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_op_bool));
        return NULL;
    }

    op->base.type  = type;
    op->base.ticks = ticks;
    op->base.next  = next;
    op->value      = value;

    return &op->base;
}


struct msica_op *
msica_op_create_string(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_z_ LPCTSTR value)
{
    if (MSICA_OP_TYPE_DATA(type) != 0x2)
    {
        msg(M_NONFATAL, "%s: Operation data type not string (%x)", __FUNCTION__, MSICA_OP_TYPE_DATA(type));
        return NULL;
    }

    /* Create and fill operation struct. */
    size_t value_size = (_tcslen(value) + 1) * sizeof(TCHAR);
    struct msica_op_string *op = (struct msica_op_string *)malloc(sizeof(struct msica_op_string) + value_size);
    if (op == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_op_string) + value_size);
        return NULL;
    }

    op->base.type  = type;
    op->base.ticks = ticks;
    op->base.next  = next;
    memcpy(op->value, value, value_size);

    return &op->base;
}


struct msica_op *
msica_op_create_multistring_va(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ va_list arglist)
{
    if (MSICA_OP_TYPE_DATA(type) != 0x3)
    {
        msg(M_NONFATAL, "%s: Operation data type not multi-string (%x)", __FUNCTION__, MSICA_OP_TYPE_DATA(type));
        return NULL;
    }

    /* Calculate required space first. */
    LPCTSTR str;
    size_t value_size = 1;
    for (va_list a = arglist; (str = va_arg(a, LPCTSTR)) != NULL; value_size += _tcslen(str) + 1)
    {
    }
    value_size *= sizeof(TCHAR);

    /* Create and fill operation struct. */
    struct msica_op_multistring *op = (struct msica_op_multistring *)malloc(sizeof(struct msica_op_multistring) + value_size);
    if (op == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_op_multistring) + value_size);
        return NULL;
    }

    op->base.type  = type;
    op->base.ticks = ticks;
    op->base.next  = next;
    LPTSTR value = op->value;
    for (va_list a = arglist; (str = va_arg(a, LPCTSTR)) != NULL;)
    {
        size_t size = _tcslen(str) + 1;
        memcpy(value, str, size*sizeof(TCHAR));
        value += size;
    }
    value[0] = 0;

    return &op->base;
}


struct msica_op *
msica_op_create_guid(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ const GUID *value)
{
    if (MSICA_OP_TYPE_DATA(type) != 0x4)
    {
        msg(M_NONFATAL, "%s: Operation data type not GUID (%x)", __FUNCTION__, MSICA_OP_TYPE_DATA(type));
        return NULL;
    }

    /* Create and fill operation struct. */
    struct msica_op_guid *op = (struct msica_op_guid *)malloc(sizeof(struct msica_op_guid));
    if (op == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_op_guid));
        return NULL;
    }

    op->base.type  = type;
    op->base.ticks = ticks;
    op->base.next  = next;
    memcpy(&op->value, value, sizeof(GUID));

    return &op->base;
}


struct msica_op *
msica_op_create_guid_string(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ const GUID *value_guid,
    _In_z_ LPCTSTR value_str)
{
    if (MSICA_OP_TYPE_DATA(type) != 0x5)
    {
        msg(M_NONFATAL, "%s: Operation data type not GUID-string (%x)", __FUNCTION__, MSICA_OP_TYPE_DATA(type));
        return NULL;
    }

    /* Create and fill operation struct. */
    size_t value_str_size = (_tcslen(value_str) + 1) * sizeof(TCHAR);
    struct msica_op_guid_string *op = (struct msica_op_guid_string *)malloc(sizeof(struct msica_op_guid_string) + value_str_size);
    if (op == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_op_guid_string) + value_str_size);
        return NULL;
    }

    op->base.type  = type;
    op->base.ticks = ticks;
    op->base.next  = next;
    memcpy(&op->value_guid, value_guid, sizeof(GUID));
    memcpy(op->value_str, value_str, value_str_size);

    return &op->base;
}


void
msica_op_seq_add_head(
    _Inout_ struct msica_op_seq *seq,
    _Inout_ struct msica_op *operation)
{
    if (seq == NULL || operation == NULL)
    {
        return;
    }

    /* Insert list in the head. */
    struct msica_op *op;
    for (op = operation; op->next; op = op->next)
    {
    }
    op->next = seq->head;

    /* Update head (and tail). */
    seq->head = operation;
    if (seq->tail == NULL)
    {
        seq->tail = op;
    }
}


void
msica_op_seq_add_tail(
    _Inout_ struct msica_op_seq *seq,
    _Inout_ struct msica_op *operation)
{
    if (seq == NULL || operation == NULL)
    {
        return;
    }

    /* Append list to the tail. */
    struct msica_op *op;
    for (op = operation; op->next; op = op->next)
    {
    }
    if (seq->tail)
    {
        seq->tail->next = operation;
    }
    else
    {
        seq->head = operation;
    }
    seq->tail = op;
}


DWORD
msica_op_seq_save(
    _In_ const struct msica_op_seq *seq,
    _In_ HANDLE hFile)
{
    DWORD dwWritten;
    for (const struct msica_op *op = seq->head; op; op = op->next)
    {
        struct msica_op_hdr hdr;
        hdr.type  = op->type;
        hdr.ticks = op->ticks;

        /* Calculate size of data. */
        switch (MSICA_OP_TYPE_DATA(op->type))
        {
            case 0x1: /* msica_op_bool */
                hdr.size_data = sizeof(struct msica_op_bool) - sizeof(struct msica_op);
                break;

            case 0x2: /* msica_op_string */
                hdr.size_data =
                    sizeof(struct msica_op_string) - sizeof(struct msica_op)
                    +(DWORD)(_tcslen(((struct msica_op_string *)op)->value) + 1) * sizeof(TCHAR);
                break;

            case 0x3: /* msica_op_multistring */
            {
                LPCTSTR str;
                for (str = ((struct msica_op_multistring *)op)->value; str[0]; str += _tcslen(str) + 1)
                {
                }
                hdr.size_data =
                    sizeof(struct msica_op_multistring) - sizeof(struct msica_op)
                    +(DWORD)(str + 1 - ((struct msica_op_multistring *)op)->value) * sizeof(TCHAR);
                break;
            }

            case 0x4: /* msica_op_guid */
                hdr.size_data = sizeof(struct msica_op_guid) - sizeof(struct msica_op);
                break;

            case 0x5: /* msica_op_guid_string */
                hdr.size_data =
                    sizeof(struct msica_op_guid_string) - sizeof(struct msica_op)
                    +(DWORD)(_tcslen(((struct msica_op_guid_string *)op)->value_str) + 1) * sizeof(TCHAR);
                break;

            default:
                msg(M_NONFATAL, "%s: Unknown operation data type (%x)", __FUNCTION__, MSICA_OP_TYPE_DATA(op->type));
                return ERROR_BAD_ARGUMENTS;
        }

        if (!WriteFile(hFile, &hdr, sizeof(struct msica_op_hdr), &dwWritten, NULL)
            || !WriteFile(hFile, op + 1, hdr.size_data, &dwWritten, NULL))
        {
            DWORD dwResult = GetLastError();
            msg(M_NONFATAL | M_ERRNO, "%s: WriteFile failed", __FUNCTION__);
            return dwResult;
        }
    }

    return ERROR_SUCCESS;
}


DWORD
msica_op_seq_load(
    _Inout_ struct msica_op_seq *seq,
    _In_ HANDLE hFile)
{
    DWORD dwRead;

    if (seq == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    seq->head = seq->tail = NULL;

    for (;;)
    {
        struct msica_op_hdr hdr;
        if (!ReadFile(hFile, &hdr, sizeof(struct msica_op_hdr), &dwRead, NULL))
        {
            DWORD dwResult = GetLastError();
            msg(M_NONFATAL | M_ERRNO, "%s: ReadFile failed", __FUNCTION__);
            return dwResult;
        }
        else if (dwRead == 0)
        {
            /* EOF */
            return ERROR_SUCCESS;
        }
        else if (dwRead < sizeof(struct msica_op_hdr))
        {
            msg(M_NONFATAL, "%s: Incomplete ReadFile", __FUNCTION__);
            return ERROR_INVALID_DATA;
        }

        struct msica_op *op = (struct msica_op *)malloc(sizeof(struct msica_op) + hdr.size_data);
        if (op == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_op) + hdr.size_data);
            return ERROR_OUTOFMEMORY;
        }

        op->type  = hdr.type;
        op->ticks = hdr.ticks;
        op->next  = NULL;

        if (!ReadFile(hFile, op + 1, hdr.size_data, &dwRead, NULL))
        {
            DWORD dwResult = GetLastError();
            msg(M_NONFATAL | M_ERRNO, "%s: ReadFile failed", __FUNCTION__);
            free(op);
            return dwResult;
        }
        else if (dwRead < hdr.size_data)
        {
            msg(M_NONFATAL, "%s: Incomplete ReadFile", __FUNCTION__);
            return ERROR_INVALID_DATA;
        }

        msica_op_seq_add_tail(seq, op);
    }
}


static DWORD
msica_op_tap_interface_create_exec(
    _Inout_ const struct msica_op_string *op,
    _Inout_ struct msica_session *session)
{
    if (op == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    {
        /* Report the name of the interface to installer. */
        MSIHANDLE hRecord = MsiCreateRecord(3);
        MsiRecordSetString(hRecord, 1, TEXT("Creating TAP interface"));
        MsiRecordSetString(hRecord, 2, op->value);
        int iResult = MsiProcessMessage(session->hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
        MsiCloseHandle(hRecord);
        if (iResult == IDCANCEL)
        {
            return ERROR_INSTALL_USEREXIT;
        }
    }

    /* Get all available network interfaces. */
    struct tap_interface_node *pInterfaceList = NULL;
    DWORD dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, TRUE);
    if (dwResult == ERROR_SUCCESS)
    {
        /* Does interface exist? */
        for (struct tap_interface_node *pInterfaceOther = pInterfaceList;; pInterfaceOther = pInterfaceOther->pNext)
        {
            if (pInterfaceOther == NULL)
            {
                /* No interface with a same name found. Create one. */
                BOOL bRebootRequired = FALSE;
                GUID guidInterface;
                dwResult = tap_create_interface(NULL, NULL, NULL, &bRebootRequired, &guidInterface);
                if (dwResult == ERROR_SUCCESS)
                {
                    /* Set interface name. */
                    dwResult = tap_set_interface_name(&guidInterface, op->value);
                    if (dwResult == ERROR_SUCCESS)
                    {
                        if (session->rollback_enabled)
                        {
                            /* Order rollback action to delete it. */
                            msica_op_seq_add_head(
                                &session->seq_cleanup[MSICA_CLEANUP_ACTION_ROLLBACK],
                                msica_op_create_guid(
                                    msica_op_tap_interface_delete_by_guid,
                                    0,
                                    NULL,
                                    &guidInterface));
                        }
                    }
                    else
                    {
                        tap_delete_interface(NULL, &guidInterface, &bRebootRequired);
                    }

                    if (bRebootRequired)
                    {
                        MsiSetMode(session->hInstall, MSIRUNMODE_REBOOTATEND, TRUE);
                    }
                }
                break;
            }
            else if (_tcsicmp(op->value, pInterfaceOther->szName) == 0)
            {
                /* Interface with a same name found. */
                for (LPCTSTR hwid = pInterfaceOther->szzHardwareIDs;; hwid += _tcslen(hwid) + 1)
                {
                    if (hwid[0] == 0)
                    {
                        /* This is not a TAP interface. */
                        msg(M_NONFATAL, "%s: Interface with name \"%" PRIsLPTSTR "\" already exists", __FUNCTION__, pInterfaceOther->szName);
                        dwResult = ERROR_ALREADY_EXISTS;
                        break;
                    }
                    else if (
                        _tcsicmp(hwid, TEXT(TAP_WIN_COMPONENT_ID)) == 0
                        || _tcsicmp(hwid, TEXT("root\\") TEXT(TAP_WIN_COMPONENT_ID)) == 0)
                    {
                        /* This is a TAP interface. We already got what we wanted! */
                        dwResult = ERROR_SUCCESS;
                        break;
                    }
                }
                break;
            }
        }

        tap_free_interface_list(pInterfaceList);
    }

    return dwResult;
}


static DWORD
msica_op_tap_interface_delete(
    _In_ struct tap_interface_node *pInterfaceList,
    _In_ struct tap_interface_node *pInterface,
    _Inout_ struct msica_session *session)
{
    if (pInterfaceList == NULL || pInterface == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    DWORD dwResult;

    /* Delete the interface. */
    BOOL bRebootRequired = FALSE;
    dwResult = tap_delete_interface(NULL, &pInterface->guid, &bRebootRequired);
    if (bRebootRequired)
    {
        MsiSetMode(session->hInstall, MSIRUNMODE_REBOOTATEND, TRUE);
    }

    if (session->rollback_enabled)
    {
        /*
         * Schedule rollback action to create the interface back. Though it won't be exactly the same interface again.
         *
         * The previous version of this function did:
         * - Execution Pass:       rename the interface to some temporary name
         * - Commit/Rollback Pass: delete the interface / rename the interface back to original name
         *
         * However, the WiX Toolset's Diffx extension to install and remove drivers removed the TAP driver between the
         * execution and commit passes. TAP driver removal makes all TAP interfaces unavailable and our CA couldn't find
         * the interface to delete any more.
         *
         * While the system where OpenVPN was uninstalled didn't have any TAP interfaces any more as expected behaviour,
         * the problem appears after reinstalling the OpenVPN. Some residue TAP interface registry keys remain on the
         * system, causing the TAP interface to reappear as "Ethernet NN" interface next time the TAP driver is
         * installed. This causes TAP interfaces to accumulate over cyclic install-uninstall-install...
         *
         * Therefore, it is better to remove the TAP interfaces before the TAP driver is removed, and reinstall the TAP
         * interface back should the rollback be required. I wonder if the WiX Diffx extension supports execute/commit/
         * rollback feature of MSI in the first place.
         */
        msica_op_seq_add_head(
            &session->seq_cleanup[MSICA_CLEANUP_ACTION_ROLLBACK],
            msica_op_create_string(
                msica_op_tap_interface_create,
                0,
                NULL,
                pInterface->szName));
    }

    return dwResult;
}


static DWORD
msica_op_tap_interface_delete_by_name_exec(
    _Inout_ const struct msica_op_string *op,
    _Inout_ struct msica_session *session)
{
    if (op == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    {
        /* Report the name of the interface to installer. */
        MSIHANDLE hRecord = MsiCreateRecord(3);
        MsiRecordSetString(hRecord, 1, TEXT("Deleting interface"));
        MsiRecordSetString(hRecord, 2, op->value);
        int iResult = MsiProcessMessage(session->hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
        MsiCloseHandle(hRecord);
        if (iResult == IDCANCEL)
        {
            return ERROR_INSTALL_USEREXIT;
        }
    }

    /* Get available TUN/TAP interfaces. */
    struct tap_interface_node *pInterfaceList = NULL;
    DWORD dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, FALSE);
    if (dwResult == ERROR_SUCCESS)
    {
        /* Does interface exist? */
        for (struct tap_interface_node *pInterface = pInterfaceList;; pInterface = pInterface->pNext)
        {
            if (pInterface == NULL)
            {
                /* Interface not found. We already got what we wanted! */
                dwResult = ERROR_SUCCESS;
                break;
            }
            else if (_tcsicmp(op->value, pInterface->szName) == 0)
            {
                /* Interface found. */
                dwResult = msica_op_tap_interface_delete(
                    pInterfaceList,
                    pInterface,
                    session);
                break;
            }
        }

        tap_free_interface_list(pInterfaceList);
    }

    return dwResult;
}


static DWORD
msica_op_tap_interface_delete_by_guid_exec(
    _Inout_ const struct msica_op_guid *op,
    _Inout_ struct msica_session *session)
{
    if (op == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    {
        /* Report the GUID of the interface to installer. */
        MSIHANDLE hRecord = MsiCreateRecord(3);
        LPOLESTR szInterfaceId = NULL;
        StringFromIID((REFIID)&op->value, &szInterfaceId);
        MsiRecordSetString(hRecord, 1, TEXT("Deleting interface"));
        MsiRecordSetString(hRecord, 2, szInterfaceId);
        int iResult = MsiProcessMessage(session->hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
        CoTaskMemFree(szInterfaceId);
        MsiCloseHandle(hRecord);
        if (iResult == IDCANCEL)
        {
            return ERROR_INSTALL_USEREXIT;
        }
    }

    /* Get all available interfaces. */
    struct tap_interface_node *pInterfaceList = NULL;
    DWORD dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, TRUE);
    if (dwResult == ERROR_SUCCESS)
    {
        /* Does interface exist? */
        for (struct tap_interface_node *pInterface = pInterfaceList;; pInterface = pInterface->pNext)
        {
            if (pInterface == NULL)
            {
                /* Interface not found. We already got what we wanted! */
                dwResult = ERROR_SUCCESS;
                break;
            }
            else if (memcmp(&op->value, &pInterface->guid, sizeof(GUID)) == 0)
            {
                /* Interface found. */
                dwResult = msica_op_tap_interface_delete(
                    pInterfaceList,
                    pInterface,
                    session);
                break;
            }
        }

        tap_free_interface_list(pInterfaceList);
    }

    return dwResult;
}


static DWORD
msica_op_tap_interface_set_name_exec(
    _Inout_ const struct msica_op_guid_string *op,
    _Inout_ struct msica_session *session)
{
    if (op == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    {
        /* Report the GUID of the interface to installer. */
        MSIHANDLE hRecord = MsiCreateRecord(3);
        LPOLESTR szInterfaceId = NULL;
        StringFromIID((REFIID)&op->value_guid, &szInterfaceId);
        MsiRecordSetString(hRecord, 1, TEXT("Setting interface name"));
        MsiRecordSetString(hRecord, 2, szInterfaceId);
        MsiRecordSetString(hRecord, 3, op->value_str);
        int iResult = MsiProcessMessage(session->hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
        CoTaskMemFree(szInterfaceId);
        MsiCloseHandle(hRecord);
        if (iResult == IDCANCEL)
        {
            return ERROR_INSTALL_USEREXIT;
        }
    }

    /* Get all available network interfaces. */
    struct tap_interface_node *pInterfaceList = NULL;
    DWORD dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, TRUE);
    if (dwResult == ERROR_SUCCESS)
    {
        /* Does interface exist? */
        for (struct tap_interface_node *pInterface = pInterfaceList;; pInterface = pInterface->pNext)
        {
            if (pInterface == NULL)
            {
                /* Interface not found. */
                LPOLESTR szInterfaceId = NULL;
                StringFromIID((REFIID)&op->value_guid, &szInterfaceId);
                msg(M_NONFATAL, "%s: %" PRIsLPOLESTR " interface not found", __FUNCTION__, szInterfaceId);
                CoTaskMemFree(szInterfaceId);
                dwResult = ERROR_FILE_NOT_FOUND;
                break;
            }
            else if (memcmp(&op->value_guid, &pInterface->guid, sizeof(GUID)) == 0)
            {
                /* Interface found. */
                for (struct tap_interface_node *pInterfaceOther = pInterfaceList;; pInterfaceOther = pInterfaceOther->pNext)
                {
                    if (pInterfaceOther == NULL)
                    {
                        /* No other interface with a same name found. All clear to rename the interface. */
                        dwResult = tap_set_interface_name(&pInterface->guid, op->value_str);
                        if (dwResult == ERROR_SUCCESS)
                        {
                            if (session->rollback_enabled)
                            {
                                /* Order rollback action to rename it back. */
                                msica_op_seq_add_head(
                                    &session->seq_cleanup[MSICA_CLEANUP_ACTION_ROLLBACK],
                                    msica_op_create_guid_string(
                                        msica_op_tap_interface_set_name,
                                        0,
                                        NULL,
                                        &pInterface->guid,
                                        pInterface->szName));
                            }
                        }
                        break;
                    }
                    else if (_tcsicmp(op->value_str, pInterfaceOther->szName) == 0)
                    {
                        /* Interface with a same name found. Duplicate interface names are not allowed. */
                        msg(M_NONFATAL, "%s: Interface with name \"%" PRIsLPTSTR "\" already exists", __FUNCTION__, pInterfaceOther->szName);
                        dwResult = ERROR_ALREADY_EXISTS;
                        break;
                    }
                }
                break;
            }
        }

        tap_free_interface_list(pInterfaceList);
    }

    return dwResult;
}


static DWORD
msica_op_file_delete_exec(
    _Inout_ const struct msica_op_string *op,
    _Inout_ struct msica_session *session)
{
    if (op == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    {
        /* Report the name of the file to installer. */
        MSIHANDLE hRecord = MsiCreateRecord(3);
        MsiRecordSetString(hRecord, 1, TEXT("Deleting file"));
        MsiRecordSetString(hRecord, 2, op->value);
        int iResult = MsiProcessMessage(session->hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
        MsiCloseHandle(hRecord);
        if (iResult == IDCANCEL)
        {
            return ERROR_INSTALL_USEREXIT;
        }
    }

    DWORD dwResult;

    if (session->rollback_enabled)
    {
        size_t sizeNameBackupLenZ = _tcslen(op->value) + 7 /*" (orig "*/ + 10 /*maximum int*/ + 1 /*")"*/ + 1 /*terminator*/;
        LPTSTR szNameBackup = (LPTSTR)malloc(sizeNameBackupLenZ * sizeof(TCHAR));
        if (szNameBackup == NULL)
        {
            msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeNameBackupLenZ * sizeof(TCHAR));
            return ERROR_OUTOFMEMORY;
        }

        int count = 0;

        do
        {
            /* Rename the file to make a backup. */
            _stprintf_s(
                szNameBackup, sizeNameBackupLenZ,
                TEXT("%s (orig %i)"),
                op->value,
                ++count);
            dwResult = MoveFile(op->value, szNameBackup) ? ERROR_SUCCESS : GetLastError();
        } while (dwResult == ERROR_ALREADY_EXISTS);

        if (dwResult == ERROR_SUCCESS)
        {
            /* Schedule rollback action to restore from backup. */
            msica_op_seq_add_head(
                &session->seq_cleanup[MSICA_CLEANUP_ACTION_ROLLBACK],
                msica_op_create_multistring(
                    msica_op_file_move,
                    0,
                    NULL,
                    szNameBackup,
                    op->value,
                    NULL));

            /* Schedule commit action to delete the backup. */
            msica_op_seq_add_tail(
                &session->seq_cleanup[MSICA_CLEANUP_ACTION_COMMIT],
                msica_op_create_string(
                    msica_op_file_delete,
                    0,
                    NULL,
                    szNameBackup));
        }
        else if (dwResult == ERROR_FILE_NOT_FOUND) /* File does not exist: We already got what we wanted! */
        {
            dwResult = ERROR_SUCCESS;
        }
        else
        {
            msg(M_NONFATAL | M_ERRNO, "%s: MoveFile(\"%" PRIsLPTSTR "\", \"%" PRIsLPTSTR "\") failed", __FUNCTION__, op->value, szNameBackup);
        }

        free(szNameBackup);
    }
    else
    {
        /* Delete the file. */
        dwResult = DeleteFile(op->value) ? ERROR_SUCCESS : GetLastError();
        if (dwResult == ERROR_FILE_NOT_FOUND) /* File does not exist: We already got what we wanted! */
        {
            dwResult = ERROR_SUCCESS;
        }
        else if (dwResult != ERROR_SUCCESS)
        {
            msg(M_NONFATAL | M_ERRNO, "%s: DeleteFile(\"%" PRIsLPTSTR "\") failed", __FUNCTION__, op->value);
        }
    }

    return dwResult;
}


static DWORD
msica_op_file_move_exec(
    _Inout_ const struct msica_op_multistring *op,
    _Inout_ struct msica_session *session)
{
    if (op == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Get source filename. */
    LPCTSTR szNameSrc = op->value;
    if (szNameSrc[0] == 0)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Get destination filename. */
    LPCTSTR szNameDst = szNameSrc + _tcslen(szNameSrc) + 1;
    if (szNameDst[0] == 0)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    {
        /* Report the name of the files to installer. */
        MSIHANDLE hRecord = MsiCreateRecord(3);
        MsiRecordSetString(hRecord, 1, TEXT("Moving file"));
        MsiRecordSetString(hRecord, 2, szNameSrc);
        MsiRecordSetString(hRecord, 3, szNameDst);
        int iResult = MsiProcessMessage(session->hInstall, INSTALLMESSAGE_ACTIONDATA, hRecord);
        MsiCloseHandle(hRecord);
        if (iResult == IDCANCEL)
        {
            return ERROR_INSTALL_USEREXIT;
        }
    }

    DWORD dwResult = MoveFile(szNameSrc, szNameDst) ? ERROR_SUCCESS : GetLastError();
    if (dwResult == ERROR_SUCCESS)
    {
        if (session->rollback_enabled)
        {
            /* Order rollback action to move it back. */
            msica_op_seq_add_head(
                &session->seq_cleanup[MSICA_CLEANUP_ACTION_ROLLBACK],
                msica_op_create_multistring(
                    msica_op_file_move,
                    0,
                    NULL,
                    szNameDst,
                    szNameSrc,
                    NULL));
        }
    }
    else
    {
        msg(M_NONFATAL | M_ERRNO, "%s: MoveFile(\"%" PRIsLPTSTR "\", \"%" PRIsLPTSTR "\") failed", __FUNCTION__, szNameSrc, szNameDst);
    }

    return dwResult;
}


void
openvpnmsica_session_init(
    _Inout_ struct msica_session *session,
    _In_ MSIHANDLE hInstall,
    _In_ bool continue_on_error,
    _In_ bool rollback_enabled)
{
    session->hInstall          = hInstall;
    session->continue_on_error = continue_on_error;
    session->rollback_enabled  = rollback_enabled;
    for (size_t i = 0; i < MSICA_CLEANUP_ACTION_COUNT; i++)
    {
        msica_op_seq_init(&session->seq_cleanup[i]);
    }
}


DWORD
msica_op_seq_process(
    _Inout_ const struct msica_op_seq *seq,
    _Inout_ struct msica_session *session)
{
    DWORD dwResult;

    if (seq == NULL || session == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    /* Tell the installer to use explicit progress messages. */
    MSIHANDLE hRecordProg = MsiCreateRecord(3);
    MsiRecordSetInteger(hRecordProg, 1, 1);
    MsiRecordSetInteger(hRecordProg, 2, 1);
    MsiRecordSetInteger(hRecordProg, 3, 0);
    MsiProcessMessage(session->hInstall, INSTALLMESSAGE_PROGRESS, hRecordProg);

    /* Prepare hRecordProg for progress messages. */
    MsiRecordSetInteger(hRecordProg, 1, 2);
    MsiRecordSetInteger(hRecordProg, 3, 0);

    for (const struct msica_op *op = seq->head; op; op = op->next)
    {
        switch (op->type)
        {
            case msica_op_rollback_enable:
                session->rollback_enabled = ((const struct msica_op_bool *)op)->value;
                dwResult = ERROR_SUCCESS;
                break;

            case msica_op_tap_interface_create:
                dwResult = msica_op_tap_interface_create_exec((const struct msica_op_string *)op, session);
                break;

            case msica_op_tap_interface_delete_by_name:
                dwResult = msica_op_tap_interface_delete_by_name_exec((const struct msica_op_string *)op, session);
                break;

            case msica_op_tap_interface_delete_by_guid:
                dwResult = msica_op_tap_interface_delete_by_guid_exec((const struct msica_op_guid *)op, session);
                break;

            case msica_op_tap_interface_set_name:
                dwResult = msica_op_tap_interface_set_name_exec((const struct msica_op_guid_string *)op, session);
                break;

            case msica_op_file_delete:
                dwResult = msica_op_file_delete_exec((const struct msica_op_string *)op, session);
                break;

            case msica_op_file_move:
                dwResult = msica_op_file_move_exec((const struct msica_op_multistring *)op, session);
                break;

            default:
                msg(M_NONFATAL, "%s: Unknown operation type (%x)", __FUNCTION__, op->type);
                dwResult = ERROR_FILE_NOT_FOUND;
        }

        if (!session->continue_on_error && dwResult != ERROR_SUCCESS)
        {
            /* Operation failed. It should have sent error message to Installer. Therefore, just quit here. */
            goto cleanup_hRecordProg;
        }

        /* Report progress and check for user cancellation. */
        MsiRecordSetInteger(hRecordProg, 2, op->ticks);
        if (MsiProcessMessage(session->hInstall, INSTALLMESSAGE_PROGRESS, hRecordProg) == IDCANCEL)
        {
            dwResult = ERROR_INSTALL_USEREXIT;
            goto cleanup_hRecordProg;
        }
    }

    dwResult = ERROR_SUCCESS;

cleanup_hRecordProg:
    MsiCloseHandle(hRecordProg);
    return dwResult;
}
