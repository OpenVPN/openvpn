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

#ifndef MSICA_OP_H
#define MSICA_OP_H

#include <windows.h>
#include <msi.h>
#include <stdarg.h>
#include <stdbool.h>
#include <tchar.h>
#include "../tapctl/basic.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4200) /* Using zero-sized arrays in struct/union. */
#endif


/**
 * Operation type macros
 */
#define MSICA_MAKE_OP_TYPE(op, data)  (((op)<<4)|((data)&0xf))
#define MSICA_OP_TYPE_OP(type)        ((unsigned int)(type)>>4)
#define MSICA_OP_TYPE_DATA(type)      ((unsigned int)(type)&0xf)


/**
 * Operation types
 */
enum msica_op_type
{
    msica_op_rollback_enable              = MSICA_MAKE_OP_TYPE(0x1, 0x1),  /** Enable/disable rollback  | msica_op_bool */
    msica_op_tap_interface_create         = MSICA_MAKE_OP_TYPE(0x2, 0x2),  /** Create TAP/TUN interface | msica_op_string */
    msica_op_tap_interface_delete_by_name = MSICA_MAKE_OP_TYPE(0x3, 0x2),  /** Delete TAP/TUN interface | msica_op_string */
    msica_op_tap_interface_delete_by_guid = MSICA_MAKE_OP_TYPE(0x3, 0x4),  /** Delete TAP/TUN interface | msica_op_guid */
    msica_op_tap_interface_set_name       = MSICA_MAKE_OP_TYPE(0x4, 0x5),  /** Rename TAP/TUN interface | msica_op_guid_string */
    msica_op_file_delete                  = MSICA_MAKE_OP_TYPE(0x5, 0x2),  /** Delete file              | msica_op_string */
    msica_op_file_move                    = MSICA_MAKE_OP_TYPE(0x6, 0x3),  /** Move file                | msica_op_multistring (min 2 strings) */
};


/**
 * Operation data
 */
struct msica_op
{
    enum msica_op_type type;  /** Operation type */
    int ticks;                /** Number of ticks on the progress indicator this operation represents */
    struct msica_op *next;    /** Pointer to the next operation in the sequence */
};


/**
 * Operation sequence
 */
struct msica_op_seq
{
    struct msica_op *head;    /** Pointer to the first operation in the sequence */
    struct msica_op *tail;    /** Pointer to the last operation in the sequence */
};


/**
 * Initializes operation sequence
 *
 * @param seq           Pointer to uninitialized operation sequence
 */
void
msica_op_seq_init(_Inout_ struct msica_op_seq *seq);


/**
 * Frees operation sequence
 *
 * @param seq           Pointer to operation sequence
 */
void
msica_op_seq_free(_Inout_ struct msica_op_seq *seq);


/**
 * Operation data (bool, 0x1)
 */
struct msica_op_bool
{
    struct msica_op base;     /** Common operation data */
    bool value;               /** Operation data boolean value */
};


/**
 * Allocates and fills a new msica_op_bool operation
 *
 * @param type          Operation type
 *
 * @param ticks         Number of ticks on the progress indicator this operation represents
 *
 * @param next          Pointer to the next operation in the sequence
 *
 * @param value         Boolean value
 *
 * @return              A new msica_op_bool operation. Must be added to a sequence list or
 *                      released using free() after use. The function returns a pointer to
 *                      msica_op to reduce type-casting in code.
 */
struct msica_op *
msica_op_create_bool(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ bool value);


/**
 * Operation data (string, 0x2)
 */
struct msica_op_string
{
    struct msica_op base;     /** Common operation data */
    TCHAR value[];            /** Operation data string - the string must always be zero terminated. */
};


/**
 * Allocates and fills a new msica_op_string operation
 *
 * @param type          Operation type
 *
 * @param ticks         Number of ticks on the progress indicator this operation represents
 *
 * @param next          Pointer to the next operation in the sequence
 *
 * @param value         String value
 *
 * @return              A new msica_op_string operation. Must be added to a sequence list or
 *                      released using free() after use. The function returns a pointer to
 *                      msica_op to reduce type-casting in code.
 */
struct msica_op *
msica_op_create_string(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_z_ LPCTSTR value);


/**
 * Operation data (multi-string, 0x3)
 */
struct msica_op_multistring
{
    struct msica_op base;     /** Common operation data */
    TCHAR value[];            /** Operation data strings - each string must always be zero terminated. The last string must be double terminated. */
};


/**
 * Allocates and fills a new msica_op_multistring operation
 *
 * @param type          Operation type
 *
 * @param ticks         Number of ticks on the progress indicator this operation represents
 *
 * @param next          Pointer to the next operation in the sequence
 *
 * @param arglist       List of non-empty strings. The last string must be NULL.
 *
 * @return              A new msica_op_string operation. Must be added to a sequence list or
 *                      released using free() after use. The function returns a pointer to
 *                      msica_op to reduce type-casting in code.
 */
struct msica_op *
msica_op_create_multistring_va(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ va_list arglist);


/**
 * Operation data (GUID, 0x4)
 */
struct msica_op_guid
{
    struct msica_op base;     /** Common operation data */
    GUID value;               /** Operation data GUID */
};


/**
 * Allocates and fills a new msica_op_guid operation
 *
 * @param type          Operation type
 *
 * @param ticks         Number of ticks on the progress indicator this operation represents
 *
 * @param next          Pointer to the next operation in the sequence
 *
 * @param value         Pointer to GUID value
 *
 * @return              A new msica_op_guid operation. Must be added to a sequence list or
 *                      released using free() after use. The function returns a pointer to
 *                      msica_op to reduce type-casting in code.
 */
struct msica_op *
msica_op_create_guid(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ const GUID *value);


/**
 * Operation data (guid-string, 0x5)
 */
struct msica_op_guid_string
{
    struct msica_op base;     /** Common operation data */
    GUID value_guid;          /** Operation data GUID */
    TCHAR value_str[];        /** Operation data string - the string must always be zero terminated. */
};


/**
 * Allocates and fills a new msica_op_guid_string operation
 *
 * @param type          Operation type
 *
 * @param ticks         Number of ticks on the progress indicator this operation represents
 *
 * @param next          Pointer to the next operation in the sequence
 *
 * @param value_guid    Pointer to GUID value
 *
 * @param value_str     String value
 *
 * @return              A new msica_op_guid_string operation. Must be added to a sequence
 *                      list or released using free() after use. The function returns a
 *                      pointer to msica_op to reduce type-casting in code.
 */
struct msica_op *
msica_op_create_guid_string(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    _In_ const GUID *value_guid,
    _In_z_ LPCTSTR value_str);


/**
 * Allocates and fills a new msica_op_multistring operation. Strings must be non-empty. The
 * last string passed as the input parameter must be NULL.
 *
 * @param type          Operation type
 *
 * @param ticks         Number of ticks on the progress indicator this operation represents
 *
 * @param next          Pointer to the next operation in the sequence
 *
 * @return              A new msica_op_string operation. Must be added to a sequence list or
 *                      released using free() after use. The function returns a pointer to
 *                      msica_op to reduce type-casting in code.
 */
static inline struct msica_op *
msica_op_create_multistring(
    _In_ enum msica_op_type type,
    _In_ int ticks,
    _In_opt_ struct msica_op *next,
    ...)
{
    va_list arglist;
    va_start(arglist, next);
    struct msica_op *op = msica_op_create_multistring_va(type, ticks, next, arglist);
    va_end(arglist);
    return op;
}


/**
 * Is operation sequence empty
 *
 * @param seq           Pointer to operation sequence
 *
 * @return true if empty; false otherwise
 */
static inline bool
msica_op_seq_is_empty(_In_ const struct msica_op_seq *seq)
{
    return seq->head != NULL;
}


/**
 * Inserts operation(s) to the beginning of the operation sequence
 *
 * @param seq           Pointer to operation sequence
 *
 * @param operation     Pointer to the operation to insert. All operations in the list are
 *                      added until the list is terminated with msica_op.next field set to
 *                      NULL. Operations must be allocated using malloc().
 */
void
msica_op_seq_add_head(
    _Inout_ struct msica_op_seq *seq,
    _Inout_ struct msica_op *operation);


/**
 * Appends operation(s) to the end of the operation sequence
 *
 * @param seq           Pointer to operation sequence
 *
 * @param operation     Pointer to the operation to append. All operations in the list are
 *                      added until the list is terminated with msica_op.next field set to
 *                      NULL. Operations must be allocated using malloc().
 */
void
msica_op_seq_add_tail(
    _Inout_ struct msica_op_seq *seq,
    _Inout_ struct msica_op *operation);


/**
 * Saves the operation sequence to the file
 *
 * @param seq           Pointer to operation sequence
 *
 * @param hFile         Handle of the file opened with GENERIC_WRITE access
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
DWORD
msica_op_seq_save(
    _In_ const struct msica_op_seq *seq,
    _In_ HANDLE hFile);


/**
 * Loads the operation sequence from the file
 *
 * @param seq           Pointer to uninitialized or empty operation sequence
 *
 * @param hFile         Handle of the file opened with GENERIC_READ access
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
DWORD
msica_op_seq_load(
    _Inout_ struct msica_op_seq *seq,
    _In_ HANDLE hFile);


/**
 * Execution session constants
 */
#define MSICA_CLEANUP_ACTION_COMMIT   0
#define MSICA_CLEANUP_ACTION_ROLLBACK 1
#define MSICA_CLEANUP_ACTION_COUNT    2


/**
 * Execution session
 */
struct msica_session
{
    MSIHANDLE hInstall;           /** Installer handle */
    bool continue_on_error;       /** Continue execution on operation error? */
    bool rollback_enabled;        /** Is rollback enabled? */
    struct msica_op_seq seq_cleanup[MSICA_CLEANUP_ACTION_COUNT]; /** Commit/Rollback action operation sequence */
};


/**
 * Initializes execution session
 *
 * @param session       Pointer to an uninitialized execution session
 *
 * @param hInstall      Installer handle
 *
 * @param continue_on_error  Continue execution on operation error?
 *
 * @param rollback_enabled  Is rollback enabled?
 */
void
openvpnmsica_session_init(
    _Inout_ struct msica_session *session,
    _In_ MSIHANDLE hInstall,
    _In_ bool continue_on_error,
    _In_ bool rollback_enabled);


/**
 * Executes all operations in sequence
 *
 * @param seq           Pointer to operation sequence
 *
 * @param session       MSI session. The execution updates its members, most notably
 *                      rollback_enabled and fills cleanup sequences with commit/rollback
 *                      operations.
 *
 * @return ERROR_SUCCESS on success; An error code otherwise
 */
DWORD
msica_op_seq_process(
    _Inout_ const struct msica_op_seq *seq,
    _Inout_ struct msica_session *session);

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif /* ifndef MSICA_OP_H */
