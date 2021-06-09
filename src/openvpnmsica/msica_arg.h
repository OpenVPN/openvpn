/*
 *  openvpnmsica -- Custom Action DLL to provide OpenVPN-specific support to MSI packages
 *                  https://community.openvpn.net/openvpn/wiki/OpenVPNMSICA
 *
 *  Copyright (C) 2018-2021 Simon Rozman <simon@rozman.si>
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

#ifndef MSICA_ARG_H
#define MSICA_ARG_H

#include <windows.h>
#include <tchar.h>
#include "../tapctl/basic.h"


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4200) /* Using zero-sized arrays in struct/union. */
#endif


/**
 * Argument list
 */
struct msica_arg
{
    struct msica_arg *next; /** Pointer to the next argument in the sequence */
    TCHAR val[];            /** Zero terminated argument string */
};


/**
 * Argument sequence
 */
struct msica_arg_seq
{
    struct msica_arg *head; /** Pointer to the first argument in the sequence */
    struct msica_arg *tail; /** Pointer to the last argument in the sequence */
};


/**
 * Initializes argument sequence
 *
 * @param seq           Pointer to uninitialized argument sequence
 */
void
msica_arg_seq_init(_Inout_ struct msica_arg_seq *seq);


/**
 * Frees argument sequence
 *
 * @param seq           Pointer to the argument sequence
 */
void
msica_arg_seq_free(_Inout_ struct msica_arg_seq *seq);


/**
 * Inserts argument to the beginning of the argument sequence
 *
 * @param seq           Pointer to the argument sequence
 *
 * @param argument      Zero-terminated argument string to insert.
 */
void
msica_arg_seq_add_head(
    _Inout_ struct msica_arg_seq *seq,
    _In_z_ LPCTSTR argument);


/**
 * Appends argument to the end of the argument sequence
 *
 * @param seq           Pointer to the argument sequence
 *
 * @param argument      Zero-terminated argument string to append.
 */
void
msica_arg_seq_add_tail(
    _Inout_ struct msica_arg_seq *seq,
    _Inout_ LPCTSTR argument);

/**
 * Join arguments of the argument sequence into a space delimited string
 *
 * @param seq           Pointer to the argument sequence
 *
 * @return Joined argument string. Must be released with free() after use.
 */
LPTSTR
msica_arg_seq_join(_In_ const struct msica_arg_seq *seq);

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif /* ifndef MSICA_ARG_H */
