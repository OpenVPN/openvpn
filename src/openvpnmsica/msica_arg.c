/*
 *  openvpnmsica -- Custom Action DLL to provide OpenVPN-specific support to MSI packages
 *                  https://community.openvpn.net/openvpn/wiki/OpenVPNMSICA
 *
 *  Copyright (C) 2018-2023 Simon Rozman <simon@rozman.si>
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
#endif

#include "msica_arg.h"
#include "../tapctl/error.h"
#include "../tapctl/tap.h"

#include <windows.h>
#include <malloc.h>


void
msica_arg_seq_init(_Inout_ struct msica_arg_seq *seq)
{
    seq->head = NULL;
    seq->tail = NULL;
}


void
msica_arg_seq_free(_Inout_ struct msica_arg_seq *seq)
{
    while (seq->head)
    {
        struct msica_arg *p = seq->head;
        seq->head = seq->head->next;
        free(p);
    }
    seq->tail = NULL;
}


void
msica_arg_seq_add_head(
    _Inout_ struct msica_arg_seq *seq,
    _In_z_ LPCTSTR argument)
{
    size_t argument_size = (_tcslen(argument) + 1) * sizeof(TCHAR);
    struct msica_arg *p = malloc(sizeof(struct msica_arg) + argument_size);
    if (p == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_arg) + argument_size);
    }
    memcpy(p->val, argument, argument_size);
    p->next = seq->head;
    seq->head = p;
    if (seq->tail == NULL)
    {
        seq->tail = p;
    }
}


void
msica_arg_seq_add_tail(
    _Inout_ struct msica_arg_seq *seq,
    _Inout_ LPCTSTR argument)
{
    size_t argument_size = (_tcslen(argument) + 1) * sizeof(TCHAR);
    struct msica_arg *p = malloc(sizeof(struct msica_arg) + argument_size);
    if (p == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, sizeof(struct msica_arg) + argument_size);
    }
    memcpy(p->val, argument, argument_size);
    p->next = NULL;
    *(seq->tail ? &seq->tail->next : &seq->head) = p;
    seq->tail = p;
}


LPTSTR
msica_arg_seq_join(_In_ const struct msica_arg_seq *seq)
{
    /* Count required space. */
    size_t size = 2 /*x + zero-terminator*/;
    for (struct msica_arg *p = seq->head; p != NULL; p = p->next)
    {
        size += _tcslen(p->val) + 1 /*space delimiter|zero-terminator*/;
    }
    size *= sizeof(TCHAR);

    /* Allocate. */
    LPTSTR str = malloc(size);
    if (str == NULL)
    {
        msg(M_FATAL, "%s: malloc(%u) failed", __FUNCTION__, size);
        return NULL;
    }

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996) /* Using unsafe string functions: The space in s and termination of p->val has been implicitly verified at the beginning of this function. */
#endif

    /* Dummy argv[0] (i.e. executable name), for CommandLineToArgvW to work correctly when parsing this string. */
    _tcscpy(str, TEXT("x"));

    /* Join. */
    LPTSTR s = str + 1 /*x*/;
    for (struct msica_arg *p = seq->head; p != NULL; p = p->next)
    {
        /* Convert zero-terminator into space delimiter. */
        s[0] = TEXT(' ');
        s++;
        /* Append argument. */
        _tcscpy(s, p->val);
        s += _tcslen(p->val);
    }

#ifdef _MSC_VER
#pragma warning(pop)
#endif

    return str;
}
