/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2012-2024 Heiko Hund <heiko.hund@sophos.com>
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


#include "service.h"

#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <userenv.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>
#include <sddl.h>
#include <shellapi.h>
#include <mstcpip.h>
#include <inttypes.h>

#include <versionhelpers.h>

#include "openvpn-msg.h"
#include "validate.h"
#include "wfp_block.h"

#define IO_TIMEOUT  2000 /*ms*/

#define ERROR_OPENVPN_STARTUP        0x20000000
#define ERROR_STARTUP_DATA           0x20000001
#define ERROR_MESSAGE_DATA           0x20000002
#define ERROR_MESSAGE_TYPE           0x20000003

static SERVICE_STATUS_HANDLE service;
static SERVICE_STATUS status = { .dwServiceType = SERVICE_WIN32_SHARE_PROCESS };
static HANDLE exit_event = NULL;
static settings_t settings;
static HANDLE rdns_semaphore = NULL;
#define RDNS_TIMEOUT 600  /* seconds to wait for the semaphore */

#define TUN_IOCTL_REGISTER_RINGS CTL_CODE(51820U, 0x970U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

openvpn_service_t interactive_service = {
    interactive,
    _L(PACKAGE_NAME) L"ServiceInteractive",
    _L(PACKAGE_NAME) L" Interactive Service",
    SERVICE_DEPENDENCIES,
    SERVICE_AUTO_START
};


typedef struct {
    WCHAR *directory;
    WCHAR *options;
    WCHAR *std_input;
} STARTUP_DATA;


/* Datatype for linked lists */
typedef struct _list_item {
    struct _list_item *next;
    LPVOID data;
} list_item_t;


/* Datatypes for undo information */
typedef enum {
    address,
    route,
    wfp_block,
    undo_dns4,
    undo_dns6,
    undo_nrpt,
    undo_domains,
    undo_wins,
    _undo_type_max
} undo_type_t;
typedef list_item_t *undo_lists_t[_undo_type_max];

typedef struct {
    HANDLE engine;
    int index;
    int metric_v4;
    int metric_v6;
} wfp_block_data_t;

typedef struct {
    char itf_name[256];
    PWSTR domains;
} dns_domains_undo_data_t;

typedef union {
    message_header_t header;
    address_message_t address;
    route_message_t route;
    flush_neighbors_message_t flush_neighbors;
    wfp_block_message_t wfp_block;
    dns_cfg_message_t dns;
    nrpt_dns_cfg_message_t nrpt_dns;
    enable_dhcp_message_t dhcp;
    set_mtu_message_t mtu;
    wins_cfg_message_t wins;
    create_adapter_message_t create_adapter;
} pipe_message_t;

typedef struct {
    CHAR addresses[NRPT_ADDR_NUM * NRPT_ADDR_SIZE];
    WCHAR domains[512]; /* MULTI_SZ string */
    DWORD domains_size; /* bytes in domains */
} nrpt_exclude_data_t;


static DWORD
AddListItem(list_item_t **pfirst, LPVOID data)
{
    list_item_t *new_item = malloc(sizeof(list_item_t));
    if (new_item == NULL)
    {
        return ERROR_OUTOFMEMORY;
    }

    new_item->next = *pfirst;
    new_item->data = data;

    *pfirst = new_item;
    return NO_ERROR;
}

typedef BOOL (*match_fn_t) (LPVOID item, LPVOID ctx);

static LPVOID
RemoveListItem(list_item_t **pfirst, match_fn_t match, LPVOID ctx)
{
    LPVOID data = NULL;
    list_item_t **pnext;

    for (pnext = pfirst; *pnext; pnext = &(*pnext)->next)
    {
        list_item_t *item = *pnext;
        if (!match(item->data, ctx))
        {
            continue;
        }

        /* Found item, remove from the list and free memory */
        *pnext = item->next;
        data = item->data;
        free(item);
        break;
    }
    return data;
}


static HANDLE
CloseHandleEx(LPHANDLE handle)
{
    if (handle && *handle && *handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(*handle);
        *handle = INVALID_HANDLE_VALUE;
    }
    return INVALID_HANDLE_VALUE;
}

static HANDLE
InitOverlapped(LPOVERLAPPED overlapped)
{
    ZeroMemory(overlapped, sizeof(OVERLAPPED));
    overlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    return overlapped->hEvent;
}

static BOOL
ResetOverlapped(LPOVERLAPPED overlapped)
{
    HANDLE io_event = overlapped->hEvent;
    if (!ResetEvent(io_event))
    {
        return FALSE;
    }
    ZeroMemory(overlapped, sizeof(OVERLAPPED));
    overlapped->hEvent = io_event;
    return TRUE;
}


typedef enum {
    peek,
    read,
    write
} async_op_t;

static DWORD
AsyncPipeOp(async_op_t op, HANDLE pipe, LPVOID buffer, DWORD size, DWORD count, LPHANDLE events)
{
    DWORD i;
    BOOL success;
    HANDLE io_event;
    DWORD res, bytes = 0;
    OVERLAPPED overlapped;
    LPHANDLE handles = NULL;

    io_event = InitOverlapped(&overlapped);
    if (!io_event)
    {
        goto out;
    }

    handles = malloc((count + 1) * sizeof(HANDLE));
    if (!handles)
    {
        goto out;
    }

    if (op == write)
    {
        success = WriteFile(pipe, buffer, size, NULL, &overlapped);
    }
    else
    {
        success = ReadFile(pipe, buffer, size, NULL, &overlapped);
    }
    if (!success && GetLastError() != ERROR_IO_PENDING && GetLastError() != ERROR_MORE_DATA)
    {
        goto out;
    }

    handles[0] = io_event;
    for (i = 0; i < count; i++)
    {
        handles[i + 1] = events[i];
    }

    res = WaitForMultipleObjects(count + 1, handles, FALSE,
                                 op == peek ? INFINITE : IO_TIMEOUT);
    if (res != WAIT_OBJECT_0)
    {
        CancelIo(pipe);
        goto out;
    }

    if (op == peek)
    {
        PeekNamedPipe(pipe, NULL, 0, NULL, &bytes, NULL);
    }
    else
    {
        GetOverlappedResult(pipe, &overlapped, &bytes, TRUE);
    }

out:
    CloseHandleEx(&io_event);
    free(handles);
    return bytes;
}

static DWORD
PeekNamedPipeAsync(HANDLE pipe, DWORD count, LPHANDLE events)
{
    return AsyncPipeOp(peek, pipe, NULL, 0, count, events);
}

static DWORD
ReadPipeAsync(HANDLE pipe, LPVOID buffer, DWORD size, DWORD count, LPHANDLE events)
{
    return AsyncPipeOp(read, pipe, buffer, size, count, events);
}

static DWORD
WritePipeAsync(HANDLE pipe, LPVOID data, DWORD size, DWORD count, LPHANDLE events)
{
    return AsyncPipeOp(write, pipe, data, size, count, events);
}

static VOID
ReturnProcessId(HANDLE pipe, DWORD pid, DWORD count, LPHANDLE events)
{
    const WCHAR msg[] = L"Process ID";
    WCHAR buf[22 + _countof(msg)]; /* 10 chars each for error and PID and 2 for line breaks */

    /*
     * Same format as error messages (3 line string) with error = 0 in
     * 0x%08x format, PID on line 2 and a description "Process ID" on line 3
     */
    swprintf(buf, _countof(buf), L"0x%08x\n0x%08x\n%ls", 0, pid, msg);

    WritePipeAsync(pipe, buf, (DWORD)(wcslen(buf) * 2), count, events);
}

static VOID
ReturnError(HANDLE pipe, DWORD error, LPCWSTR func, DWORD count, LPHANDLE events)
{
    DWORD result_len;
    LPWSTR result = L"0xffffffff\nFormatMessage failed\nCould not return result";
    DWORD_PTR args[] = {
        (DWORD_PTR) error,
        (DWORD_PTR) func,
        (DWORD_PTR) ""
    };

    if (error != ERROR_OPENVPN_STARTUP)
    {
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM
                       |FORMAT_MESSAGE_ALLOCATE_BUFFER
                       |FORMAT_MESSAGE_IGNORE_INSERTS,
                       0, error, 0, (LPWSTR) &args[2], 0, NULL);
    }

    result_len = FormatMessageW(FORMAT_MESSAGE_FROM_STRING
                                |FORMAT_MESSAGE_ALLOCATE_BUFFER
                                |FORMAT_MESSAGE_ARGUMENT_ARRAY,
                                L"0x%1!08x!\n%2!s!\n%3!s!", 0, 0,
                                (LPWSTR) &result, 0, (va_list *) args);

    WritePipeAsync(pipe, result, (DWORD)(wcslen(result) * 2), count, events);
    MsgToEventLog(MSG_FLAGS_ERROR, result);

    if (error != ERROR_OPENVPN_STARTUP)
    {
        LocalFree((LPVOID) args[2]);
    }
    if (result_len)
    {
        LocalFree(result);
    }
}


static VOID
ReturnLastError(HANDLE pipe, LPCWSTR func)
{
    ReturnError(pipe, GetLastError(), func, 1, &exit_event);
}

/*
 * Validate options against a white list. Also check the config_file is
 * inside the config_dir. The white list is defined in validate.c
 * Returns true on success, false on error with reason set in errmsg.
 */
static BOOL
ValidateOptions(HANDLE pipe, const WCHAR *workdir, const WCHAR *options, WCHAR *errmsg, DWORD capacity)
{
    WCHAR **argv;
    int argc;
    BOOL ret = FALSE;
    int i;
    const WCHAR *msg1 = L"You have specified a config file location (%ls relative to %ls)"
                        L" that requires admin approval. This error may be avoided"
                        L" by adding your account to the \"%ls\" group";

    const WCHAR *msg2 = L"You have specified an option (%ls) that may be used"
                        L" only with admin approval. This error may be avoided"
                        L" by adding your account to the \"%ls\" group";

    argv = CommandLineToArgvW(options, &argc);

    if (!argv)
    {
        swprintf(errmsg, capacity,
                 L"Cannot validate options: CommandLineToArgvW failed with error = 0x%08x",
                 GetLastError());
        goto out;
    }

    /* Note: argv[0] is the first option */
    if (argc < 1)  /* no options */
    {
        ret = TRUE;
        goto out;
    }

    /*
     * If only one argument, it is the config file
     */
    if (argc == 1)
    {
        WCHAR *argv_tmp[2] = { L"--config", argv[0] };

        if (!CheckOption(workdir, 2, argv_tmp, &settings))
        {
            swprintf(errmsg, capacity, msg1, argv[0], workdir,
                     settings.ovpn_admin_group);
        }
        goto out;
    }

    for (i = 0; i < argc; ++i)
    {
        if (!IsOption(argv[i]))
        {
            continue;
        }

        if (!CheckOption(workdir, argc-i, &argv[i], &settings))
        {
            if (wcscmp(L"--config", argv[i]) == 0 && argc-i > 1)
            {
                swprintf(errmsg, capacity, msg1, argv[i+1], workdir,
                         settings.ovpn_admin_group);
            }
            else
            {
                swprintf(errmsg, capacity, msg2, argv[i],
                         settings.ovpn_admin_group);
            }
            goto out;
        }
    }

    /* all options passed */
    ret = TRUE;

out:
    if (argv)
    {
        LocalFree(argv);
    }
    return ret;
}

static BOOL
GetStartupData(HANDLE pipe, STARTUP_DATA *sud)
{
    size_t size, len;
    WCHAR *data = NULL;
    DWORD bytes, read;

    bytes = PeekNamedPipeAsync(pipe, 1, &exit_event);
    if (bytes == 0)
    {
        MsgToEventLog(M_SYSERR, L"PeekNamedPipeAsync failed");
        ReturnLastError(pipe, L"PeekNamedPipeAsync");
        goto err;
    }

    size = bytes / sizeof(*data);
    if (size == 0)
    {
        MsgToEventLog(M_SYSERR, L"malformed startup data: 1 byte received");
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto err;
    }

    data = malloc(bytes);
    if (data == NULL)
    {
        MsgToEventLog(M_SYSERR, L"malloc failed");
        ReturnLastError(pipe, L"malloc");
        goto err;
    }

    read = ReadPipeAsync(pipe, data, bytes, 1, &exit_event);
    if (bytes != read)
    {
        MsgToEventLog(M_SYSERR, L"ReadPipeAsync failed");
        ReturnLastError(pipe, L"ReadPipeAsync");
        goto err;
    }

    if (data[size - 1] != 0)
    {
        MsgToEventLog(M_ERR, L"Startup data is not NULL terminated");
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto err;
    }

    sud->directory = data;
    len = wcslen(sud->directory) + 1;
    size -= len;
    if (size <= 0)
    {
        MsgToEventLog(M_ERR, L"Startup data ends at working directory");
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto err;
    }

    sud->options = sud->directory + len;
    len = wcslen(sud->options) + 1;
    size -= len;
    if (size <= 0)
    {
        MsgToEventLog(M_ERR, L"Startup data ends at command line options");
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto err;
    }

    sud->std_input = sud->options + len;
    return TRUE;

err:
    sud->directory = NULL;              /* caller must not free() */
    free(data);
    return FALSE;
}


static VOID
FreeStartupData(STARTUP_DATA *sud)
{
    free(sud->directory);
}


static SOCKADDR_INET
sockaddr_inet(short family, inet_address_t *addr)
{
    SOCKADDR_INET sa_inet;
    ZeroMemory(&sa_inet, sizeof(sa_inet));
    sa_inet.si_family = family;
    if (family == AF_INET)
    {
        sa_inet.Ipv4.sin_addr = addr->ipv4;
    }
    else if (family == AF_INET6)
    {
        sa_inet.Ipv6.sin6_addr = addr->ipv6;
    }
    return sa_inet;
}

static DWORD
InterfaceLuid(const char *iface_name, PNET_LUID luid)
{
    NETIO_STATUS status;
    LPWSTR wide_name = utf8to16(iface_name);

    if (wide_name)
    {
        status = ConvertInterfaceAliasToLuid(wide_name, luid);
        free(wide_name);
    }
    else
    {
        status = ERROR_OUTOFMEMORY;
    }
    return status;
}

static BOOL
CmpAddress(LPVOID item, LPVOID address)
{
    return memcmp(item, address, sizeof(MIB_UNICASTIPADDRESS_ROW)) == 0 ? TRUE : FALSE;
}

static DWORD
DeleteAddress(PMIB_UNICASTIPADDRESS_ROW addr_row)
{
    return DeleteUnicastIpAddressEntry(addr_row);
}

static DWORD
HandleAddressMessage(address_message_t *msg, undo_lists_t *lists)
{
    DWORD err;
    PMIB_UNICASTIPADDRESS_ROW addr_row;
    BOOL add = msg->header.type == msg_add_address;

    addr_row = malloc(sizeof(*addr_row));
    if (addr_row == NULL)
    {
        return ERROR_OUTOFMEMORY;
    }

    InitializeUnicastIpAddressEntry(addr_row);
    addr_row->Address = sockaddr_inet(msg->family, &msg->address);
    addr_row->OnLinkPrefixLength = (UINT8) msg->prefix_len;

    if (msg->iface.index != -1)
    {
        addr_row->InterfaceIndex = msg->iface.index;
    }
    else
    {
        NET_LUID luid;
        err = InterfaceLuid(msg->iface.name, &luid);
        if (err)
        {
            goto out;
        }
        addr_row->InterfaceLuid = luid;
    }

    if (add)
    {
        err = CreateUnicastIpAddressEntry(addr_row);
        if (err)
        {
            goto out;
        }

        err = AddListItem(&(*lists)[address], addr_row);
        if (err)
        {
            DeleteAddress(addr_row);
        }
    }
    else
    {
        err = DeleteAddress(addr_row);
        if (err)
        {
            goto out;
        }

        free(RemoveListItem(&(*lists)[address], CmpAddress, addr_row));
    }

out:
    if (!add || err)
    {
        free(addr_row);
    }

    return err;
}

static BOOL
CmpRoute(LPVOID item, LPVOID route)
{
    return memcmp(item, route, sizeof(MIB_IPFORWARD_ROW2)) == 0 ? TRUE : FALSE;
}

static DWORD
DeleteRoute(PMIB_IPFORWARD_ROW2 fwd_row)
{
    return DeleteIpForwardEntry2(fwd_row);
}

static DWORD
HandleRouteMessage(route_message_t *msg, undo_lists_t *lists)
{
    DWORD err;
    PMIB_IPFORWARD_ROW2 fwd_row;
    BOOL add = msg->header.type == msg_add_route;

    fwd_row = malloc(sizeof(*fwd_row));
    if (fwd_row == NULL)
    {
        return ERROR_OUTOFMEMORY;
    }

    ZeroMemory(fwd_row, sizeof(*fwd_row));
    fwd_row->ValidLifetime = 0xffffffff;
    fwd_row->PreferredLifetime = 0xffffffff;
    fwd_row->Protocol = MIB_IPPROTO_NETMGMT;
    fwd_row->Metric = msg->metric;
    fwd_row->DestinationPrefix.Prefix = sockaddr_inet(msg->family, &msg->prefix);
    fwd_row->DestinationPrefix.PrefixLength = (UINT8) msg->prefix_len;
    fwd_row->NextHop = sockaddr_inet(msg->family, &msg->gateway);

    if (msg->iface.index != -1)
    {
        fwd_row->InterfaceIndex = msg->iface.index;
    }
    else if (strlen(msg->iface.name))
    {
        NET_LUID luid;
        err = InterfaceLuid(msg->iface.name, &luid);
        if (err)
        {
            goto out;
        }
        fwd_row->InterfaceLuid = luid;
    }

    if (add)
    {
        err = CreateIpForwardEntry2(fwd_row);
        if (err)
        {
            goto out;
        }

        err = AddListItem(&(*lists)[route], fwd_row);
        if (err)
        {
            DeleteRoute(fwd_row);
        }
    }
    else
    {
        err = DeleteRoute(fwd_row);
        if (err)
        {
            goto out;
        }

        free(RemoveListItem(&(*lists)[route], CmpRoute, fwd_row));
    }

out:
    if (!add || err)
    {
        free(fwd_row);
    }

    return err;
}


static DWORD
HandleFlushNeighborsMessage(flush_neighbors_message_t *msg)
{
    if (msg->family == AF_INET)
    {
        return FlushIpNetTable(msg->iface.index);
    }

    return FlushIpNetTable2(msg->family, msg->iface.index);
}

static void
BlockDNSErrHandler(DWORD err, const char *msg)
{
    WCHAR buf[256];
    LPCWSTR err_str;

    if (!err)
    {
        return;
    }

    err_str = L"Unknown Win32 Error";

    if (FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM
                      | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                      NULL, err, 0, buf, sizeof(buf), NULL))
    {
        err_str = buf;
    }

    MsgToEventLog(M_ERR, L"%hs (status = %lu): %ls", msg, err, err_str);
}

/* Use an always-true match_fn to get the head of the list */
static BOOL
CmpAny(LPVOID item, LPVOID any)
{
    return TRUE;
}

static DWORD
DeleteWfpBlock(const wfp_block_message_t *msg, undo_lists_t *lists)
{
    DWORD err = 0;
    wfp_block_data_t *block_data = RemoveListItem(&(*lists)[wfp_block], CmpAny, NULL);

    if (block_data)
    {
        err = delete_wfp_block_filters(block_data->engine);
        if (block_data->metric_v4 >= 0)
        {
            set_interface_metric(msg->iface.index, AF_INET,
                                 block_data->metric_v4);
        }
        if (block_data->metric_v6 >= 0)
        {
            set_interface_metric(msg->iface.index, AF_INET6,
                                 block_data->metric_v6);
        }
        free(block_data);
    }
    else
    {
        MsgToEventLog(M_ERR, L"No previous block filters to delete");
    }

    return err;
}

static DWORD
AddWfpBlock(const wfp_block_message_t *msg, undo_lists_t *lists)
{
    DWORD err = 0;
    wfp_block_data_t *block_data = NULL;
    HANDLE engine = NULL;
    LPCWSTR exe_path;
    BOOL dns_only;

    exe_path = settings.exe_path;
    dns_only = (msg->flags == wfp_block_dns);

    err = add_wfp_block_filters(&engine, msg->iface.index, exe_path, BlockDNSErrHandler, dns_only);
    if (!err)
    {
        block_data = malloc(sizeof(wfp_block_data_t));
        if (!block_data)
        {
            err = ERROR_OUTOFMEMORY;
            goto out;
        }
        block_data->engine = engine;
        block_data->index = msg->iface.index;
        int is_auto = 0;
        block_data->metric_v4 = get_interface_metric(msg->iface.index,
                                                     AF_INET, &is_auto);
        if (is_auto)
        {
            block_data->metric_v4 = 0;
        }
        block_data->metric_v6 = get_interface_metric(msg->iface.index,
                                                     AF_INET6, &is_auto);
        if (is_auto)
        {
            block_data->metric_v6 = 0;
        }

        err = AddListItem(&(*lists)[wfp_block], block_data);
        if (!err)
        {
            err = set_interface_metric(msg->iface.index, AF_INET,
                                       WFP_BLOCK_IFACE_METRIC);
            if (!err)
            {
                /* for IPv6, we intentionally ignore errors, because
                 * otherwise block-dns activation will fail if a user or
                 * admin has disabled IPv6 on the tun/tap/dco interface
                 * (if OpenVPN wants IPv6 ifconfig, we'll fail there)
                 */
                set_interface_metric(msg->iface.index, AF_INET6,
                                     WFP_BLOCK_IFACE_METRIC);
            }
            if (err)
            {
                /* delete the filters, remove undo item and free interface data */
                DeleteWfpBlock(msg, lists);
                engine = NULL;
            }
        }
    }

out:
    if (err && engine)
    {
        delete_wfp_block_filters(engine);
        free(block_data);
    }

    return err;
}

static DWORD
HandleWfpBlockMessage(const wfp_block_message_t *msg, undo_lists_t *lists)
{
    if (msg->header.type == msg_add_wfp_block)
    {
        return AddWfpBlock(msg, lists);
    }
    else
    {
        return DeleteWfpBlock(msg, lists);
    }
}

/*
 * Execute a command and return its exit code. If timeout > 0, terminate
 * the process if still running after timeout milliseconds. In that case
 * the return value is the windows error code WAIT_TIMEOUT = 0x102
 */
static DWORD
ExecCommand(const WCHAR *argv0, const WCHAR *cmdline, DWORD timeout)
{
    DWORD exit_code;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD proc_flags = CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT;
    WCHAR *cmdline_dup = NULL;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

    /* CreateProcess needs a modifiable cmdline: make a copy */
    cmdline_dup = _wcsdup(cmdline);
    if (cmdline_dup && CreateProcessW(argv0, cmdline_dup, NULL, NULL, FALSE,
                                      proc_flags, NULL, NULL, &si, &pi) )
    {
        WaitForSingleObject(pi.hProcess, timeout ? timeout : INFINITE);
        if (!GetExitCodeProcess(pi.hProcess, &exit_code))
        {
            MsgToEventLog(M_SYSERR, L"ExecCommand: Error getting exit_code:");
            exit_code = GetLastError();
        }
        else if (exit_code == STILL_ACTIVE)
        {
            exit_code = WAIT_TIMEOUT; /* Windows error code 0x102 */

            /* kill without impunity */
            TerminateProcess(pi.hProcess, exit_code);
            MsgToEventLog(M_ERR, L"ExecCommand: \"%ls %ls\" killed after timeout",
                          argv0, cmdline);
        }
        else if (exit_code)
        {
            MsgToEventLog(M_ERR, L"ExecCommand: \"%ls %ls\" exited with status = %lu",
                          argv0, cmdline, exit_code);
        }
        else
        {
            MsgToEventLog(M_INFO, L"ExecCommand: \"%ls %ls\" completed", argv0, cmdline);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        exit_code = GetLastError();
        MsgToEventLog(M_SYSERR, L"ExecCommand: could not run \"%ls %ls\" :",
                      argv0, cmdline);
    }

    free(cmdline_dup);
    return exit_code;
}

/*
 * Entry point for register-dns thread.
 */
static DWORD WINAPI
RegisterDNS(LPVOID unused)
{
    DWORD err;
    size_t i;
    DWORD timeout = RDNS_TIMEOUT * 1000; /* in milliseconds */

    /* path of ipconfig command */
    WCHAR ipcfg[MAX_PATH];

    struct
    {
        WCHAR *argv0;
        WCHAR *cmdline;
        DWORD timeout;
    } cmds [] = {
        { ipcfg, L"ipconfig /flushdns",    timeout },
        { ipcfg, L"ipconfig /registerdns", timeout },
    };

    HANDLE wait_handles[2] = {rdns_semaphore, exit_event};

    swprintf(ipcfg, MAX_PATH, L"%ls\\%ls", get_win_sys_path(), L"ipconfig.exe");

    if (WaitForMultipleObjects(2, wait_handles, FALSE, timeout) == WAIT_OBJECT_0)
    {
        /* Semaphore locked */
        for (i = 0; i < _countof(cmds); ++i)
        {
            ExecCommand(cmds[i].argv0, cmds[i].cmdline, cmds[i].timeout);
        }
        err = 0;
        if (!ReleaseSemaphore(rdns_semaphore, 1, NULL) )
        {
            err = MsgToEventLog(M_SYSERR, L"RegisterDNS: Failed to release regsiter-dns semaphore:");
        }
    }
    else
    {
        MsgToEventLog(M_ERR, L"RegisterDNS: Failed to lock register-dns semaphore");
        err = ERROR_SEM_TIMEOUT; /* Windows error code 0x79 */
    }
    return err;
}

static DWORD
HandleRegisterDNSMessage(void)
{
    DWORD err;
    HANDLE thread = NULL;

    /* Delegate this job to a sub-thread */
    thread = CreateThread(NULL, 0, RegisterDNS, NULL, 0, NULL);

    /*
     * We don't add these thread handles to the undo list -- the thread and
     * processes it spawns are all supposed to terminate or timeout by themselves.
     */
    if (thread)
    {
        err = 0;
        CloseHandle(thread);
    }
    else
    {
        err = GetLastError();
    }

    return err;
}

/**
 * Run the command: netsh interface ip $action wins $if_name [static] $addr
 * @param  action      "delete", "add" or "set"
 * @param  if_name     "name_of_interface"
 * @param  addr        IPv4 address as a string
 *
 * If addr is null and action = "delete" all addresses are deleted.
 * if action = "set" then "static" is added before $addr
 */
static DWORD
netsh_wins_cmd(const wchar_t *action, const wchar_t *if_name, const wchar_t *addr)
{
    DWORD err = 0;
    int timeout = 30000; /* in msec */
    wchar_t argv0[MAX_PATH];
    wchar_t *cmdline = NULL;
    const wchar_t *addr_static = (wcscmp(action, L"set") == 0) ? L"static" : L"";

    if (!addr)
    {
        if (wcscmp(action, L"delete") == 0)
        {
            addr = L"all";
        }
        else /* nothing to do -- return success*/
        {
            goto out;
        }
    }

    /* Path of netsh */
    swprintf(argv0, _countof(argv0), L"%ls\\%ls", get_win_sys_path(), L"netsh.exe");

    /* cmd template:
     * netsh interface ip $action wins $if_name $static $addr
     */
    const wchar_t *fmt = L"netsh interface ip %ls wins \"%ls\" %ls %ls";

    /* max cmdline length in wchars -- include room for worst case and some */
    size_t ncmdline = wcslen(fmt) + wcslen(if_name) + wcslen(action) + wcslen(addr)
                      +wcslen(addr_static) + 32 + 1;
    cmdline = malloc(ncmdline * sizeof(wchar_t));
    if (!cmdline)
    {
        err = ERROR_OUTOFMEMORY;
        goto out;
    }

    swprintf(cmdline, ncmdline, fmt, action, if_name, addr_static, addr);

    err = ExecCommand(argv0, cmdline, timeout);

out:
    free(cmdline);
    return err;
}

static BOOL
CmpWString(LPVOID item, LPVOID str)
{
    return (wcscmp(item, str) == 0) ? TRUE : FALSE;
}

/**
 * Signal the DNS resolver (and others potentially) to reload the
 * group policy (DNS) settings on 32 bit Windows systems
 *
 * @return BOOL to indicate if the reload was initiated
 */
static BOOL
ApplyGpolSettings32(void)
{
    typedef NTSTATUS (__stdcall *publish_fn_t)(
        DWORD StateNameLo,
        DWORD StateNameHi,
        DWORD TypeId,
        DWORD Buffer,
        DWORD Length,
        DWORD ExplicitScope);
    publish_fn_t RtlPublishWnfStateData;
    const DWORD WNF_GPOL_SYSTEM_CHANGES_HI = 0x0D891E2A;
    const DWORD WNF_GPOL_SYSTEM_CHANGES_LO = 0xA3BC0875;

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll == NULL)
    {
        return FALSE;
    }

    RtlPublishWnfStateData = (publish_fn_t) GetProcAddress(ntdll, "RtlPublishWnfStateData");
    if (RtlPublishWnfStateData == NULL)
    {
        return FALSE;
    }

    if (RtlPublishWnfStateData(WNF_GPOL_SYSTEM_CHANGES_LO, WNF_GPOL_SYSTEM_CHANGES_HI, 0, 0, 0, 0) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * Signal the DNS resolver (and others potentially) to reload the
 * group policy (DNS) settings on 64 bit Windows systems
 *
 * @return BOOL to indicate if the reload was initiated
 */
static BOOL
ApplyGpolSettings64(void)
{
    typedef NTSTATUS (*publish_fn_t)(
        INT64 StateName,
        INT64 TypeId,
        INT64 Buffer,
        unsigned int Length,
        INT64 ExplicitScope);
    publish_fn_t RtlPublishWnfStateData;
    const INT64 WNF_GPOL_SYSTEM_CHANGES = 0x0D891E2AA3BC0875;

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll == NULL)
    {
        return FALSE;
    }

    RtlPublishWnfStateData = (publish_fn_t) GetProcAddress(ntdll, "RtlPublishWnfStateData");
    if (RtlPublishWnfStateData == NULL)
    {
        return FALSE;
    }

    if (RtlPublishWnfStateData(WNF_GPOL_SYSTEM_CHANGES, 0, 0, 0, 0) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * Signal the DNS resolver (and others potentially) to reload the group policy (DNS) settings
 *
 * @return BOOL to indicate if the reload was initiated
 */
static BOOL
ApplyGpolSettings(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const BOOL win_32bit = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL;
    return win_32bit ? ApplyGpolSettings32() : ApplyGpolSettings64();
}

/**
 * Signal the DNS resolver to reload its settings
 *
 * @param apply_gpol    BOOL reload setting from group policy hives as well
 *
 * @return BOOL to indicate if the reload was initiated
 */
static BOOL
ApplyDnsSettings(BOOL apply_gpol)
{
    BOOL res = FALSE;
    SC_HANDLE scm = NULL;
    SC_HANDLE dnssvc = NULL;

    if (apply_gpol && ApplyGpolSettings() == FALSE)
    {
        MsgToEventLog(M_ERR, L"%S: sending GPOL notification failed", __func__);
    }

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL)
    {
        MsgToEventLog(M_ERR, L"%S: OpenSCManager call failed (%lu)",
                      __func__, GetLastError());
        goto out;
    }

    dnssvc = OpenServiceA(scm, "Dnscache", SERVICE_PAUSE_CONTINUE);
    if (dnssvc == NULL)
    {
        MsgToEventLog(M_ERR, L"%S: OpenService call failed (%lu)",
                      __func__, GetLastError());
        goto out;
    }

    SERVICE_STATUS status;
    if (ControlService(dnssvc, SERVICE_CONTROL_PARAMCHANGE, &status) == 0)
    {
        MsgToEventLog(M_ERR, L"%S: ControlService call failed (%lu)",
                      __func__, GetLastError());
        goto out;
    }

    res = TRUE;

out:
    if (dnssvc)
    {
        CloseServiceHandle(dnssvc);
    }
    if (scm)
    {
        CloseServiceHandle(scm);
    }
    return res;
}

/**
 * Get the string interface UUID (with braces) for an interface alias name
 *
 * @param  itf_name   the interface alias name
 * @param  str        pointer to the buffer the wide UUID is returned in
 * @param  len        size of the str buffer in characters
 *
 * @return NO_ERROR on success, or the Windows error code for the failure
 */
static DWORD
InterfaceIdString(PCSTR itf_name, PWSTR str, size_t len)
{
    DWORD err;
    GUID guid;
    NET_LUID luid;
    PWSTR iid_str = NULL;

    err = InterfaceLuid(itf_name, &luid);
    if (err)
    {
        MsgToEventLog(M_ERR, L"%S: failed to convert itf alias '%s'", __func__, itf_name);
        goto out;
    }
    err = ConvertInterfaceLuidToGuid(&luid, &guid);
    if (err)
    {
        MsgToEventLog(M_ERR, L"%S: Failed to convert itf '%s' LUID", __func__, itf_name);
        goto out;
    }

    if (StringFromIID(&guid, &iid_str) != S_OK)
    {
        MsgToEventLog(M_ERR, L"%S: Failed to convert itf '%s' IID", __func__, itf_name);
        err = ERROR_OUTOFMEMORY;
        goto out;
    }
    if (wcslen(iid_str) + 1 > len)
    {
        err = ERROR_INVALID_PARAMETER;
        goto out;
    }

    wcsncpy(str, iid_str, len);

out:
    if (iid_str)
    {
        CoTaskMemFree(iid_str);
    }
    return err;
}

/**
 * Check for a valid search list in a certain key of the registry
 *
 * Valid means that a string value "SearchList" exists and that it
 * contains one or more domains. We only check if the string contains
 * a valid domain name character, but the main point is to prevent letting
 * pass whitespace-only lists, so that check is good enough for that
 * purpose.
 *
 * @param  key  HKEY in which to check for a valid search list
 *
 * @return BOOL to indicate if a valid search list has been found
 */
static BOOL
HasValidSearchList(HKEY key)
{
    char data[64];
    DWORD size = sizeof(data);
    LSTATUS err = RegGetValueA(key, NULL, "SearchList", RRF_RT_REG_SZ, NULL, (PBYTE)data, &size);
    if (!err || err == ERROR_MORE_DATA)
    {
        data[sizeof(data) - 1] = '\0';
        for (int i = 0; i < strlen(data); ++i)
        {
            if (isalnum(data[i]) || data[i] == '-' || data[i] == '.')
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/**
 * Find the registry key for storing the DNS domains for the VPN interface
 *
 * @param  itf_name PCSTR that contains the alias name of the interface the domains
 *                  are related to. If this is NULL the interface probing is skipped.
 * @param  gpol     PBOOL to indicate if the key returned is the group policy hive
 * @param  key      PHKEY in which the found registry key is returned in
 *
 * @return BOOL to indicate if a search list is already present at the location.
 *         If the key returned is INVALID_HANDLE_VALUE, this indicates an
 *         unrecoverable error.
 *
 * The correct location to add them is where a non-empty "SearchList" value exists,
 * or in the interface configuration itself. However, the system-wide and then the
 * group policy search lists overrule the previous one respectively, so we need to
 * probe to find the effective list.
 */
static BOOL
GetDnsSearchListKey(PCSTR itf_name, PBOOL gpol, PHKEY key)
{
    LSTATUS err;

    *gpol = FALSE;

    /* Try the group policy search list */
    err = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                        0, KEY_ALL_ACCESS, key);
    if (!err)
    {
        if (HasValidSearchList(*key))
        {
            *gpol = TRUE;
            return TRUE;
        }
        RegCloseKey(*key);
    }

    /* Try the system-wide search list */
    err = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                        "System\\CurrentControlSet\\Services\\TCPIP\\Parameters",
                        0, KEY_ALL_ACCESS, key);
    if (!err)
    {
        if (HasValidSearchList(*key))
        {
            return TRUE;
        }
        RegCloseKey(*key);
    }

    if (itf_name)
    {
        /* Always return the VPN interface key (if it exists) */
        WCHAR iid[64];
        DWORD iid_err = InterfaceIdString(itf_name, iid, _countof(iid));
        if (!iid_err)
        {
            HKEY itfs;
            err = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                "System\\CurrentControlSet\\Services\\TCPIP\\Parameters\\Interfaces",
                                0, KEY_ALL_ACCESS, &itfs);
            if (!err)
            {
                err = RegOpenKeyExW(itfs, iid, 0, KEY_ALL_ACCESS, key);
                RegCloseKey(itfs);
                if (!err)
                {
                    return FALSE; /* No need to preserve the VPN itf search list */
                }
            }
        }
    }

    *key = INVALID_HANDLE_VALUE;
    return FALSE;
}

/**
 * Check if a initial list had already been created
 *
 * @param  key      HKEY of the registry subkey to search in
 *
 * @return BOOL to indicate if the initial list is already present under key
 */
static BOOL
InitialSearchListExists(HKEY key)
{
    LSTATUS err;

    err = RegGetValueA(key, NULL, "InitialSearchList", RRF_RT_REG_SZ, NULL, NULL, NULL);
    if (err)
    {
        if (err == ERROR_FILE_NOT_FOUND)
        {
            return FALSE;
        }
        MsgToEventLog(M_ERR, L"%S: failed to get InitialSearchList (%lu)",
                      __func__, err);
    }

    return TRUE;
}

/**
 * Prepare DNS domain "SearchList" registry value, so additional
 * VPN domains can be added and its original state can be restored
 * in case the system cannot clean up regularly.
 *
 * @param  key      registry subkey to store the list in
 * @param  list     string of comma separated domains to use as the list
 *
 * @return boolean to indicate whether the list was stored successfully
 */
static BOOL
StoreInitialDnsSearchList(HKEY key, PCWSTR list)
{
    if (!list || wcslen(list) == 0)
    {
        MsgToEventLog(M_ERR, L"%S: empty search list", __func__);
        return FALSE;
    }

    if (InitialSearchListExists(key))
    {
        /* Initial list had already been stored */
        return TRUE;
    }

    DWORD size = (wcslen(list) + 1) * sizeof(*list);
    LSTATUS err = RegSetValueExW(key, L"InitialSearchList", 0, REG_SZ, (PBYTE)list, size);
    if (err)
    {
        MsgToEventLog(M_ERR, L"%S: failed to set InitialSearchList value (%lu)",
                      __func__, err);
        return FALSE;
    }

    return TRUE;
}

/**
 * Append domain suffixes to an existing search list
 *
 * @param  key          HKEY the list is stored at
 * @param  have_list    BOOL to indicate if a search list already exists
 * @param  domains      domain suffixes as comma separated string
 *
 * @return BOOL to indicate success or failure
 */
static BOOL
AddDnsSearchDomains(HKEY key, BOOL have_list, PCWSTR domains)
{
    LSTATUS err;
    WCHAR list[2048] = {0};
    DWORD size = sizeof(list);

    if (have_list)
    {
        err = RegGetValueW(key, NULL, L"SearchList", RRF_RT_REG_SZ, NULL, list, &size);
        if (err)
        {
            MsgToEventLog(M_SYSERR, L"%S: could not get SearchList from registry (%lu)",
                          __func__, err);
            return FALSE;
        }

        if (!StoreInitialDnsSearchList(key, list))
        {
            return FALSE;
        }

        size_t listlen = (size / sizeof(list[0])) - 1; /* returned size is in bytes */
        size_t domlen = wcslen(domains);
        if (listlen + domlen + 2 > _countof(list))
        {
            MsgToEventLog(M_SYSERR, L"%S: not enough space in list for search domains (len=%lu)",
                          __func__, domlen);
            return FALSE;
        }

        /* Append to end of the search list */
        PWSTR pos = list + listlen;
        *pos = ',';
        wcsncpy(pos + 1, domains, domlen + 1);
    }
    else
    {
        wcsncpy(list, domains, wcslen(domains) + 1);
    }

    size = (wcslen(list) + 1) * sizeof(list[0]);
    err = RegSetValueExW(key, L"SearchList", 0, REG_SZ, (PBYTE)list, size);
    if (err)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not set SearchList to registry (%lu)",
                      __func__, err);
        return FALSE;
    }

    return TRUE;
}

/**
 * Reset the DNS search list to its original value
 *
 * Looks for a "InitialSearchList" value as the one to reset to.
 * If it doesn't exist, doesn't reset anything, as there was no
 * SearchList in the first place.
 *
 * @param  key  HKEY of the location in the registry to reset
 *
 * @return BOOL to indicate if something was reset
 */
static BOOL
ResetDnsSearchDomains(HKEY key)
{
    LSTATUS err;
    BOOL ret = FALSE;
    WCHAR list[2048];
    DWORD size = sizeof(list);

    err = RegGetValueW(key, NULL, L"InitialSearchList", RRF_RT_REG_SZ, NULL, list, &size);
    if (err)
    {
        if (err != ERROR_FILE_NOT_FOUND)
        {
            MsgToEventLog(M_SYSERR, L"%S: could not get InitialSearchList from registry (%lu)",
                          __func__, err);
        }
        goto out;
    }

    size = (wcslen(list) + 1) * sizeof(list[0]);
    err = RegSetValueExW(key, L"SearchList", 0, REG_SZ, (PBYTE)list, size);
    if (err)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not set SearchList in registry (%lu)",
                      __func__, err);
        goto out;
    }

    RegDeleteValueA(key, "InitialSearchList");
    ret = TRUE;

out:
    return ret;
}

/**
 * Remove domain suffixes from an existing search list
 *
 * @param  key      HKEY the list is stored at
 * @param  domains  domain suffixes to remove as comma separated string
 */
static void
RemoveDnsSearchDomains(HKEY key, PCWSTR domains)
{
    LSTATUS err;
    WCHAR list[2048];
    DWORD size = sizeof(list);

    err = RegGetValueW(key, NULL, L"SearchList", RRF_RT_REG_SZ, NULL, list, &size);
    if (err)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not get SearchList from registry (%lu)",
                      __func__, err);
        return;
    }

    PWSTR dst = wcsstr(list, domains);
    if (!dst)
    {
        MsgToEventLog(M_ERR, L"%S: could not find domains in search list", __func__);
        return;
    }

    /* Cut out domains from list */
    size_t domlen = wcslen(domains);
    PCWSTR src = dst + domlen;
    /* Also remove the leading comma, if there is one */
    dst = dst > list ? dst - 1 : dst;
    wmemmove(dst, src, domlen);

    size_t list_len = wcslen(list);
    if (list_len)
    {
        /* Now check if the shortened list equals the initial search list */
        WCHAR initial[2048];
        size = sizeof(initial);
        err = RegGetValueW(key, NULL, L"InitialSearchList", RRF_RT_REG_SZ, NULL, initial, &size);
        if (err)
        {
            MsgToEventLog(M_SYSERR, L"%S: could not get InitialSearchList from registry (%lu)",
                          __func__, err);
            return;
        }

        /* If the search list is back to its initial state reset it */
        if (wcsncmp(list, initial, wcslen(list)) == 0)
        {
            ResetDnsSearchDomains(key);
            return;
        }
    }

    size = (list_len + 1) * sizeof(list[0]);
    err = RegSetValueExW(key, L"SearchList", 0, REG_SZ, (PBYTE)list, size);
    if (err)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not set SearchList in registry (%lu)",
                      __func__, err);
    }
}

/**
 * Removes DNS domains from a search list they were previously added to
 *
 * @param undo_data     pointer to dns_domains_undo_data_t
 */
static void
UndoDnsSearchDomains(dns_domains_undo_data_t *undo_data)
{
    BOOL gpol;
    HKEY dns_searchlist_key;
    GetDnsSearchListKey(undo_data->itf_name, &gpol, &dns_searchlist_key);
    if (dns_searchlist_key != INVALID_HANDLE_VALUE)
    {
        RemoveDnsSearchDomains(dns_searchlist_key, undo_data->domains);
        RegCloseKey(dns_searchlist_key);
        ApplyDnsSettings(gpol);

        free(undo_data->domains);
        undo_data->domains = NULL;
    }
}

/**
 * Add or remove DNS search domains
 *
 * @param  itf_name   alias name of the interface the domains are set for
 * @param  domains    a comma separated list of domain name suffixes
 * @param  gpol       PBOOL to indicate if group policy values were modified
 * @param  lists      pointer to the undo lists
 *
 * @return NO_ERROR on success, an error status code otherwise
 *
 * If a SearchList is present in the registry already, the domains are added
 * to that list. Otherwise the domains are added to the VPN interface specific list.
 * A group policy search list takes precedence over a system-wide list, and that one
 * itself takes precedence over interface specific ones.
 *
 * This function will remove previously set domains if the domains parameter
 * is NULL or empty.
 *
 * The gpol value is only valid if the function returns no error. In the error
 * case nothing is changed.
 */
static DWORD
SetDnsSearchDomains(PCSTR itf_name, PCSTR domains, PBOOL gpol, undo_lists_t *lists)
{
    DWORD err = ERROR_OUTOFMEMORY;

    HKEY list_key;
    BOOL have_list = GetDnsSearchListKey(itf_name, gpol, &list_key);
    if (list_key == INVALID_HANDLE_VALUE)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not get search list registry key", __func__);
        return ERROR_FILE_NOT_FOUND;
    }

    /* Remove previously installed search domains */
    dns_domains_undo_data_t *undo_data = RemoveListItem(&(*lists)[undo_domains], CmpAny, NULL);
    if (undo_data)
    {
        RemoveDnsSearchDomains(list_key, undo_data->domains);
        free(undo_data->domains);
        free(undo_data);
        undo_data = NULL;
    }

    /* If there are search domains, add them */
    if (domains && *domains)
    {
        wchar_t *wide_domains = utf8to16(domains); /* utf8 to wide-char */
        if (!wide_domains)
        {
            goto out;
        }

        undo_data = malloc(sizeof(*undo_data));
        if (!undo_data)
        {
            free(wide_domains);
            wide_domains = NULL;
            goto out;
        }
        strncpy(undo_data->itf_name, itf_name, sizeof(undo_data->itf_name));
        undo_data->domains = wide_domains;

        if (AddDnsSearchDomains(list_key, have_list, wide_domains) == FALSE
            || AddListItem(&(*lists)[undo_domains], undo_data) != NO_ERROR)
        {
            RemoveDnsSearchDomains(list_key, wide_domains);
            free(wide_domains);
            free(undo_data);
            undo_data = NULL;
            goto out;
        }
    }

    err = NO_ERROR;

out:
    RegCloseKey(list_key);
    return err;
}

/**
 * Return the interfaces registry key for the specified address family
 *
 * @param family    the internet address family to open the key for
 * @param key       PHKEY to return the key in
 * @return BOOL to indicate success or failure
 */
static BOOL
GetInterfacesKey(short family, PHKEY key)
{
    PCSTR itfs_key = family == AF_INET6
        ? "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces"
        : "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";

    LSTATUS err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, itfs_key, 0, KEY_ALL_ACCESS, key);
    if (err)
    {
        *key = INVALID_HANDLE_VALUE;
        MsgToEventLog(M_SYSERR, L"%S: could not open interfaces registry key for family %d (%lu)",
                      __func__, family, err);
    }

    return err ? FALSE : TRUE;
}

/**
 * Set the DNS name servers in a registry interface configuration
 *
 * @param itf_id    the interface id to set the servers for
 * @param family    internet address family to set the servers for
 * @param value     the value to set the name servers to
 *
 * @return DWORD NO_ERROR on success, a Windows error code otherwise
 */
static DWORD
SetNameServersValue(PCWSTR itf_id, short family, PCSTR value)
{
    DWORD err;

    HKEY itfs;
    if (!GetInterfacesKey(family, &itfs))
    {
        return ERROR_FILE_NOT_FOUND;
    }

    HKEY itf = INVALID_HANDLE_VALUE;
    err = RegOpenKeyExW(itfs, itf_id, 0, KEY_ALL_ACCESS, &itf);
    if (err)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not open interface key for %s family %d (%lu)",
                      __func__, itf_id, family, err);
        goto out;
    }

    err = RegSetValueExA(itf, "NameServer", 0, REG_SZ, (PBYTE)value, strlen(value) + 1);
    if (err)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not set name servers '%S' for %s family %d (%lu)",
                      __func__, value, itf_id, family, err);
    }

out:
    if (itf != INVALID_HANDLE_VALUE)
    {
        RegCloseKey(itf);
    }
    if (itfs != INVALID_HANDLE_VALUE)
    {
        RegCloseKey(itfs);
    }
    return err;
}

/**
 * Set the DNS name servers in a registry interface configuration
 *
 * @param itf_id    the interface id to set the servers for
 * @param family    internet address family to set the servers for
 * @param addrs     comma separated list of name server addresses
 *
 * @return DWORD NO_ERROR on success, a Windows error code otherwise
 */
static DWORD
SetNameServers(PCWSTR itf_id, short family, PCSTR addrs)
{
    return SetNameServersValue(itf_id, family, addrs);
}

/**
 * Delete all DNS name servers from a registry interface configuration
 *
 * @param itf_id    the interface id to clear the servers for
 * @param family    internet address family to clear the servers for
 *
 * @return DWORD NO_ERROR on success, a Windows error code otherwise
 */
static DWORD
ResetNameServers(PCWSTR itf_id, short family)
{
    return SetNameServersValue(itf_id, family, "");
}

static DWORD
HandleDNSConfigMessage(const dns_cfg_message_t *msg, undo_lists_t *lists)
{
    DWORD err = 0;
    undo_type_t undo_type = (msg->family == AF_INET6) ? undo_dns4 : undo_dns6;
    int addr_len = msg->addr_len;

    /* sanity check */
    const size_t max_addrs = _countof(msg->addr);
    if (addr_len > max_addrs)
    {
        addr_len = max_addrs;
    }

    if (!msg->iface.name[0]) /* interface name is required */
    {
        return ERROR_MESSAGE_DATA;
    }

    /* use a non-const reference with limited scope to enforce null-termination of strings from client */
    {
        dns_cfg_message_t *msgptr = (dns_cfg_message_t *) msg;
        msgptr->iface.name[_countof(msg->iface.name)-1] = '\0';
        msgptr->domains[_countof(msg->domains)-1] = '\0';
    }

    WCHAR iid[64];
    err = InterfaceIdString(msg->iface.name, iid, _countof(iid));
    if (err)
    {
        return err;
    }

    /* We delete all current addresses before adding any
     * OR if the message type is del_dns_cfg
     */
    if (addr_len > 0 || msg->header.type == msg_del_dns_cfg)
    {
        err = ResetNameServers(iid, msg->family);
        if (err)
        {
            return err;
        }
        free(RemoveListItem(&(*lists)[undo_type], CmpAny, iid));
    }

    if (msg->header.type == msg_del_dns_cfg)
    {
        BOOL gpol = FALSE;
        if (msg->domains[0])
        {
            /* setting an empty domain list removes any previous value */
            err = SetDnsSearchDomains(msg->iface.name, NULL, &gpol, lists);
        }
        ApplyDnsSettings(gpol);
        return err;  /* job done */
    }

    if (msg->addr_len > 0)
    {
        /* prepare the comma separated address list */
        /* cannot use max_addrs here as that is not considered compile
         * time constant by all compilers and constexpr is C23 */
        CHAR addrs[_countof(msg->addr) * 64]; /* 64 is enough for one IPv4/6 address */
        size_t offset = 0;
        for (int i = 0; i < addr_len; ++i)
        {
            if (i != 0)
            {
                addrs[offset++] = ',';
            }
            if (msg->family == AF_INET6)
            {
                RtlIpv6AddressToStringA(&msg->addr[i].ipv6, addrs + offset);
            }
            else
            {
                RtlIpv4AddressToStringA(&msg->addr[i].ipv4, addrs + offset);
            }
            offset += strlen(addrs);
        }

        err = SetNameServers(iid, msg->family, addrs);
        if (err)
        {
            return err;
        }

        wchar_t *tmp_iid = _wcsdup(iid);
        if (!tmp_iid || AddListItem(&(*lists)[undo_type], tmp_iid))
        {
            free(tmp_iid);
            ResetNameServers(iid, msg->family);
            return ERROR_OUTOFMEMORY;
        }
    }

    BOOL gpol = FALSE;
    if (msg->domains[0])
    {
        err = SetDnsSearchDomains(msg->iface.name, msg->domains, &gpol, lists);
    }
    ApplyDnsSettings(gpol);

    return err;
}

/**
 * Checks if DHCP is enabled for an interface
 *
 * @param  key        HKEY of the interface to check for
 *
 * @return BOOL set to TRUE if DHCP is enabled, or FALSE if
 *         disabled or an error occurred
 */
static BOOL
IsDhcpEnabled(HKEY key)
{
    DWORD dhcp;
    DWORD size = sizeof(dhcp);
    LSTATUS err;

    err = RegGetValueA(key, NULL, "EnableDHCP", RRF_RT_REG_DWORD, NULL, (PBYTE)&dhcp, &size);
    if (err != NO_ERROR)
    {
        MsgToEventLog(M_SYSERR, L"%S: Could not read DHCP status (%lu)", __func__, err);
        return FALSE;
    }

    return dhcp ? TRUE : FALSE;
}

/**
 * Set name servers from a NRPT address list
 *
 * @param itf_id        the VPN interface ID to set the name servers for
 * @param addresses     the list of NRPT addresses
 *
 * @return LSTATUS NO_ERROR in case of success, a Windows error code otherwise
 */
static LSTATUS
SetNameServerAddresses(PWSTR itf_id, const nrpt_address_t *addresses)
{
    const short families[] = { AF_INET, AF_INET6 };
    for (int i = 0; i < _countof(families); i++)
    {
        short family = families[i];

        /* Create a comma sparated list of addresses of this family */
        int offset = 0;
        char addr_list[NRPT_ADDR_SIZE * NRPT_ADDR_NUM];
        for (int j = 0; j < NRPT_ADDR_NUM && addresses[j][0]; j++)
        {
            if ((family == AF_INET6 && strchr(addresses[j], ':') == NULL)
                || (family == AF_INET && strchr(addresses[j], ':') != NULL))
            {
                /* Address family doesn't match, skip this one */
                continue;
            }
            if (offset)
            {
                addr_list[offset++] = ',';
            }
            strcpy(addr_list + offset, addresses[j]);
            offset += strlen(addresses[j]);
        }

        if (offset == 0)
        {
            /* No address for this family to set */
            continue;
        }

        /* Set name server addresses */
        LSTATUS err = SetNameServers(itf_id, family, addr_list);
        if (err)
        {
            return err;
        }
    }
    return NO_ERROR;
}

/**
 * Get DNS server IPv4 addresses of an interface
 *
 * @param  itf_key    registry key of the IPv4 interface data
 * @param  addrs      pointer to the buffer addresses are returned in
 * @param  size       pointer to the size of the buffer, contains the
 *                    size of the addresses on return
 *
 * @return LSTATUS NO_ERROR on success, a Windows error code otherwise
 */
static LSTATUS
GetItfDnsServersV4(HKEY itf_key, PSTR addrs, PDWORD size)
{
    addrs[*size - 1] = '\0';

    LSTATUS err;
    DWORD s = *size;
    err = RegGetValueA(itf_key, NULL, "NameServer", RRF_RT_REG_SZ, NULL, (PBYTE)addrs, &s);
    if (err && err != ERROR_FILE_NOT_FOUND)
    {
        *size = 0;
        return err;
    }

    /* Try DHCP addresses if we don't have some already */
    if (!strchr(addrs, '.') && IsDhcpEnabled(itf_key))
    {
        s = *size;
        RegGetValueA(itf_key, NULL, "DhcpNameServer", RRF_RT_REG_SZ, NULL, (PBYTE)addrs, &s);
        if (err)
        {
            *size = 0;
            return err;
        }
    }

    if (strchr(addrs, '.'))
    {
        *size = s;
        return NO_ERROR;
    }

    *size = 0;
    return ERROR_FILE_NOT_FOUND;
}

/**
 * Get DNS server IPv6 addresses of an interface
 *
 * @param  itf_key    registry key of the IPv6 interface data
 * @param  addrs      pointer to the buffer addresses are returned in
 * @param  size       pointer to the size of the buffer
 *
 * @return LSTATUS NO_ERROR on success, a Windows error code otherwise
 */
static LSTATUS
GetItfDnsServersV6(HKEY itf_key, PSTR addrs, PDWORD size)
{
    addrs[*size - 1] = '\0';

    LSTATUS err;
    DWORD s = *size;
    err = RegGetValueA(itf_key, NULL, "NameServer", RRF_RT_REG_SZ, NULL, (PBYTE)addrs, &s);
    if (err && err != ERROR_FILE_NOT_FOUND)
    {
        *size = 0;
        return err;
    }

    /* Try DHCP addresses if we don't have some already */
    if (!strchr(addrs, ':') && IsDhcpEnabled(itf_key))
    {
        IN6_ADDR in_addrs[8];
        DWORD in_addrs_size = sizeof(in_addrs);
        err = RegGetValueA(itf_key, NULL, "Dhcpv6DNSServers", RRF_RT_REG_BINARY, NULL,
                           (PBYTE)in_addrs, &in_addrs_size);
        if (err)
        {
            *size = 0;
            return err;
        }

        s = *size;
        PSTR pos = addrs;
        size_t in_addrs_read = in_addrs_size / sizeof(IN6_ADDR);
        for (size_t i = 0; i < in_addrs_read; ++i)
        {
            if (i != 0)
            {
                /* Add separator */
                *pos++ = ',';
                s--;
            }

            if (inet_ntop(AF_INET6, &in_addrs[i],
                          pos, s) != NULL)
            {
                *size = 0;
                return ERROR_MORE_DATA;
            }

            size_t addr_len = strlen(pos);
            pos += addr_len;
            s -= addr_len;
        }
        s = strlen(addrs) + 1;
    }

    if (strchr(addrs, ':'))
    {
        *size = s;
        return NO_ERROR;
    }

    *size = 0;
    return ERROR_FILE_NOT_FOUND;
}

/**
 * Return interface specific domain suffix(es)
 *
 * The \p domains paramter will be set to a MULTI_SZ domains string.
 * In case of an error or if no domains are found for the interface
 * \p size is set to 0 and the contents of \p domains are invalid.
 * Note that the domains could have been set by DHCP or manually.
 *
 * @param  itf        HKEY of the interface to read from
 * @param  domains    PWSTR buffer to return the domain(s) in
 * @param  size       pointer to size of the domains buffer in bytes. Will be
 *                    set to the size of the string returned, including
 *                    the terminating zeros or 0.
 *
 * @return LSTATUS NO_ERROR if the domain suffix(es) were read successfully,
 *         ERROR_FILE_NOT_FOUND if no domain was found for the interface,
 *         ERROR_MORE_DATA if the list did not fit into the buffer,
 *         any other error indicates an error while reading from the registry.
 */
static LSTATUS
GetItfDnsDomains(HKEY itf, PWSTR domains, PDWORD size)
{
    if (domains == NULL || size == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    LSTATUS err = ERROR_FILE_NOT_FOUND;
    const DWORD buf_size = *size;
    const size_t one_glyph = sizeof(*domains);
    PWSTR values[] = { L"SearchList", L"Domain", L"DhcpDomainSearchList", L"DhcpDomain", NULL};

    for (int i = 0; values[i]; i++)
    {
        *size = buf_size;
        err = RegGetValueW(itf, NULL, values[i], RRF_RT_REG_SZ, NULL, (PBYTE)domains, size);
        if (!err && *size > one_glyph && wcschr(domains, '.'))
        {
            /*
             * Found domain(s), now convert them:
             *   - prefix each domain with a dot
             *   - convert comma separated list to MULTI_SZ
             */
            PWCHAR pos = domains;
            const DWORD buf_len = buf_size / one_glyph;
            while (TRUE)
            {
                /* Terminate the domain at the next comma */
                PWCHAR comma = wcschr(pos, ',');
                if (comma)
                {
                    *comma = '\0';
                }

                /* Check for enough space to convert this domain */
                size_t converted_size = pos - domains;
                size_t domain_len = wcslen(pos) + 1;
                size_t domain_size = domain_len * one_glyph;
                size_t extra_size = 2 * one_glyph;
                if (converted_size + domain_size + extra_size > buf_size)
                {
                    /* Domain doesn't fit, bad luck if it's the first one */
                    *pos = '\0';
                    *size = converted_size == 0 ? 0 : *size + 1;
                    return ERROR_MORE_DATA;
                }

                /* Prefix domain at pos with the dot */
                memmove(pos + 1, pos, buf_size - converted_size - one_glyph);
                domains[buf_len - 1] = '\0';
                *pos = '.';
                *size += 1;

                if (!comma)
                {
                    /* Conversion is done */
                    *(pos + domain_len) = '\0';
                    *size += 1;
                    return NO_ERROR;
                }

                pos = comma + 1;
            }
        }
    }

    *size = 0;
    return err;
}

/**
 * Check if an interface is connected and up
 *
 * @param  iid_str    the interface GUID as string
 *
 * @return TRUE if the interface is connected and up, FALSE otherwise or in
 *         case an error happened
 */
static BOOL
IsInterfaceConnected(PWSTR iid_str)
{
    GUID iid;
    BOOL res = FALSE;
    MIB_IF_ROW2 itf_row;

    /* Get GUID from string */
    if (IIDFromString(iid_str, &iid) != S_OK)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not convert interface %s GUID string", __func__, iid_str);
        goto out;
    }

    /* Get LUID from GUID */
    if (ConvertInterfaceGuidToLuid(&iid, &itf_row.InterfaceLuid) != NO_ERROR)
    {
        goto out;
    }

    /* Look up interface status */
    if (GetIfEntry2(&itf_row) != NO_ERROR)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not get interface %s status", __func__, iid_str);
        goto out;
    }

    if (itf_row.MediaConnectState == MediaConnectStateConnected
        && itf_row.OperStatus == IfOperStatusUp)
    {
        res = TRUE;
    }

out:
    return res;
}

/**
 * Collect interface DNS settings to be used in excluding NRPT rules. This is
 * needed so that local DNS keeps working even when a catch all NRPT rule is
 * installed by a VPN connection.
 *
 * @param  data       pointer to the data structures the values are returned in
 * @param  data_size  number of exclude data structures pointed to
 */
static void
GetNrptExcludeData(nrpt_exclude_data_t *data, size_t data_size)
{
    HKEY v4_itfs = INVALID_HANDLE_VALUE;
    HKEY v6_itfs = INVALID_HANDLE_VALUE;

    if (!GetInterfacesKey(AF_INET, &v4_itfs)
        || !GetInterfacesKey(AF_INET6, &v6_itfs))
    {
        goto out;
    }

    size_t i = 0;
    DWORD enum_index = 0;
    while (i < data_size)
    {
        WCHAR itf_guid[MAX_PATH];
        DWORD itf_guid_len = _countof(itf_guid);
        LSTATUS err = RegEnumKeyExW(v4_itfs, enum_index++, itf_guid, &itf_guid_len,
                                    NULL, NULL, NULL, NULL);
        if (err)
        {
            if (err != ERROR_NO_MORE_ITEMS)
            {
                MsgToEventLog(M_SYSERR, L"%S: could not enumerate interfaces (%lu)", __func__, err);
            }
            goto out;
        }

        /* Ignore interfaces that are not connected or disabled */
        if (!IsInterfaceConnected(itf_guid))
        {
            continue;
        }

        HKEY v4_itf;
        if (RegOpenKeyExW(v4_itfs, itf_guid, 0, KEY_READ, &v4_itf) != NO_ERROR)
        {
            MsgToEventLog(M_SYSERR, L"%S: could not open interface %s v4 registry key", __func__, itf_guid);
            goto out;
        }

        /* Get the DNS domain(s) for exclude routing */
        data[i].domains_size = sizeof(data[0].domains);
        memset(data[i].domains, 0, data[i].domains_size);
        err = GetItfDnsDomains(v4_itf, data[i].domains, &data[i].domains_size);
        if (err)
        {
            if (err != ERROR_FILE_NOT_FOUND)
            {
                MsgToEventLog(M_SYSERR, L"%S: could not read interface %s domain suffix", __func__, itf_guid);
            }
            goto next_itf;
        }

        /* Get the IPv4 DNS servers */
        DWORD v4_addrs_size = sizeof(data[0].addresses);
        err = GetItfDnsServersV4(v4_itf, data[i].addresses, &v4_addrs_size);
        if (err && err != ERROR_FILE_NOT_FOUND)
        {
            MsgToEventLog(M_SYSERR, L"%S: could not read interface %s v4 name servers (%ld)",
                          __func__, itf_guid, err);
            goto next_itf;
        }

        /* Get the IPv6 DNS servers, if there's space left */
        PSTR v6_addrs = data[i].addresses + v4_addrs_size;
        DWORD v6_addrs_size = sizeof(data[0].addresses) - v4_addrs_size;
        if (v6_addrs_size > NRPT_ADDR_SIZE)
        {
            HKEY v6_itf;
            if (RegOpenKeyExW(v6_itfs, itf_guid, 0, KEY_READ, &v6_itf) != NO_ERROR)
            {
                MsgToEventLog(M_SYSERR, L"%S: could not open interface %s v6 registry key", __func__, itf_guid);
                goto next_itf;
            }
            err = GetItfDnsServersV6(v6_itf, v6_addrs, &v6_addrs_size);
            RegCloseKey(v6_itf);
            if (err && err != ERROR_FILE_NOT_FOUND)
            {
                MsgToEventLog(M_SYSERR, L"%S: could not read interface %s v6 name servers (%ld)",
                              __func__, itf_guid, err);
                goto next_itf;
            }
        }

        if (v4_addrs_size || v6_addrs_size)
        {
            /* Replace comma-delimters with semicolons, as required by NRPT */
            for (int j = 0; j < sizeof(data[0].addresses) && data[i].addresses[j]; j++)
            {
                if (data[i].addresses[j] == ',')
                {
                    data[i].addresses[j] = ';';
                }
            }
            ++i;
        }

next_itf:
        RegCloseKey(v4_itf);
    }

out:
    RegCloseKey(v6_itfs);
    RegCloseKey(v4_itfs);
}

/**
 * Set a NRPT rule (subkey) and its values in the registry
 *
 * @param  nrpt_key   NRPT registry key handle
 * @param  subkey     subkey string to create
 * @param  address    name server address string
 * @param  domains    domains to resolve by this server as MULTI_SZ
 * @param  dom_size   size of domains in bytes including the terminators
 * @param  dnssec     boolean to determine if DNSSEC is to be enabled
 *
 * @return NO_ERROR on success, or Windows error code
 */
static DWORD
SetNrptRule(HKEY nrpt_key, PCWSTR subkey, PCSTR address,
            PCWSTR domains, DWORD dom_size, BOOL dnssec)
{
    /* Create rule subkey */
    DWORD err = NO_ERROR;
    HKEY rule_key;
    err = RegCreateKeyExW(nrpt_key, subkey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &rule_key, NULL);
    if (err)
    {
        return err;
    }

    /* Set name(s) for DNS routing */
    err = RegSetValueExW(rule_key, L"Name", 0, REG_MULTI_SZ, (PBYTE)domains, dom_size);
    if (err)
    {
        goto out;
    }

    /* Set DNS Server address */
    err = RegSetValueExA(rule_key, "GenericDNSServers", 0, REG_SZ, (PBYTE)address, strlen(address) + 1);
    if (err)
    {
        goto out;
    }

    DWORD reg_val;
    /* Set DNSSEC if required */
    if (dnssec)
    {
        reg_val = 1;
        err = RegSetValueExA(rule_key, "DNSSECValidationRequired", 0, REG_DWORD, (PBYTE)&reg_val, sizeof(reg_val));
        if (err)
        {
            goto out;
        }

        reg_val = 0;
        err = RegSetValueExA(rule_key, "DNSSECQueryIPSECRequired", 0, REG_DWORD, (PBYTE)&reg_val, sizeof(reg_val));
        if (err)
        {
            goto out;
        }

        reg_val = 0;
        err = RegSetValueExA(rule_key, "DNSSECQueryIPSECEncryption", 0, REG_DWORD, (PBYTE)&reg_val, sizeof(reg_val));
        if (err)
        {
            goto out;
        }
    }

    /* Set NRPT config options */
    reg_val = dnssec ? 0x0000000A : 0x00000008;
    err = RegSetValueExA(rule_key, "ConfigOptions", 0, REG_DWORD, (const PBYTE)&reg_val, sizeof(reg_val));
    if (err)
    {
        goto out;
    }

    /* Mandatory NRPT version */
    reg_val = 2;
    err = RegSetValueExA(rule_key, "Version", 0, REG_DWORD, (const PBYTE)&reg_val, sizeof(reg_val));
    if (err)
    {
        goto out;
    }

out:
    if (err)
    {
        RegDeleteKeyW(nrpt_key, subkey);
    }
    RegCloseKey(rule_key);
    return err;
}

/**
 * Set NRPT exclude rules to accompany a catch all rule. This is done so that
 * local resolution of names is not interfered with in case the VPN resolves
 * all names.
 *
 * @param  nrpt_key   the registry key to set the rules under
 * @param  ovpn_pid   the PID of the openvpn process
 */
static void
SetNrptExcludeRules(HKEY nrpt_key, DWORD ovpn_pid)
{
    nrpt_exclude_data_t data[8]; /* data from up to 8 interfaces */
    memset(data, 0, sizeof(data));
    GetNrptExcludeData(data, _countof(data));

    unsigned n = 0;
    for (int i = 0; i < _countof(data); ++i)
    {
        nrpt_exclude_data_t *d = &data[i];
        if (d->domains_size == 0)
        {
            break;
        }

        DWORD err;
        WCHAR subkey[48];
        swprintf(subkey, _countof(subkey), L"OpenVPNDNSRoutingX-%02x-%lu", ++n, ovpn_pid);
        err = SetNrptRule(nrpt_key, subkey, d->addresses, d->domains, d->domains_size, FALSE);
        if (err)
        {
            MsgToEventLog(M_ERR, L"%S: failed to set rule %s (%lu)", __func__, subkey, err);
        }
    }
}

/**
 * Set NRPT rules for a openvpn process
 *
 * @param  nrpt_key   the registry key to set the rules under
 * @param  addresses  name server addresses
 * @param  domains    optional list of split routing domains
 * @param  dnssec     boolean whether DNSSEC is to be used
 * @param  ovpn_pid   the PID of the openvpn process
 *
 * @return NO_ERROR on success, or a Windows error code
 */
static DWORD
SetNrptRules(HKEY nrpt_key, const nrpt_address_t *addresses,
             const char *domains, BOOL dnssec, DWORD ovpn_pid)
{
    DWORD err = NO_ERROR;
    PWSTR wide_domains = L".\0"; /* DNS route everything by default */
    DWORD dom_size = 6;

    /* Prepare DNS routing domains / split DNS */
    if (domains[0])
    {
        size_t domains_len = strlen(domains);
        dom_size = domains_len + 2; /* len + the trailing NULs */

        wide_domains = utf8to16_size(domains, dom_size);
        dom_size *= sizeof(*wide_domains);
        if (!wide_domains)
        {
            return ERROR_OUTOFMEMORY;
        }
        /* Make a MULTI_SZ from a comma separated list */
        for (size_t i = 0; i < domains_len; ++i)
        {
            if (wide_domains[i] == ',')
            {
                wide_domains[i] = 0;
            }
        }
    }
    else
    {
        SetNrptExcludeRules(nrpt_key, ovpn_pid);
    }

    /* Create address string list */
    CHAR addr_list[NRPT_ADDR_NUM * NRPT_ADDR_SIZE];
    PSTR pos = addr_list;
    for (int i = 0; i < NRPT_ADDR_NUM && addresses[i][0]; ++i)
    {
        if (i != 0)
        {
            *pos++ = ';';
        }
        strcpy(pos, addresses[i]);
        pos += strlen(pos);
    }

    WCHAR subkey[MAX_PATH];
    swprintf(subkey, _countof(subkey), L"OpenVPNDNSRouting-%lu", ovpn_pid);
    err = SetNrptRule(nrpt_key, subkey, addr_list, wide_domains, dom_size, dnssec);
    if (err)
    {
        MsgToEventLog(M_ERR, L"%S: failed to set rule %s (%lu)", __func__, subkey, err);
    }

    if (domains[0])
    {
        free(wide_domains);
    }
    return err;
}

/**
 * Return the registry key where NRPT rules are stored
 *
 * @param  key        pointer to the HKEY it is returned in
 * @param  gpol       pointer to BOOL the use of GPOL hive is returned in
 *
 * @return NO_ERROR on success, or a Windows error code
 */
static LSTATUS
OpenNrptBaseKey(PHKEY key, PBOOL gpol)
{
    /*
     * Registry keys Name Service Policy Table (NRPT) rules can be stored at.
     * When the group policy key exists, NRPT rules must be placed there.
     * It is created when NRPT rules are pushed via group policy and it
     * remains in the registry even if the last GP-NRPT rule is deleted.
     */
    static PCSTR gpol_key = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig";
    static PCSTR sys_key = "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";

    HKEY nrpt;
    *gpol = TRUE;
    LSTATUS err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, gpol_key, 0, KEY_ALL_ACCESS, &nrpt);
    if (err == ERROR_FILE_NOT_FOUND)
    {
        *gpol = FALSE;
        err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, sys_key, 0, KEY_ALL_ACCESS, &nrpt);
        if (err)
        {
            nrpt = INVALID_HANDLE_VALUE;
        }
    }
    *key = nrpt;
    return err;
}

/**
 * Delete OpenVPN NRPT rules from the registry
 *
 * If the pid parameter is 0 all NRPT rules added by OpenVPN are deleted.
 * In all other cases only rules matching the pid are deleted.
 *
 * @param  pid        PID of the process to delete the rules for or 0
 * @param  gpol
 *
 * @return BOOL to indicate if rules were deleted
 */
static BOOL
DeleteNrptRules(DWORD pid, PBOOL gpol)
{
    HKEY key;
    LSTATUS err = OpenNrptBaseKey(&key, gpol);
    if (err)
    {
        MsgToEventLog(M_SYSERR, L"%S: could not open NRPT base key (%lu)", __func__, err);
        return FALSE;
    }

    /* PID suffix string to compare against later */
    WCHAR pid_str[16];
    size_t pidlen = 0;
    if (pid)
    {
        swprintf(pid_str, _countof(pid_str), L"-%lu", pid);
        pidlen = wcslen(pid_str);
    }

    int deleted = 0;
    DWORD enum_index = 0;
    while (TRUE)
    {
        WCHAR name[MAX_PATH];
        DWORD namelen = _countof(name);
        err = RegEnumKeyExW(key, enum_index++, name, &namelen, NULL, NULL, NULL, NULL);
        if (err)
        {
            if (err != ERROR_NO_MORE_ITEMS)
            {
                MsgToEventLog(M_SYSERR, L"%S: could not enumerate NRPT rules (%lu)", __func__, err);
            }
            break;
        }

        /* Keep rule if name doesn't match */
        if (wcsncmp(name, L"OpenVPNDNSRouting", 17) != 0
            || (pid && wcsncmp(name + namelen - pidlen, pid_str, pidlen) != 0))
        {
            continue;
        }

        if (RegDeleteKeyW(key, name) == NO_ERROR)
        {
            enum_index--;
            deleted++;
        }
    }

    RegCloseKey(key);
    return deleted ? TRUE : FALSE;
}

/**
 * Delete a process' NRPT rules and apply the reduced set of rules
 *
 * @param ovpn_pid  OpenVPN process id to delete rules for
 */
static void
UndoNrptRules(DWORD ovpn_pid)
{
    BOOL gpol;
    if (DeleteNrptRules(ovpn_pid, &gpol))
    {
        ApplyDnsSettings(gpol);
    }
}

/**
 * Add Name Resolution Policy Table (NRPT) rules as documented in
 * https://msdn.microsoft.com/en-us/library/ff957356.aspx for DNS name
 * resolution, as well as DNS search domain(s), if given.
 *
 * @param  msg        config messages sent by the openvpn process
 * @param  ovpn_pid   process id of the sending openvpn process
 * @param  lists      undo lists for this process
 *
 * @return NO_ERROR on success, or a Windows error code
 */
static DWORD
HandleDNSConfigNrptMessage(const nrpt_dns_cfg_message_t *msg,
                           DWORD ovpn_pid, undo_lists_t *lists)
{
    /*
     * Use a non-const reference with limited scope to
     * enforce null-termination of strings from client
     */
    {
        nrpt_dns_cfg_message_t *msgptr = (nrpt_dns_cfg_message_t *) msg;
        msgptr->iface.name[_countof(msg->iface.name) - 1] = '\0';
        msgptr->search_domains[_countof(msg->search_domains) - 1] = '\0';
        msgptr->resolve_domains[_countof(msg->resolve_domains) - 1] = '\0';
        for (size_t i = 0; i < NRPT_ADDR_NUM; ++i)
        {
            msgptr->addresses[i][_countof(msg->addresses[0]) - 1] = '\0';
        }
    }

    /* Make sure we have the VPN interface name */
    if (msg->iface.name[0] == 0)
    {
        return ERROR_MESSAGE_DATA;
    }

    /* Some sanity checks on the add message data */
    if (msg->header.type == msg_add_nrpt_cfg)
    {
        /* At least one name server address is set */
        if (msg->addresses[0][0] == 0)
        {
            return ERROR_MESSAGE_DATA;
        }
        /* Resolve domains are double zero terminated (MULTI_SZ) */
        const char *rdom = msg->resolve_domains;
        size_t rdom_size = sizeof(msg->resolve_domains);
        size_t rdom_len = strlen(rdom);
        if (rdom_len && (rdom_len + 1 >= rdom_size || rdom[rdom_len + 2] != 0))
        {
            return ERROR_MESSAGE_DATA;
        }
    }

    BOOL gpol_nrpt = FALSE;
    BOOL gpol_list = FALSE;

    WCHAR iid[64];
    DWORD iid_err = InterfaceIdString(msg->iface.name, iid, _countof(iid));
    if (iid_err)
    {
        return iid_err;
    }

    /* Delete previously set values for this instance first, if any */
    PDWORD undo_pid = RemoveListItem(&(*lists)[undo_nrpt], CmpAny, NULL);
    if (undo_pid)
    {
        if (*undo_pid != ovpn_pid)
        {
            MsgToEventLog(M_INFO,
                          L"%S: PID stored for undo doesn't match: %lu vs %lu. "
                          "This is likely an error. Cleaning up anyway.",
                          __func__, *undo_pid, ovpn_pid);
        }
        DeleteNrptRules(*undo_pid, &gpol_nrpt);
        free(undo_pid);

        ResetNameServers(iid, AF_INET);
        ResetNameServers(iid, AF_INET6);
    }
    SetDnsSearchDomains(msg->iface.name, NULL, &gpol_list, lists);

    if (msg->header.type == msg_del_nrpt_cfg)
    {
        ApplyDnsSettings(gpol_nrpt || gpol_list);
        return NO_ERROR; /* Done dealing with del message */
    }

    HKEY key;
    LSTATUS err = OpenNrptBaseKey(&key, &gpol_nrpt);
    if (err)
    {
        goto out;
    }

    /* Add undo information first in case there's no heap left */
    PDWORD pid = malloc(sizeof(ovpn_pid));
    if (!pid)
    {
        err = ERROR_OUTOFMEMORY;
        goto out;
    }
    *pid = ovpn_pid;
    if (AddListItem(&(*lists)[undo_nrpt], pid))
    {
        err = ERROR_OUTOFMEMORY;
        free(pid);
        goto out;
    }

    /* Set NRPT rules */
    BOOL dnssec = (msg->flags & nrpt_dnssec) != 0;
    err = SetNrptRules(key, msg->addresses, msg->resolve_domains, dnssec, ovpn_pid);
    if (err)
    {
        goto out;
    }

    /* Set name servers */
    err = SetNameServerAddresses(iid, msg->addresses);
    if (err)
    {
        goto out;
    }

    /* Set search domains, if any */
    if (msg->search_domains[0])
    {
        err = SetDnsSearchDomains(msg->iface.name, msg->search_domains, &gpol_list, lists);
    }

    ApplyDnsSettings(gpol_nrpt || gpol_list);

out:
    return err;
}

static DWORD
HandleWINSConfigMessage(const wins_cfg_message_t *msg, undo_lists_t *lists)
{
    DWORD err = 0;
    wchar_t addr[16]; /* large enough to hold string representation of an ipv4 */
    int addr_len = msg->addr_len;

    /* sanity check */
    if (addr_len > _countof(msg->addr))
    {
        addr_len = _countof(msg->addr);
    }

    if (!msg->iface.name[0]) /* interface name is required */
    {
        return ERROR_MESSAGE_DATA;
    }

    /* use a non-const reference with limited scope to enforce null-termination of strings from client */
    {
        wins_cfg_message_t *msgptr = (wins_cfg_message_t *)msg;
        msgptr->iface.name[_countof(msg->iface.name) - 1] = '\0';
    }

    wchar_t *wide_name = utf8to16(msg->iface.name); /* utf8 to wide-char */
    if (!wide_name)
    {
        return ERROR_OUTOFMEMORY;
    }

    /* We delete all current addresses before adding any
     * OR if the message type is del_wins_cfg
     */
    if (addr_len > 0 || msg->header.type == msg_del_wins_cfg)
    {
        err = netsh_wins_cmd(L"delete", wide_name, NULL);
        if (err)
        {
            goto out;
        }
        free(RemoveListItem(&(*lists)[undo_wins], CmpWString, wide_name));
    }

    if (msg->header.type == msg_del_wins_cfg)
    {
        goto out;  /* job done */
    }

    for (int i = 0; i < addr_len; ++i)
    {
        RtlIpv4AddressToStringW(&msg->addr[i].ipv4, addr);
        err = netsh_wins_cmd(i == 0 ? L"set" : L"add", wide_name, addr);
        if (i == 0 && err)
        {
            goto out;
        }
        /* We do not check for duplicate addresses, so any error in adding
         * additional addresses is ignored.
         */
    }

    err = 0;

    if (addr_len > 0)
    {
        wchar_t *tmp_name = _wcsdup(wide_name);
        if (!tmp_name || AddListItem(&(*lists)[undo_wins], tmp_name))
        {
            free(tmp_name);
            netsh_wins_cmd(L"delete", wide_name, NULL);
            err = ERROR_OUTOFMEMORY;
            goto out;
        }
    }

out:
    free(wide_name);
    return err;
}

static DWORD
HandleEnableDHCPMessage(const enable_dhcp_message_t *dhcp)
{
    DWORD err = 0;
    DWORD timeout = 5000; /* in milli seconds */
    wchar_t argv0[MAX_PATH];

    /* Path of netsh */
    swprintf(argv0, _countof(argv0), L"%ls\\%ls", get_win_sys_path(), L"netsh.exe");

    /* cmd template:
     * netsh interface ipv4 set address name=$if_index source=dhcp
     */
    const wchar_t *fmt = L"netsh interface ipv4 set address name=\"%d\" source=dhcp";

    /* max cmdline length in wchars -- include room for if index:
     * 10 chars for 32 bit int in decimal and +1 for NUL
     */
    size_t ncmdline = wcslen(fmt) + 10 + 1;
    wchar_t *cmdline = malloc(ncmdline*sizeof(wchar_t));
    if (!cmdline)
    {
        err = ERROR_OUTOFMEMORY;
        return err;
    }

    swprintf(cmdline, ncmdline, fmt, dhcp->iface.index);

    err = ExecCommand(argv0, cmdline, timeout);

    /* Note: This could fail if dhcp is already enabled, so the caller
     * may not want to treat errors as FATAL.
     */

    free(cmdline);
    return err;
}

static DWORD
HandleMTUMessage(const set_mtu_message_t *mtu)
{
    DWORD err = 0;
    MIB_IPINTERFACE_ROW ipiface;
    InitializeIpInterfaceEntry(&ipiface);
    ipiface.Family = mtu->family;
    ipiface.InterfaceIndex = mtu->iface.index;
    err = GetIpInterfaceEntry(&ipiface);
    if (err != NO_ERROR)
    {
        return err;
    }
    if (mtu->family == AF_INET)
    {
        ipiface.SitePrefixLength = 0;
    }
    ipiface.NlMtu = mtu->mtu;

    err = SetIpInterfaceEntry(&ipiface);
    return err;
}

/**
 * Creates a VPN adapter of the specified type by invoking tapctl.exe.
 *
 * @param msg Adapter creation request specifying the type.
 *
 * @return NO_ERROR on success, otherwise a Windows error code.
 */
static DWORD
HandleCreateAdapterMessage(const create_adapter_message_t *msg)
{
    const WCHAR *hwid;

    switch (msg->adapter_type)
    {
        case ADAPTER_TYPE_DCO:
            hwid = L"ovpn-dco";
            break;

        case ADAPTER_TYPE_TAP:
            hwid = L"root\\tap0901";
            break;

        default:
            return ERROR_INVALID_PARAMETER;
    }

    WCHAR cmd[MAX_PATH];
    WCHAR args[MAX_PATH];

    if (swprintf_s(cmd, _countof(cmd), L"%s\\tapctl.exe", settings.bin_dir) < 0)
    {
        return ERROR_BUFFER_OVERFLOW;
    }

    if (swprintf_s(args, _countof(args), L"tapctl create --hwid %s", hwid) < 0)
    {
        return ERROR_BUFFER_OVERFLOW;
    }

    return ExecCommand(cmd, args, 10000);
}

static VOID
HandleMessage(HANDLE pipe, PPROCESS_INFORMATION proc_info,
              DWORD bytes, DWORD count, LPHANDLE events, undo_lists_t *lists)
{
    pipe_message_t msg;
    ack_message_t ack = {
        .header = {
            .type = msg_acknowledgement,
            .size = sizeof(ack),
            .message_id = -1
        },
        .error_number = ERROR_MESSAGE_DATA
    };

    DWORD read = ReadPipeAsync(pipe, &msg, bytes, count, events);
    if (read != bytes || read < sizeof(msg.header) || read != msg.header.size)
    {
        goto out;
    }

    ack.header.message_id = msg.header.message_id;

    switch (msg.header.type)
    {
        case msg_add_address:
        case msg_del_address:
            if (msg.header.size == sizeof(msg.address))
            {
                ack.error_number = HandleAddressMessage(&msg.address, lists);
            }
            break;

        case msg_add_route:
        case msg_del_route:
            if (msg.header.size == sizeof(msg.route))
            {
                ack.error_number = HandleRouteMessage(&msg.route, lists);
            }
            break;

        case msg_flush_neighbors:
            if (msg.header.size == sizeof(msg.flush_neighbors))
            {
                ack.error_number = HandleFlushNeighborsMessage(&msg.flush_neighbors);
            }
            break;

        case msg_add_wfp_block:
        case msg_del_wfp_block:
            if (msg.header.size == sizeof(msg.wfp_block))
            {
                ack.error_number = HandleWfpBlockMessage(&msg.wfp_block, lists);
            }
            break;

        case msg_register_dns:
            ack.error_number = HandleRegisterDNSMessage();
            break;

        case msg_add_dns_cfg:
        case msg_del_dns_cfg:
            ack.error_number = HandleDNSConfigMessage(&msg.dns, lists);
            break;

        case msg_add_nrpt_cfg:
        case msg_del_nrpt_cfg:
        {
            DWORD ovpn_pid = proc_info->dwProcessId;
            ack.error_number = HandleDNSConfigNrptMessage(&msg.nrpt_dns, ovpn_pid, lists);
        }
        break;

        case msg_add_wins_cfg:
        case msg_del_wins_cfg:
            ack.error_number = HandleWINSConfigMessage(&msg.wins, lists);
            break;

        case msg_enable_dhcp:
            if (msg.header.size == sizeof(msg.dhcp))
            {
                ack.error_number = HandleEnableDHCPMessage(&msg.dhcp);
            }
            break;

        case msg_set_mtu:
            if (msg.header.size == sizeof(msg.mtu))
            {
                ack.error_number = HandleMTUMessage(&msg.mtu);
            }
            break;

        case msg_create_adapter:
            if (msg.header.size == sizeof(msg.create_adapter))
            {
                ack.error_number = HandleCreateAdapterMessage(&msg.create_adapter);
            }
            break;

        default:
            ack.error_number = ERROR_MESSAGE_TYPE;
            MsgToEventLog(MSG_FLAGS_ERROR, L"Unknown message type %d", msg.header.type);
            break;
    }

out:
    WritePipeAsync(pipe, &ack, sizeof(ack), count, events);
}


static VOID
Undo(undo_lists_t *lists)
{
    undo_type_t type;
    wfp_block_data_t *interface_data;
    for (type = 0; type < _undo_type_max; type++)
    {
        list_item_t **pnext = &(*lists)[type];
        while (*pnext)
        {
            list_item_t *item = *pnext;
            switch (type)
            {
                case address:
                    DeleteAddress(item->data);
                    break;

                case route:
                    DeleteRoute(item->data);
                    break;

                case undo_dns4:
                    ResetNameServers(item->data, AF_INET);
                    break;

                case undo_dns6:
                    ResetNameServers(item->data, AF_INET6);
                    break;

                case undo_nrpt:
                    UndoNrptRules(*(PDWORD)item->data);
                    break;

                case undo_domains:
                    UndoDnsSearchDomains(item->data);
                    break;

                case undo_wins:
                    netsh_wins_cmd(L"delete", item->data, NULL);
                    break;

                case wfp_block:
                    interface_data = (wfp_block_data_t *)(item->data);
                    delete_wfp_block_filters(interface_data->engine);
                    if (interface_data->metric_v4 >= 0)
                    {
                        set_interface_metric(interface_data->index, AF_INET,
                                             interface_data->metric_v4);
                    }
                    if (interface_data->metric_v6 >= 0)
                    {
                        set_interface_metric(interface_data->index, AF_INET6,
                                             interface_data->metric_v6);
                    }
                    break;

                case _undo_type_max:
                    /* unreachable */
                    break;
            }

            /* Remove from the list and free memory */
            *pnext = item->next;
            free(item->data);
            free(item);
        }
    }
}

static DWORD WINAPI
RunOpenvpn(LPVOID p)
{
    HANDLE pipe = p;
    HANDLE ovpn_pipe = NULL, svc_pipe = NULL;
    PTOKEN_USER svc_user = NULL, ovpn_user = NULL;
    HANDLE svc_token = NULL, imp_token = NULL, pri_token = NULL;
    HANDLE stdin_read = NULL, stdin_write = NULL;
    HANDLE stdout_write = NULL;
    DWORD pipe_mode, len, exit_code = 0;
    STARTUP_DATA sud = { 0, 0, 0 };
    STARTUPINFOW startup_info;
    PROCESS_INFORMATION proc_info;
    LPVOID user_env = NULL;
    WCHAR ovpn_pipe_name[256]; /* The entire pipe name string can be up to 256 characters long according to MSDN. */
    LPCWSTR exe_path;
    WCHAR *cmdline = NULL;
    size_t cmdline_size;
    undo_lists_t undo_lists;
    WCHAR errmsg[512] = L"";

    SECURITY_ATTRIBUTES inheritable = {
        .nLength = sizeof(inheritable),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = TRUE
    };

    PACL ovpn_dacl;
    EXPLICIT_ACCESS ea[2];
    SECURITY_DESCRIPTOR ovpn_sd;
    SECURITY_ATTRIBUTES ovpn_sa = {
        .nLength = sizeof(ovpn_sa),
        .lpSecurityDescriptor = &ovpn_sd,
        .bInheritHandle = FALSE
    };

    ZeroMemory(&ea, sizeof(ea));
    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&undo_lists, sizeof(undo_lists));
    ZeroMemory(&proc_info, sizeof(proc_info));

    if (!GetStartupData(pipe, &sud))
    {
        goto out;
    }

    if (!InitializeSecurityDescriptor(&ovpn_sd, SECURITY_DESCRIPTOR_REVISION))
    {
        ReturnLastError(pipe, L"InitializeSecurityDescriptor");
        goto out;
    }

    /* Get SID of user the service is running under */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &svc_token))
    {
        ReturnLastError(pipe, L"OpenProcessToken");
        goto out;
    }
    len = 0;
    while (!GetTokenInformation(svc_token, TokenUser, svc_user, len, &len))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            ReturnLastError(pipe, L"GetTokenInformation (service token)");
            goto out;
        }
        free(svc_user);
        svc_user = malloc(len);
        if (svc_user == NULL)
        {
            ReturnLastError(pipe, L"malloc (service token user)");
            goto out;
        }
    }
    if (!IsValidSid(svc_user->User.Sid))
    {
        ReturnLastError(pipe, L"IsValidSid (service token user)");
        goto out;
    }

    if (!ImpersonateNamedPipeClient(pipe))
    {
        ReturnLastError(pipe, L"ImpersonateNamedPipeClient");
        goto out;
    }
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &imp_token))
    {
        ReturnLastError(pipe, L"OpenThreadToken");
        goto out;
    }
    len = 0;
    while (!GetTokenInformation(imp_token, TokenUser, ovpn_user, len, &len))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            ReturnLastError(pipe, L"GetTokenInformation (impersonation token)");
            goto out;
        }
        free(ovpn_user);
        ovpn_user = malloc(len);
        if (ovpn_user == NULL)
        {
            ReturnLastError(pipe, L"malloc (impersonation token user)");
            goto out;
        }
    }
    if (!IsValidSid(ovpn_user->User.Sid))
    {
        ReturnLastError(pipe, L"IsValidSid (impersonation token user)");
        goto out;
    }

    /*
     * Only authorized users are allowed to use any command line options or
     * have the config file in locations other than the global config directory.
     *
     * Check options are white-listed and config is in the global directory
     * OR user is authorized to run any config.
     */
    if (!ValidateOptions(pipe, sud.directory, sud.options, errmsg, _countof(errmsg))
        && !IsAuthorizedUser(ovpn_user->User.Sid, imp_token, settings.ovpn_admin_group, settings.ovpn_service_user))
    {
        ReturnError(pipe, ERROR_STARTUP_DATA, errmsg, 1, &exit_event);
        goto out;
    }

    /* OpenVPN process DACL entry for access by service and user */
    ea[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea[0].Trustee.ptstrName = (LPWSTR) svc_user->User.Sid;
    ea[1].grfAccessPermissions = READ_CONTROL | SYNCHRONIZE | PROCESS_VM_READ
                                 |SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea[1].Trustee.ptstrName = (LPWSTR) ovpn_user->User.Sid;

    /* Set owner and DACL of OpenVPN security descriptor */
    if (!SetSecurityDescriptorOwner(&ovpn_sd, svc_user->User.Sid, FALSE))
    {
        ReturnLastError(pipe, L"SetSecurityDescriptorOwner");
        goto out;
    }
    if (SetEntriesInAcl(2, ea, NULL, &ovpn_dacl) != ERROR_SUCCESS)
    {
        ReturnLastError(pipe, L"SetEntriesInAcl");
        goto out;
    }
    if (!SetSecurityDescriptorDacl(&ovpn_sd, TRUE, ovpn_dacl, FALSE))
    {
        ReturnLastError(pipe, L"SetSecurityDescriptorDacl");
        goto out;
    }

    /* Create primary token from impersonation token */
    if (!DuplicateTokenEx(imp_token, TOKEN_ALL_ACCESS, NULL, 0, TokenPrimary, &pri_token))
    {
        ReturnLastError(pipe, L"DuplicateTokenEx");
        goto out;
    }

    /* use /dev/null for stdout of openvpn (client should use --log for output) */
    stdout_write = CreateFile(_L("NUL"), GENERIC_WRITE, FILE_SHARE_WRITE,
                              &inheritable, OPEN_EXISTING, 0, NULL);
    if (stdout_write == INVALID_HANDLE_VALUE)
    {
        ReturnLastError(pipe, L"CreateFile for stdout");
        goto out;
    }

    if (!CreatePipe(&stdin_read, &stdin_write, &inheritable, 0)
        || !SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0))
    {
        ReturnLastError(pipe, L"CreatePipe");
        goto out;
    }

    swprintf(ovpn_pipe_name, _countof(ovpn_pipe_name),
             L"\\\\.\\pipe\\" _L(PACKAGE) L"%ls\\service_%lu", service_instance, GetCurrentThreadId());
    ovpn_pipe = CreateNamedPipe(ovpn_pipe_name,
                                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 128, 128, 0, NULL);
    if (ovpn_pipe == INVALID_HANDLE_VALUE)
    {
        ReturnLastError(pipe, L"CreateNamedPipe");
        goto out;
    }

    svc_pipe = CreateFile(ovpn_pipe_name, GENERIC_READ | GENERIC_WRITE, 0,
                          &inheritable, OPEN_EXISTING, 0, NULL);
    if (svc_pipe == INVALID_HANDLE_VALUE)
    {
        ReturnLastError(pipe, L"CreateFile");
        goto out;
    }

    pipe_mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(svc_pipe, &pipe_mode, NULL, NULL))
    {
        ReturnLastError(pipe, L"SetNamedPipeHandleState");
        goto out;
    }

    cmdline_size = wcslen(sud.options) + 128;
    cmdline = malloc(cmdline_size * sizeof(*cmdline));
    if (cmdline == NULL)
    {
        ReturnLastError(pipe, L"malloc");
        goto out;
    }
    /* there seem to be no common printf specifier that works on all
     * mingw/msvc platforms without trickery, so convert to void* and use
     * PRIuPTR to print that as best compromise */
    swprintf(cmdline, cmdline_size, L"openvpn %ls --msg-channel %" PRIuPTR,
             sud.options, (uintptr_t)svc_pipe);

    if (!CreateEnvironmentBlock(&user_env, imp_token, FALSE))
    {
        ReturnLastError(pipe, L"CreateEnvironmentBlock");
        goto out;
    }

    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = stdin_read;
    startup_info.hStdOutput = stdout_write;
    startup_info.hStdError = stdout_write;

    exe_path = settings.exe_path;

    /* TODO: make sure HKCU is correct or call LoadUserProfile() */
    if (!CreateProcessAsUserW(pri_token, exe_path, cmdline, &ovpn_sa, NULL, TRUE,
                              settings.priority | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                              user_env, sud.directory, &startup_info, &proc_info))
    {
        ReturnLastError(pipe, L"CreateProcessAsUser");
        goto out;
    }

    if (!RevertToSelf())
    {
        TerminateProcess(proc_info.hProcess, 1);
        ReturnLastError(pipe, L"RevertToSelf");
        goto out;
    }

    ReturnProcessId(pipe, proc_info.dwProcessId, 1, &exit_event);

    CloseHandleEx(&stdout_write);
    CloseHandleEx(&stdin_read);
    CloseHandleEx(&svc_pipe);

    DWORD input_size = WideCharToMultiByte(CP_UTF8, 0, sud.std_input, -1, NULL, 0, NULL, NULL);
    LPSTR input = NULL;
    if (input_size && (input = malloc(input_size)))
    {
        DWORD written;
        WideCharToMultiByte(CP_UTF8, 0, sud.std_input, -1, input, input_size, NULL, NULL);
        WriteFile(stdin_write, input, (DWORD)strlen(input), &written, NULL);
        free(input);
    }

    while (TRUE)
    {
        DWORD bytes = PeekNamedPipeAsync(ovpn_pipe, 1, &exit_event);
        if (bytes == 0)
        {
            break;
        }

        if (bytes > sizeof(pipe_message_t))
        {
            /* process at the other side of the pipe is misbehaving, shut it down */
            MsgToEventLog(MSG_FLAGS_ERROR, L"OpenVPN process sent too large payload length to the pipe (%lu bytes), it will be terminated", bytes);
            break;
        }

        HandleMessage(ovpn_pipe, &proc_info, bytes, 1, &exit_event, &undo_lists);
    }

    WaitForSingleObject(proc_info.hProcess, IO_TIMEOUT);
    GetExitCodeProcess(proc_info.hProcess, &exit_code);
    if (exit_code == STILL_ACTIVE)
    {
        TerminateProcess(proc_info.hProcess, 1);
    }
    else if (exit_code != 0)
    {
        WCHAR buf[256];
        swprintf(buf, _countof(buf),
                 L"OpenVPN exited with error: exit code = %lu", exit_code);
        ReturnError(pipe, ERROR_OPENVPN_STARTUP, buf, 1, &exit_event);
    }
    Undo(&undo_lists);

out:
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);

    free(ovpn_user);
    free(svc_user);
    free(cmdline);
    DestroyEnvironmentBlock(user_env);
    FreeStartupData(&sud);
    CloseHandleEx(&proc_info.hProcess);
    CloseHandleEx(&proc_info.hThread);
    CloseHandleEx(&stdin_read);
    CloseHandleEx(&stdin_write);
    CloseHandleEx(&stdout_write);
    CloseHandleEx(&svc_token);
    CloseHandleEx(&imp_token);
    CloseHandleEx(&pri_token);
    CloseHandleEx(&ovpn_pipe);
    CloseHandleEx(&svc_pipe);
    CloseHandleEx(&pipe);

    return 0;
}


static DWORD WINAPI
ServiceCtrlInteractive(DWORD ctrl_code, DWORD event, LPVOID data, LPVOID ctx)
{
    SERVICE_STATUS *status = ctx;
    switch (ctrl_code)
    {
        case SERVICE_CONTROL_STOP:
            status->dwCurrentState = SERVICE_STOP_PENDING;
            ReportStatusToSCMgr(service, status);
            if (exit_event)
            {
                SetEvent(exit_event);
            }
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}


static HANDLE
CreateClientPipeInstance(VOID)
{
    /*
     * allow all access for local system
     * deny FILE_CREATE_PIPE_INSTANCE for everyone
     * allow read/write for authenticated users
     * deny all access to anonymous
     */
    const WCHAR *sddlString = L"D:(A;OICI;GA;;;S-1-5-18)(D;OICI;0x4;;;S-1-1-0)(A;OICI;GRGW;;;S-1-5-11)(D;;GA;;;S-1-5-7)";

    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddlString, SDDL_REVISION_1, &sd, NULL))
    {
        MsgToEventLog(M_SYSERR, L"ConvertStringSecurityDescriptorToSecurityDescriptor failed.");
        return INVALID_HANDLE_VALUE;
    }

    /* Set up SECURITY_ATTRIBUTES */
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    DWORD flags = PIPE_ACCESS_DUPLEX | WRITE_DAC | FILE_FLAG_OVERLAPPED;

    static BOOL first = TRUE;
    if (first)
    {
        flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        first = FALSE;
    }

    WCHAR pipe_name[256]; /* The entire pipe name string can be up to 256 characters long according to MSDN. */
    swprintf(pipe_name, _countof(pipe_name), L"\\\\.\\pipe\\" _L(PACKAGE) L"%ls\\service", service_instance);
    HANDLE pipe = CreateNamedPipe(pipe_name, flags,
                                  PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                                  PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, &sa);

    LocalFree(sd);

    if (pipe == INVALID_HANDLE_VALUE)
    {
        MsgToEventLog(M_SYSERR, L"Could not create named pipe");
        return INVALID_HANDLE_VALUE;
    }

    return pipe;
}


static DWORD
UpdateWaitHandles(LPHANDLE *handles_ptr, LPDWORD count,
                  HANDLE io_event, HANDLE exit_event, list_item_t *threads)
{
    static DWORD size = 10;
    static LPHANDLE handles = NULL;
    DWORD pos = 0;

    if (handles == NULL)
    {
        handles = malloc(size * sizeof(HANDLE));
        *handles_ptr = handles;
        if (handles == NULL)
        {
            return ERROR_OUTOFMEMORY;
        }
    }

    handles[pos++] = io_event;

    if (!threads)
    {
        handles[pos++] = exit_event;
    }

    while (threads)
    {
        if (pos == size)
        {
            LPHANDLE tmp;
            size += 10;
            tmp = realloc(handles, size * sizeof(HANDLE));
            if (tmp == NULL)
            {
                size -= 10;
                *count = pos;
                return ERROR_OUTOFMEMORY;
            }
            handles = tmp;
            *handles_ptr = handles;
        }
        handles[pos++] = threads->data;
        threads = threads->next;
    }

    *count = pos;
    return NO_ERROR;
}


static VOID
FreeWaitHandles(LPHANDLE h)
{
    free(h);
}

static BOOL
CmpHandle(LPVOID item, LPVOID hnd)
{
    return item == hnd;
}


VOID WINAPI
ServiceStartInteractiveOwn(DWORD dwArgc, LPWSTR *lpszArgv)
{
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStartInteractive(dwArgc, lpszArgv);
}

/**
 * Clean up remains of previous sessions in registry. These remains can
 * happen with unclean shutdowns or crashes and would interfere with
 * normal operation of the system with and without active tunnels.
 */
static void
CleanupRegistry(void)
{
    BOOL changed = FALSE;

    /* Clean up leftover NRPT rules */
    BOOL gpol_nrpt;
    changed = DeleteNrptRules(0, &gpol_nrpt);

    /* Clean up leftover DNS search list fragments */
    HKEY key;
    BOOL gpol_list;
    GetDnsSearchListKey(NULL, &gpol_list, &key);
    if (key != INVALID_HANDLE_VALUE)
    {
        if (ResetDnsSearchDomains(key))
        {
            changed = TRUE;
        }
        RegCloseKey(key);
    }

    if (changed)
    {
        ApplyDnsSettings(gpol_nrpt || gpol_list);
    }
}

VOID WINAPI
ServiceStartInteractive(DWORD dwArgc, LPWSTR *lpszArgv)
{
    HANDLE pipe, io_event = NULL;
    OVERLAPPED overlapped;
    DWORD error = NO_ERROR;
    list_item_t *threads = NULL;
    PHANDLE handles = NULL;
    DWORD handle_count;

    service = RegisterServiceCtrlHandlerEx(interactive_service.name, ServiceCtrlInteractive, &status);
    if (!service)
    {
        return;
    }

    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwServiceSpecificExitCode = NO_ERROR;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwWaitHint = 3000;
    ReportStatusToSCMgr(service, &status);

    /* Clean up potentially left over registry values */
    CleanupRegistry();

    /* Read info from registry in key HKLM\SOFTWARE\OpenVPN */
    error = GetOpenvpnSettings(&settings);
    if (error != ERROR_SUCCESS)
    {
        goto out;
    }

    io_event = InitOverlapped(&overlapped);
    exit_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!exit_event || !io_event)
    {
        error = MsgToEventLog(M_SYSERR, L"Could not create event");
        goto out;
    }

    rdns_semaphore = CreateSemaphoreW(NULL, 1, 1, NULL);
    if (!rdns_semaphore)
    {
        error = MsgToEventLog(M_SYSERR, L"Could not create semaphore for register-dns");
        goto out;
    }

    error = UpdateWaitHandles(&handles, &handle_count, io_event, exit_event, threads);
    if (error != NO_ERROR)
    {
        goto out;
    }

    pipe = CreateClientPipeInstance();
    if (pipe == INVALID_HANDLE_VALUE)
    {
        goto out;
    }

    status.dwCurrentState = SERVICE_RUNNING;
    status.dwWaitHint = 0;
    ReportStatusToSCMgr(service, &status);

    while (TRUE)
    {
        if (ConnectNamedPipe(pipe, &overlapped) == FALSE
            && GetLastError() != ERROR_PIPE_CONNECTED
            && GetLastError() != ERROR_IO_PENDING)
        {
            MsgToEventLog(M_SYSERR, L"Could not connect pipe");
            break;
        }

        error = WaitForMultipleObjects(handle_count, handles, FALSE, INFINITE);
        if (error == WAIT_OBJECT_0)
        {
            /* Client connected, spawn a worker thread for it */
            HANDLE next_pipe = CreateClientPipeInstance();
            HANDLE thread = CreateThread(NULL, 0, RunOpenvpn, pipe, CREATE_SUSPENDED, NULL);
            if (thread)
            {
                error = AddListItem(&threads, thread);
                if (!error)
                {
                    error = UpdateWaitHandles(&handles, &handle_count, io_event, exit_event, threads);
                }
                if (error)
                {
                    ReturnError(pipe, error, L"Insufficient resources to service new clients", 1, &exit_event);
                    /* Update wait handles again after removing the last worker thread */
                    RemoveListItem(&threads, CmpHandle, thread);
                    UpdateWaitHandles(&handles, &handle_count, io_event, exit_event, threads);
                    TerminateThread(thread, 1);
                    CloseHandleEx(&thread);
                    CloseHandleEx(&pipe);
                }
                else
                {
                    ResumeThread(thread);
                }
            }
            else
            {
                CloseHandleEx(&pipe);
            }

            ResetOverlapped(&overlapped);
            pipe = next_pipe;
        }
        else
        {
            CancelIo(pipe);
            if (error == WAIT_FAILED)
            {
                MsgToEventLog(M_SYSERR, L"WaitForMultipleObjects failed");
                SetEvent(exit_event);
                /* Give some time for worker threads to exit and then terminate */
                Sleep(1000);
                break;
            }
            if (!threads)
            {
                /* exit event signaled */
                CloseHandleEx(&pipe);
                ResetEvent(exit_event);
                error = NO_ERROR;
                break;
            }

            /* Worker thread ended */
            HANDLE thread = RemoveListItem(&threads, CmpHandle, handles[error]);
            UpdateWaitHandles(&handles, &handle_count, io_event, exit_event, threads);
            CloseHandleEx(&thread);
        }
    }

out:
    FreeWaitHandles(handles);
    CloseHandleEx(&io_event);
    CloseHandleEx(&exit_event);
    CloseHandleEx(&rdns_semaphore);

    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = error;
    ReportStatusToSCMgr(service, &status);
}
