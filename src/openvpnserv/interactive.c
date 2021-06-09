/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2012-2021 Heiko Hund <heiko.hund@sophos.com>
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

#ifdef HAVE_VERSIONHELPERS_H
#include <versionhelpers.h>
#else
#include "compat-versionhelpers.h"
#endif

#include "openvpn-msg.h"
#include "validate.h"
#include "block_dns.h"
#include "ring_buffer.h"

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
    TEXT(PACKAGE_NAME "ServiceInteractive"),
    TEXT(PACKAGE_NAME " Interactive Service"),
    TEXT(SERVICE_DEPENDENCIES),
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
    block_dns,
    undo_dns4,
    undo_dns6,
    undo_domain,
    _undo_type_max
} undo_type_t;
typedef list_item_t *undo_lists_t[_undo_type_max];

typedef struct {
    HANDLE engine;
    int index;
    int metric_v4;
    int metric_v6;
} block_dns_data_t;

typedef struct {
    HANDLE send_ring_handle;
    HANDLE receive_ring_handle;
    HANDLE send_tail_moved;
    HANDLE receive_tail_moved;
    HANDLE device;
} ring_buffer_handles_t;


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
OvpnUnmapViewOfFile(LPHANDLE handle)
{
    if (handle && *handle && *handle != INVALID_HANDLE_VALUE)
    {
        UnmapViewOfFile(*handle);
        *handle = INVALID_HANDLE_VALUE;
    }
    return INVALID_HANDLE_VALUE;
}

static void
CloseRingBufferHandles(ring_buffer_handles_t *ring_buffer_handles)
{
    CloseHandleEx(&ring_buffer_handles->device);
    CloseHandleEx(&ring_buffer_handles->receive_tail_moved);
    CloseHandleEx(&ring_buffer_handles->send_tail_moved);
    OvpnUnmapViewOfFile(&ring_buffer_handles->send_ring_handle);
    OvpnUnmapViewOfFile(&ring_buffer_handles->receive_ring_handle);
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
    openvpn_swprintf(buf, _countof(buf), L"0x%08x\n0x%08x\n%ls", 0, pid, msg);

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
        openvpn_swprintf(errmsg, capacity,
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
            openvpn_swprintf(errmsg, capacity, msg1, argv[0], workdir,
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
                openvpn_swprintf(errmsg, capacity, msg1, argv[i+1], workdir,
                                 settings.ovpn_admin_group);
            }
            else
            {
                openvpn_swprintf(errmsg, capacity, msg2, argv[i],
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
        MsgToEventLog(M_SYSERR, TEXT("PeekNamedPipeAsync failed"));
        ReturnLastError(pipe, L"PeekNamedPipeAsync");
        goto err;
    }

    size = bytes / sizeof(*data);
    if (size == 0)
    {
        MsgToEventLog(M_SYSERR, TEXT("malformed startup data: 1 byte received"));
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto err;
    }

    data = malloc(bytes);
    if (data == NULL)
    {
        MsgToEventLog(M_SYSERR, TEXT("malloc failed"));
        ReturnLastError(pipe, L"malloc");
        goto err;
    }

    read = ReadPipeAsync(pipe, data, bytes, 1, &exit_event);
    if (bytes != read)
    {
        MsgToEventLog(M_SYSERR, TEXT("ReadPipeAsync failed"));
        ReturnLastError(pipe, L"ReadPipeAsync");
        goto err;
    }

    if (data[size - 1] != 0)
    {
        MsgToEventLog(M_ERR, TEXT("Startup data is not NULL terminated"));
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto err;
    }

    sud->directory = data;
    len = wcslen(sud->directory) + 1;
    size -= len;
    if (size <= 0)
    {
        MsgToEventLog(M_ERR, TEXT("Startup data ends at working directory"));
        ReturnError(pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
        goto err;
    }

    sud->options = sud->directory + len;
    len = wcslen(sud->options) + 1;
    size -= len;
    if (size <= 0)
    {
        MsgToEventLog(M_ERR, TEXT("Startup data ends at command line options"));
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

static DWORD
ConvertInterfaceNameToIndex(const wchar_t *ifname, NET_IFINDEX *index)
{
   NET_LUID luid;
   DWORD err;

   err = ConvertInterfaceAliasToLuid(ifname, &luid);
   if (err == ERROR_SUCCESS)
   {
       err = ConvertInterfaceLuidToIndex(&luid, index);
   }
   if (err != ERROR_SUCCESS)
   {
       MsgToEventLog(M_ERR, L"Failed to find interface index for <%ls>", ifname);
   }
   return err;
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
    TCHAR buf[256];
    LPCTSTR err_str;

    if (!err)
    {
        return;
    }

    err_str = TEXT("Unknown Win32 Error");

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
CmpEngine(LPVOID item, LPVOID any)
{
    return TRUE;
}

static DWORD
HandleBlockDNSMessage(const block_dns_message_t *msg, undo_lists_t *lists)
{
    DWORD err = 0;
    block_dns_data_t *interface_data;
    HANDLE engine = NULL;
    LPCWSTR exe_path;

    exe_path = settings.exe_path;

    if (msg->header.type == msg_add_block_dns)
    {
        err = add_block_dns_filters(&engine, msg->iface.index, exe_path, BlockDNSErrHandler);
        if (!err)
        {
            interface_data = malloc(sizeof(block_dns_data_t));
            if (!interface_data)
            {
                return ERROR_OUTOFMEMORY;
            }
            interface_data->engine = engine;
            interface_data->index = msg->iface.index;
            int is_auto = 0;
            interface_data->metric_v4 = get_interface_metric(msg->iface.index,
                                                             AF_INET, &is_auto);
            if (is_auto)
            {
                interface_data->metric_v4 = 0;
            }
            interface_data->metric_v6 = get_interface_metric(msg->iface.index,
                                                             AF_INET6, &is_auto);
            if (is_auto)
            {
                interface_data->metric_v6 = 0;
            }
            err = AddListItem(&(*lists)[block_dns], interface_data);
            if (!err)
            {
                err = set_interface_metric(msg->iface.index, AF_INET,
                                           BLOCK_DNS_IFACE_METRIC);
                if (!err)
                {
                    set_interface_metric(msg->iface.index, AF_INET6,
                                         BLOCK_DNS_IFACE_METRIC);
                }
            }
        }
    }
    else
    {
        interface_data = RemoveListItem(&(*lists)[block_dns], CmpEngine, NULL);
        if (interface_data)
        {
            engine = interface_data->engine;
            err = delete_block_dns_filters(engine);
            engine = NULL;
            if (interface_data->metric_v4 >= 0)
            {
                set_interface_metric(msg->iface.index, AF_INET,
                                     interface_data->metric_v4);
            }
            if (interface_data->metric_v6 >= 0)
            {
                set_interface_metric(msg->iface.index, AF_INET6,
                                     interface_data->metric_v6);
            }
            free(interface_data);
        }
        else
        {
            MsgToEventLog(M_ERR, TEXT("No previous block DNS filters to delete"));
        }
    }

    if (err && engine)
    {
        delete_block_dns_filters(engine);
    }

    return err;
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
            MsgToEventLog(M_SYSERR, TEXT("ExecCommand: Error getting exit_code:"));
            exit_code = GetLastError();
        }
        else if (exit_code == STILL_ACTIVE)
        {
            exit_code = WAIT_TIMEOUT; /* Windows error code 0x102 */

            /* kill without impunity */
            TerminateProcess(pi.hProcess, exit_code);
            MsgToEventLog(M_ERR, TEXT("ExecCommand: \"%ls %ls\" killed after timeout"),
                          argv0, cmdline);
        }
        else if (exit_code)
        {
            MsgToEventLog(M_ERR, TEXT("ExecCommand: \"%ls %ls\" exited with status = %lu"),
                          argv0, cmdline, exit_code);
        }
        else
        {
            MsgToEventLog(M_INFO, TEXT("ExecCommand: \"%ls %ls\" completed"), argv0, cmdline);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        exit_code = GetLastError();
        MsgToEventLog(M_SYSERR, TEXT("ExecCommand: could not run \"%ls %ls\" :"),
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

    openvpn_swprintf(ipcfg, MAX_PATH, L"%ls\\%ls", get_win_sys_path(), L"ipconfig.exe");

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
            err = MsgToEventLog(M_SYSERR, TEXT("RegisterDNS: Failed to release regsiter-dns semaphore:"));
        }
    }
    else
    {
        MsgToEventLog(M_ERR, TEXT("RegisterDNS: Failed to lock register-dns semaphore"));
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
 * Run the command: netsh interface $proto $action dns $if_name $addr [validate=no]
 * @param  action      "delete" or "add"
 * @param  proto       "ipv6" or "ip"
 * @param  if_name     "name_of_interface"
 * @param  addr         IPv4 (for proto = ip) or IPv6 address as a string
 *
 * If addr is null and action = "delete" all addresses are deleted.
 */
static DWORD
netsh_dns_cmd(const wchar_t *action, const wchar_t *proto, const wchar_t *if_name, const wchar_t *addr)
{
    DWORD err = 0;
    int timeout = 30000; /* in msec */
    wchar_t argv0[MAX_PATH];
    wchar_t *cmdline = NULL;

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
    openvpn_swprintf(argv0, _countof(argv0), L"%ls\\%ls", get_win_sys_path(), L"netsh.exe");

    /* cmd template:
     * netsh interface $proto $action dns $if_name $addr [validate=no]
     */
    const wchar_t *fmt = L"netsh interface %ls %ls dns \"%ls\" %ls";

    /* max cmdline length in wchars -- include room for worst case and some */
    size_t ncmdline = wcslen(fmt) + wcslen(if_name) + wcslen(addr) + 32 + 1;
    cmdline = malloc(ncmdline*sizeof(wchar_t));
    if (!cmdline)
    {
        err = ERROR_OUTOFMEMORY;
        goto out;
    }

    openvpn_swprintf(cmdline, ncmdline, fmt, proto, action, if_name, addr);

    if (IsWindows7OrGreater())
    {
        wcscat_s(cmdline, ncmdline, L" validate=no");
    }
    err = ExecCommand(argv0, cmdline, timeout);

out:
    free(cmdline);
    return err;
}

/**
 * Run command: wmic nicconfig (InterfaceIndex=$if_index) call $action ($data)
 * @param  if_index    "index of interface"
 * @param  action      e.g., "SetDNSDomain"
 * @param  data        data if required for action
 *                     - a single word for SetDNSDomain, empty or NULL to delete
 *                     - comma separated values for a list
 */
static DWORD
wmic_nicconfig_cmd(const wchar_t *action, const NET_IFINDEX if_index,
                   const wchar_t *data)
{
    DWORD err = 0;
    wchar_t argv0[MAX_PATH];
    wchar_t *cmdline = NULL;
    int timeout = 10000; /* in msec */

    openvpn_swprintf(argv0, _countof(argv0), L"%ls\\%ls", get_win_sys_path(), L"wbem\\wmic.exe");

    const wchar_t *fmt;
    /* comma separated list must be enclosed in parenthesis */
    if (data && wcschr(data, L','))
    {
       fmt = L"wmic nicconfig where (InterfaceIndex=%ld) call %ls (%ls)";
    }
    else
    {
       fmt = L"wmic nicconfig where (InterfaceIndex=%ld) call %ls \"%ls\"";
    }

    size_t ncmdline = wcslen(fmt) + 20 + wcslen(action) /* max 20 for ifindex */
                    + (data ? wcslen(data) + 1 : 1);
    cmdline = malloc(ncmdline*sizeof(wchar_t));
    if (!cmdline)
    {
        return ERROR_OUTOFMEMORY;
    }

    openvpn_swprintf(cmdline, ncmdline, fmt, if_index, action,
                      data? data : L"");
    err = ExecCommand(argv0, cmdline, timeout);

    free(cmdline);
    return err;
}

/* Delete all IPv4 or IPv6 dns servers for an interface */
static DWORD
DeleteDNS(short family, wchar_t *if_name)
{
    wchar_t *proto = (family == AF_INET6) ? L"ipv6" : L"ip";
    return netsh_dns_cmd(L"delete", proto, if_name, NULL);
}

/* Add an IPv4 or IPv6 dns server to an interface */
static DWORD
AddDNS(short family, wchar_t *if_name, wchar_t *addr)
{
    wchar_t *proto = (family == AF_INET6) ? L"ipv6" : L"ip";
    return netsh_dns_cmd(L"add", proto, if_name, addr);
}

static BOOL
CmpWString(LPVOID item, LPVOID str)
{
    return (wcscmp(item, str) == 0) ? TRUE : FALSE;
}

/**
 * Set interface specific DNS domain suffix
 * @param  if_name    name of the the interface
 * @param  domain     a single domain name
 * @param  lists      pointer to the undo lists. If NULL
 *                    undo lists are not altered.
 * Will delete the currently set value if domain is empty.
 */
static DWORD
SetDNSDomain(const wchar_t *if_name, const char *domain, undo_lists_t *lists)
{
   NET_IFINDEX if_index;

   DWORD err  = ConvertInterfaceNameToIndex(if_name, &if_index);
   if (err != ERROR_SUCCESS)
   {
       return err;
   }

   wchar_t *wdomain = utf8to16(domain); /* utf8 to wide-char */
   if (!wdomain)
   {
       return ERROR_OUTOFMEMORY;
   }

   /* free undo list if previously set */
   if (lists)
   {
       free(RemoveListItem(&(*lists)[undo_domain], CmpWString, (void *)if_name));
   }

   err = wmic_nicconfig_cmd(L"SetDNSDomain", if_index, wdomain);

   /* Add to undo list if domain is non-empty */
   if (err == 0 && wdomain[0] && lists)
   {
        wchar_t *tmp_name = _wcsdup(if_name);
        if (!tmp_name || AddListItem(&(*lists)[undo_domain], tmp_name))
        {
            free(tmp_name);
            err = ERROR_OUTOFMEMORY;
        }
   }

   free(wdomain);
   return err;
}

static DWORD
HandleDNSConfigMessage(const dns_cfg_message_t *msg, undo_lists_t *lists)
{
    DWORD err = 0;
    wchar_t addr[46]; /* large enough to hold string representation of an ipv4 / ipv6 address */
    undo_type_t undo_type = (msg->family == AF_INET6) ? undo_dns4 : undo_dns6;
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
        dns_cfg_message_t *msgptr = (dns_cfg_message_t *) msg;
        msgptr->iface.name[_countof(msg->iface.name)-1] = '\0';
        msgptr->domains[_countof(msg->domains)-1] = '\0';
    }

    wchar_t *wide_name = utf8to16(msg->iface.name); /* utf8 to wide-char */
    if (!wide_name)
    {
        return ERROR_OUTOFMEMORY;
    }

    /* We delete all current addresses before adding any
     * OR if the message type is del_dns_cfg
     */
    if (addr_len > 0 || msg->header.type == msg_del_dns_cfg)
    {
        err = DeleteDNS(msg->family, wide_name);
        if (err)
        {
            goto out;
        }
        free(RemoveListItem(&(*lists)[undo_type], CmpWString, wide_name));
    }

    if (msg->header.type == msg_del_dns_cfg)
    {
        if (msg->domains[0])
        {
            /* setting an empty domain removes any previous value */
            err = SetDNSDomain(wide_name, "", lists);
        }
        goto out;  /* job done */
    }

    for (int i = 0; i < addr_len; ++i)
    {
        if (msg->family == AF_INET6)
        {
            RtlIpv6AddressToStringW(&msg->addr[i].ipv6, addr);
        }
        else
        {
            RtlIpv4AddressToStringW(&msg->addr[i].ipv4, addr);
        }
        err = AddDNS(msg->family, wide_name, addr);
        if (i == 0 && err)
        {
            goto out;
        }
        /* We do not check for duplicate addresses, so any error in adding
         * additional addresses is ignored.
         */
    }

    err = 0;

    if (msg->addr_len > 0)
    {
        wchar_t *tmp_name = _wcsdup(wide_name);
        if (!tmp_name || AddListItem(&(*lists)[undo_type], tmp_name))
        {
            free(tmp_name);
            DeleteDNS(msg->family, wide_name);
            err = ERROR_OUTOFMEMORY;
            goto out;
        }
    }

    if (msg->domains[0])
    {
        err = SetDNSDomain(wide_name, msg->domains, lists);
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
    openvpn_swprintf(argv0, _countof(argv0), L"%ls\\%ls", get_win_sys_path(), L"netsh.exe");

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

    openvpn_swprintf(cmdline, ncmdline, fmt, dhcp->iface.index);

    err = ExecCommand(argv0, cmdline, timeout);

    /* Note: This could fail if dhcp is already enabled, so the caller
     * may not want to treat errors as FATAL.
     */

    free(cmdline);
    return err;
}

static DWORD
OvpnDuplicateHandle(HANDLE ovpn_proc, HANDLE orig_handle, HANDLE* new_handle)
{
    DWORD err = ERROR_SUCCESS;

    if (!DuplicateHandle(ovpn_proc, orig_handle, GetCurrentProcess(), new_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        err = GetLastError();
        MsgToEventLog(M_SYSERR, TEXT("Could not duplicate handle"));
        return err;
    }

    return err;
}

static DWORD
DuplicateAndMapRing(HANDLE ovpn_proc, HANDLE orig_handle, HANDLE *new_handle, struct tun_ring **ring)
{
    DWORD err = ERROR_SUCCESS;

    err = OvpnDuplicateHandle(ovpn_proc, orig_handle, new_handle);
    if (err != ERROR_SUCCESS)
    {
        return err;
    }
    *ring = (struct tun_ring *)MapViewOfFile(*new_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(struct tun_ring));
    if (*ring == NULL)
    {
        err = GetLastError();
        MsgToEventLog(M_SYSERR, TEXT("Could not map shared memory"));
        return err;
    }

    return err;
}

static DWORD
HandleRegisterRingBuffers(const register_ring_buffers_message_t *rrb, HANDLE ovpn_proc,
                          ring_buffer_handles_t *ring_buffer_handles)
{
    DWORD err = 0;
    struct tun_ring *send_ring;
    struct tun_ring *receive_ring;

    CloseRingBufferHandles(ring_buffer_handles);

    err = OvpnDuplicateHandle(ovpn_proc, rrb->device, &ring_buffer_handles->device);
    if (err != ERROR_SUCCESS)
    {
        return err;
    }

    err = DuplicateAndMapRing(ovpn_proc, rrb->send_ring_handle, &ring_buffer_handles->send_ring_handle, &send_ring);
    if (err != ERROR_SUCCESS)
    {
        return err;
    }

    err = DuplicateAndMapRing(ovpn_proc, rrb->receive_ring_handle, &ring_buffer_handles->receive_ring_handle, &receive_ring);
    if (err != ERROR_SUCCESS)
    {
        return err;
    }

    err = OvpnDuplicateHandle(ovpn_proc, rrb->send_tail_moved, &ring_buffer_handles->send_tail_moved);
    if (err != ERROR_SUCCESS)
    {
        return err;
    }

    err = OvpnDuplicateHandle(ovpn_proc, rrb->receive_tail_moved, &ring_buffer_handles->receive_tail_moved);
    if (err != ERROR_SUCCESS)
    {
        return err;
    }

    if (!register_ring_buffers(ring_buffer_handles->device, send_ring, receive_ring,
                               ring_buffer_handles->send_tail_moved, ring_buffer_handles->receive_tail_moved))
    {
        err = GetLastError();
        MsgToEventLog(M_SYSERR, TEXT("Could not register ring buffers"));
    }

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

static VOID
HandleMessage(HANDLE pipe, HANDLE ovpn_proc, ring_buffer_handles_t *ring_buffer_handles,
              DWORD bytes, DWORD count, LPHANDLE events, undo_lists_t *lists)
{
    DWORD read;
    union {
        message_header_t header;
        address_message_t address;
        route_message_t route;
        flush_neighbors_message_t flush_neighbors;
        block_dns_message_t block_dns;
        dns_cfg_message_t dns;
        enable_dhcp_message_t dhcp;
        register_ring_buffers_message_t rrb;
        set_mtu_message_t mtu;
    } msg;
    ack_message_t ack = {
        .header = {
            .type = msg_acknowledgement,
            .size = sizeof(ack),
            .message_id = -1
        },
        .error_number = ERROR_MESSAGE_DATA
    };

    read = ReadPipeAsync(pipe, &msg, bytes, count, events);
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

        case msg_add_block_dns:
        case msg_del_block_dns:
            if (msg.header.size == sizeof(msg.block_dns))
            {
                ack.error_number = HandleBlockDNSMessage(&msg.block_dns, lists);
            }
            break;

        case msg_register_dns:
            ack.error_number = HandleRegisterDNSMessage();
            break;

        case msg_add_dns_cfg:
        case msg_del_dns_cfg:
            ack.error_number = HandleDNSConfigMessage(&msg.dns, lists);
            break;

        case msg_enable_dhcp:
            if (msg.header.size == sizeof(msg.dhcp))
            {
                ack.error_number = HandleEnableDHCPMessage(&msg.dhcp);
            }
            break;

        case msg_register_ring_buffers:
            if (msg.header.size == sizeof(msg.rrb))
            {
                ack.error_number = HandleRegisterRingBuffers(&msg.rrb, ovpn_proc, ring_buffer_handles);
            }
            break;

        case msg_set_mtu:
            if (msg.header.size == sizeof(msg.mtu))
            {
                ack.error_number = HandleMTUMessage(&msg.mtu);
            }
            break;

        default:
            ack.error_number = ERROR_MESSAGE_TYPE;
            MsgToEventLog(MSG_FLAGS_ERROR, TEXT("Unknown message type %d"), msg.header.type);
            break;
    }

out:
    WritePipeAsync(pipe, &ack, sizeof(ack), count, events);
}


static VOID
Undo(undo_lists_t *lists)
{
    undo_type_t type;
    block_dns_data_t *interface_data;
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
                    DeleteDNS(AF_INET, item->data);
                    break;

                case undo_dns6:
                    DeleteDNS(AF_INET6, item->data);
                    break;

                case undo_domain:
                    SetDNSDomain(item->data, "", NULL);
                    break;

                case block_dns:
                    interface_data = (block_dns_data_t *)(item->data);
                    delete_block_dns_filters(interface_data->engine);
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
    TCHAR ovpn_pipe_name[256]; /* The entire pipe name string can be up to 256 characters long according to MSDN. */
    LPCWSTR exe_path;
    WCHAR *cmdline = NULL;
    size_t cmdline_size;
    undo_lists_t undo_lists;
    ring_buffer_handles_t ring_buffer_handles;
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
    ZeroMemory(&ring_buffer_handles, sizeof(ring_buffer_handles));

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
        && !IsAuthorizedUser(ovpn_user->User.Sid, imp_token, settings.ovpn_admin_group))
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
    ea[0].Trustee.ptstrName = (LPTSTR) svc_user->User.Sid;
    ea[1].grfAccessPermissions = READ_CONTROL | SYNCHRONIZE | PROCESS_VM_READ
                                 |SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea[1].Trustee.ptstrName = (LPTSTR) ovpn_user->User.Sid;

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
    stdout_write = CreateFile(_T("NUL"), GENERIC_WRITE, FILE_SHARE_WRITE,
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

    openvpn_swprintf(ovpn_pipe_name, _countof(ovpn_pipe_name),
                      TEXT("\\\\.\\pipe\\" PACKAGE "%ls\\service_%lu"), service_instance, GetCurrentThreadId());
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
    openvpn_swprintf(cmdline, cmdline_size, L"openvpn %ls --msg-channel %lu",
                      sud.options, svc_pipe);

    if (!CreateEnvironmentBlock(&user_env, imp_token, FALSE))
    {
        ReturnLastError(pipe, L"CreateEnvironmentBlock");
        goto out;
    }

    startup_info.cb = sizeof(startup_info);
    startup_info.lpDesktop = L"winsta0\\default";
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

        HandleMessage(ovpn_pipe, proc_info.hProcess, &ring_buffer_handles, bytes, 1, &exit_event, &undo_lists);
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
        openvpn_swprintf(buf, _countof(buf),
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
    CloseRingBufferHandles(&ring_buffer_handles);
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
    TCHAR pipe_name[256]; /* The entire pipe name string can be up to 256 characters long according to MSDN. */
    HANDLE pipe = NULL;
    PACL old_dacl, new_dacl;
    PSECURITY_DESCRIPTOR sd;
    static EXPLICIT_ACCESS ea[2];
    static BOOL initialized = FALSE;
    DWORD flags = PIPE_ACCESS_DUPLEX | WRITE_DAC | FILE_FLAG_OVERLAPPED;

    if (!initialized)
    {
        PSID everyone, anonymous;

        ConvertStringSidToSid(TEXT("S-1-1-0"), &everyone);
        ConvertStringSidToSid(TEXT("S-1-5-7"), &anonymous);

        ea[0].grfAccessPermissions = FILE_GENERIC_WRITE;
        ea[0].grfAccessMode = GRANT_ACCESS;
        ea[0].grfInheritance = NO_INHERITANCE;
        ea[0].Trustee.pMultipleTrustee = NULL;
        ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        ea[0].Trustee.ptstrName = (LPTSTR) everyone;

        ea[1].grfAccessPermissions = 0;
        ea[1].grfAccessMode = REVOKE_ACCESS;
        ea[1].grfInheritance = NO_INHERITANCE;
        ea[1].Trustee.pMultipleTrustee = NULL;
        ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        ea[1].Trustee.ptstrName = (LPTSTR) anonymous;

        flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        initialized = TRUE;
    }

    openvpn_swprintf(pipe_name, _countof(pipe_name), TEXT("\\\\.\\pipe\\" PACKAGE "%ls\\service"), service_instance);
    pipe = CreateNamedPipe(pipe_name, flags,
                           PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
                           PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        MsgToEventLog(M_SYSERR, TEXT("Could not create named pipe"));
        return INVALID_HANDLE_VALUE;
    }

    if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &old_dacl, NULL, &sd) != ERROR_SUCCESS)
    {
        MsgToEventLog(M_SYSERR, TEXT("Could not get pipe security info"));
        return CloseHandleEx(&pipe);
    }

    if (SetEntriesInAcl(2, ea, old_dacl, &new_dacl) != ERROR_SUCCESS)
    {
        MsgToEventLog(M_SYSERR, TEXT("Could not set entries in new acl"));
        return CloseHandleEx(&pipe);
    }

    if (SetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, new_dacl, NULL) != ERROR_SUCCESS)
    {
        MsgToEventLog(M_SYSERR, TEXT("Could not set pipe security info"));
        return CloseHandleEx(&pipe);
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
ServiceStartInteractiveOwn(DWORD dwArgc, LPTSTR *lpszArgv)
{
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStartInteractive(dwArgc, lpszArgv);
}


VOID WINAPI
ServiceStartInteractive(DWORD dwArgc, LPTSTR *lpszArgv)
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
        error = MsgToEventLog(M_SYSERR, TEXT("Could not create event"));
        goto out;
    }

    rdns_semaphore = CreateSemaphoreW(NULL, 1, 1, NULL);
    if (!rdns_semaphore)
    {
        error = MsgToEventLog(M_SYSERR, TEXT("Could not create semaphore for register-dns"));
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
            MsgToEventLog(M_SYSERR, TEXT("Could not connect pipe"));
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
                MsgToEventLog(M_SYSERR, TEXT("WaitForMultipleObjects failed"));
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
