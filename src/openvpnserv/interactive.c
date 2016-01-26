/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2012 Heiko Hund <heiko.hund@sophos.com>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "service.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <userenv.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>
#include <sddl.h>

#include "openvpn-msg.h"

#define IO_TIMEOUT  2000 /*ms*/

#define ERROR_OPENVPN_STARTUP  0x20000000
#define ERROR_STARTUP_DATA     0x20000001
#define ERROR_MESSAGE_DATA     0x20000002
#define ERROR_MESSAGE_TYPE     0x20000003

static SERVICE_STATUS_HANDLE service;
static SERVICE_STATUS status;
static HANDLE exit_event = NULL;
static settings_t settings;

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
  _undo_type_max
} undo_type_t;
typedef list_item_t* undo_lists_t[_undo_type_max];


static DWORD
AddListItem (list_item_t **pfirst, LPVOID data)
{
  list_item_t *new_item = malloc (sizeof (list_item_t));
  if (new_item == NULL)
    return ERROR_OUTOFMEMORY;

  new_item->next = *pfirst;
  new_item->data = data;

  *pfirst = new_item;
  return NO_ERROR;
}

typedef BOOL (*match_fn_t) (LPVOID item, LPVOID ctx);

static LPVOID
RemoveListItem (list_item_t **pfirst, match_fn_t match, LPVOID ctx)
{
  LPVOID data = NULL;
  list_item_t **pnext;

  for (pnext = pfirst; *pnext; pnext = &(*pnext)->next)
    {
      list_item_t *item = *pnext;
      if (!match (item->data, ctx))
        continue;

      /* Found item, remove from the list and free memory */
      *pnext = item->next;
      data = item->data;
      free (item);
      break;
    }
  return data;
}


static HANDLE
CloseHandleEx (LPHANDLE handle)
{
  if (handle && *handle && *handle != INVALID_HANDLE_VALUE)
    {
      CloseHandle (*handle);
      *handle = INVALID_HANDLE_VALUE;
    }
  return INVALID_HANDLE_VALUE;
}


static HANDLE
InitOverlapped (LPOVERLAPPED overlapped)
{
  ZeroMemory (overlapped, sizeof (OVERLAPPED));
  overlapped->hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
  return overlapped->hEvent;
}


static BOOL
ResetOverlapped (LPOVERLAPPED overlapped)
{
  HANDLE io_event = overlapped->hEvent;
  if (!ResetEvent (io_event))
    return FALSE;
  ZeroMemory (overlapped, sizeof (OVERLAPPED));
  overlapped->hEvent = io_event;
  return TRUE;
}


typedef enum {
  peek,
  read,
  write
} async_op_t;

static DWORD
AsyncPipeOp (async_op_t op, HANDLE pipe, LPVOID buffer, DWORD size, DWORD count, LPHANDLE events)
{
  int i;
  BOOL success;
  HANDLE io_event;
  DWORD res, bytes = 0;
  OVERLAPPED overlapped;
  LPHANDLE handles = NULL;

  io_event = InitOverlapped (&overlapped);
  if (!io_event)
    goto out;

  handles = malloc ((count + 1) * sizeof (HANDLE));
  if (!handles)
    goto out;

  if (op == write)
    success = WriteFile (pipe, buffer, size, NULL, &overlapped);
  else
    success = ReadFile (pipe, buffer, size, NULL, &overlapped);
  if (!success && GetLastError () != ERROR_IO_PENDING && GetLastError () != ERROR_MORE_DATA)
    goto out;

  handles[0] = io_event;
  for (i = 0; i < count; i++)
    handles[i + 1] = events[i];

  res = WaitForMultipleObjects (count + 1, handles, FALSE,
                                op == peek ? INFINITE : IO_TIMEOUT);
  if (res != WAIT_OBJECT_0)
    {
      CancelIo (pipe);
      goto out;
    }

  if (op == peek)
    PeekNamedPipe (pipe, NULL, 0, NULL, &bytes, NULL);
  else
    GetOverlappedResult (pipe, &overlapped, &bytes, TRUE);

out:
  CloseHandleEx (&io_event);
  free (handles);
  return bytes;
}

static DWORD
PeekNamedPipeAsync (HANDLE pipe, DWORD count, LPHANDLE events)
{
  return AsyncPipeOp (peek, pipe, NULL, 0, count, events);
}

static DWORD
ReadPipeAsync (HANDLE pipe, LPVOID buffer, DWORD size, DWORD count, LPHANDLE events)
{
  return AsyncPipeOp (read, pipe, buffer, size, count, events);
}

static DWORD
WritePipeAsync (HANDLE pipe, LPVOID data, DWORD size, DWORD count, LPHANDLE events)
{
  return AsyncPipeOp (write, pipe, data, size, count, events);
}


static VOID
ReturnError (HANDLE pipe, DWORD error, LPCWSTR func, DWORD count, LPHANDLE events)
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
      FormatMessageW (FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      0, error, 0, (LPWSTR) &args[2], 0, NULL);
    }

  result_len = FormatMessageW (FORMAT_MESSAGE_FROM_STRING |
                               FORMAT_MESSAGE_ALLOCATE_BUFFER |
                               FORMAT_MESSAGE_ARGUMENT_ARRAY,
                               L"0x%1!08x!\n%2!s!\n%3!s!", 0, 0,
                               (LPWSTR) &result, 0, (va_list*) args);

  WritePipeAsync (pipe, result, wcslen (result) * 2, count, events);
#ifdef UNICODE
  MsgToEventLog (MSG_FLAGS_ERROR, result);
#else
  MsgToEventLog (MSG_FLAGS_ERROR, "%S", result);
#endif

  if (error != ERROR_OPENVPN_STARTUP)
    LocalFree ((LPVOID) args[2]);
  if (result_len)
    LocalFree (result);
}


static VOID
ReturnLastError (HANDLE pipe, LPCWSTR func)
{
  ReturnError (pipe, GetLastError (), func, 1, &exit_event);
}


static VOID
ReturnOpenvpnOutput (HANDLE pipe, HANDLE ovpn_output, DWORD count, LPHANDLE events)
{
  WCHAR *wide_output = NULL;
  CHAR output[512];
  DWORD size;

  ReadFile (ovpn_output, output, sizeof (output), &size, NULL);
  if (size == 0)
    return;

  wide_output = malloc ((size) * sizeof (WCHAR));
  if (wide_output)
    {
      MultiByteToWideChar (CP_UTF8, 0, output, size, wide_output, size);
      wide_output[size - 1] = 0;
    }

  ReturnError (pipe, ERROR_OPENVPN_STARTUP, wide_output, count, events);
  free (wide_output);
}


static BOOL
GetStartupData (HANDLE pipe, STARTUP_DATA *sud)
{
  size_t len;
  BOOL ret = FALSE;
  WCHAR *data = NULL;
  DWORD size, bytes, read;

  bytes = PeekNamedPipeAsync (pipe, 1, &exit_event);
  if (bytes == 0)
    {
      MsgToEventLog (M_SYSERR, TEXT("PeekNamedPipeAsync failed"));
      ReturnLastError (pipe, L"PeekNamedPipeAsync");
      goto out;
    }

  size = bytes / sizeof (*data);
  data = malloc (bytes);
  if (data == NULL)
    {
      MsgToEventLog (M_SYSERR, TEXT("malloc failed"));
      ReturnLastError (pipe, L"malloc");
      goto out;
    }

  read = ReadPipeAsync (pipe, data, bytes, 1, &exit_event);
  if (bytes != read)
  {
      MsgToEventLog (M_SYSERR, TEXT("ReadPipeAsync failed"));
      ReturnLastError (pipe, L"ReadPipeAsync");
      goto out;
  }

  if (data[size - 1] != 0)
    {
      MsgToEventLog (M_ERR, TEXT("Startup data is not NULL terminated"));
      ReturnError (pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
      goto out;
    }

  sud->directory = data;
  len = wcslen (sud->directory) + 1;
  size -= len;
  if (size <= 0)
    {
      MsgToEventLog (M_ERR, TEXT("Startup data ends at working directory"));
      ReturnError (pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
      goto out;
    }

  sud->options = sud->directory + len;
  len = wcslen (sud->options) + 1;
  size -= len;
  if (size <= 0)
    {
      MsgToEventLog (M_ERR, TEXT("Startup data ends at command line options"));
      ReturnError (pipe, ERROR_STARTUP_DATA, L"GetStartupData", 1, &exit_event);
      goto out;
    }

  sud->std_input = sud->options + len;
  data = NULL; /* don't free data */
  ret = TRUE;

out:
  free (data);
  return ret;
}


static VOID
FreeStartupData (STARTUP_DATA *sud)
{
  free (sud->directory);
}


static SOCKADDR_INET
sockaddr_inet (short family, inet_address_t *addr)
{
  SOCKADDR_INET sa_inet;
  ZeroMemory (&sa_inet, sizeof (sa_inet));
  sa_inet.si_family = family;
  if (family == AF_INET)
    sa_inet.Ipv4.sin_addr = addr->ipv4;
  else if (family == AF_INET6)
    sa_inet.Ipv6.sin6_addr = addr->ipv6;
  return sa_inet;
}

static DWORD
InterfaceLuid (const char *iface_name, PNET_LUID luid)
{
  NETIO_STATUS status;
  LPWSTR wide_name;
  int n;

  typedef NETIO_STATUS WINAPI (*ConvertInterfaceAliasToLuidFn) (LPCWSTR, PNET_LUID);
  static ConvertInterfaceAliasToLuidFn ConvertInterfaceAliasToLuid = NULL;
  if (!ConvertInterfaceAliasToLuid)
    {
      HMODULE iphlpapi = GetModuleHandle (TEXT("iphlpapi.dll"));
      if (iphlpapi == NULL)
        return GetLastError ();

      ConvertInterfaceAliasToLuid = (ConvertInterfaceAliasToLuidFn) GetProcAddress (iphlpapi, "ConvertInterfaceAliasToLuid");
      if (!ConvertInterfaceAliasToLuid)
        return GetLastError ();
    }

  n = MultiByteToWideChar (CP_UTF8, 0, iface_name, -1, NULL, 0);
  wide_name = malloc (n * sizeof (WCHAR));
  MultiByteToWideChar (CP_UTF8, 0, iface_name, -1, wide_name, n);
  status = ConvertInterfaceAliasToLuid (wide_name, luid);
  free (wide_name);

  return status;
}

static BOOL
CmpAddress (LPVOID item, LPVOID address)
{
  return memcmp (item, address, sizeof (MIB_UNICASTIPADDRESS_ROW)) == 0 ? TRUE : FALSE;
}

static DWORD
DeleteAddress (PMIB_UNICASTIPADDRESS_ROW addr_row)
{
  typedef NETIOAPI_API (*DeleteUnicastIpAddressEntryFn) (const PMIB_UNICASTIPADDRESS_ROW);
  static DeleteUnicastIpAddressEntryFn DeleteUnicastIpAddressEntry = NULL;

  if (!DeleteUnicastIpAddressEntry)
    {
      HMODULE iphlpapi = GetModuleHandle (TEXT("iphlpapi.dll"));
      if (iphlpapi == NULL)
        return GetLastError ();

      DeleteUnicastIpAddressEntry = (DeleteUnicastIpAddressEntryFn) GetProcAddress (iphlpapi, "DeleteUnicastIpAddressEntry");
      if (!DeleteUnicastIpAddressEntry)
        return GetLastError ();
    }

  return DeleteUnicastIpAddressEntry (addr_row);
}

static DWORD
HandleAddressMessage (address_message_t *msg, undo_lists_t *lists)
{
  DWORD err;
  PMIB_UNICASTIPADDRESS_ROW addr_row;
  BOOL add = msg->header.type == msg_add_address;

  typedef NETIOAPI_API (*CreateUnicastIpAddressEntryFn) (const PMIB_UNICASTIPADDRESS_ROW);
  typedef NETIOAPI_API (*InitializeUnicastIpAddressEntryFn) (PMIB_UNICASTIPADDRESS_ROW);
  static CreateUnicastIpAddressEntryFn CreateUnicastIpAddressEntry = NULL;
  static InitializeUnicastIpAddressEntryFn InitializeUnicastIpAddressEntry = NULL;

  if (!CreateUnicastIpAddressEntry || !InitializeUnicastIpAddressEntry)
    {
      HMODULE iphlpapi = GetModuleHandle (TEXT("iphlpapi.dll"));
      if (iphlpapi == NULL)
        return GetLastError ();

      CreateUnicastIpAddressEntry = (CreateUnicastIpAddressEntryFn) GetProcAddress (iphlpapi, "CreateUnicastIpAddressEntry");
      if (!CreateUnicastIpAddressEntry)
        return GetLastError ();

      InitializeUnicastIpAddressEntry = (InitializeUnicastIpAddressEntryFn) GetProcAddress (iphlpapi, "InitializeUnicastIpAddressEntry");
      if (!InitializeUnicastIpAddressEntry)
        return GetLastError ();
    }

  addr_row = malloc (sizeof (*addr_row));
  if (addr_row == NULL)
    return ERROR_OUTOFMEMORY;

  InitializeUnicastIpAddressEntry (addr_row);
  addr_row->Address = sockaddr_inet (msg->family, &msg->address);
  addr_row->OnLinkPrefixLength = (UINT8) msg->prefix_len;

  if (msg->iface.index != -1)
    {
      addr_row->InterfaceIndex = msg->iface.index;
    }
  else
    {
      NET_LUID luid;
      err = InterfaceLuid (msg->iface.name, &luid);
      if (err)
        goto out;
      addr_row->InterfaceLuid = luid;
    }

  if (add)
    {
      err = CreateUnicastIpAddressEntry (addr_row);
      if (err)
        goto out;

      err = AddListItem (&(*lists)[address], addr_row);
      if (err)
        DeleteAddress (addr_row);
    }
  else
    {
      err = DeleteAddress (addr_row);
      if (err)
        goto out;

      free (RemoveListItem (&(*lists)[address], CmpAddress, addr_row));
    }

out:
  if (!add || err)
    free (addr_row);

  return err;
}


static BOOL
CmpRoute (LPVOID item, LPVOID route)
{
  return memcmp (item, route, sizeof (MIB_IPFORWARD_ROW2)) == 0 ? TRUE : FALSE;
}

static DWORD
DeleteRoute (PMIB_IPFORWARD_ROW2 fwd_row)
{
  typedef NETIOAPI_API (*DeleteIpForwardEntry2Fn) (PMIB_IPFORWARD_ROW2);
  static DeleteIpForwardEntry2Fn DeleteIpForwardEntry2 = NULL;

  if (!DeleteIpForwardEntry2)
    {
      HMODULE iphlpapi = GetModuleHandle (TEXT("iphlpapi.dll"));
      if (iphlpapi == NULL)
        return GetLastError ();

      DeleteIpForwardEntry2 = (DeleteIpForwardEntry2Fn) GetProcAddress (iphlpapi, "DeleteIpForwardEntry2");
      if (!DeleteIpForwardEntry2)
        return GetLastError ();
    }

  return DeleteIpForwardEntry2 (fwd_row);
}

static DWORD
HandleRouteMessage (route_message_t *msg, undo_lists_t *lists)
{
  DWORD err;
  PMIB_IPFORWARD_ROW2 fwd_row;
  BOOL add = msg->header.type == msg_add_route;

  typedef NETIOAPI_API (*CreateIpForwardEntry2Fn) (PMIB_IPFORWARD_ROW2);
  static CreateIpForwardEntry2Fn CreateIpForwardEntry2 = NULL;

  if (!CreateIpForwardEntry2)
    {
      HMODULE iphlpapi = GetModuleHandle (TEXT("iphlpapi.dll"));
      if (iphlpapi == NULL)
        return GetLastError ();

      CreateIpForwardEntry2 = (CreateIpForwardEntry2Fn) GetProcAddress (iphlpapi, "CreateIpForwardEntry2");
      if (!CreateIpForwardEntry2)
        return GetLastError ();
    }

  fwd_row = malloc (sizeof (*fwd_row));
  if (fwd_row == NULL)
    return ERROR_OUTOFMEMORY;

  ZeroMemory (fwd_row, sizeof (*fwd_row));
  fwd_row->ValidLifetime = 0xffffffff;
  fwd_row->PreferredLifetime = 0xffffffff;
  fwd_row->Protocol = MIB_IPPROTO_NETMGMT;
  fwd_row->Metric = msg->metric;
  fwd_row->DestinationPrefix.Prefix = sockaddr_inet (msg->family, &msg->prefix);
  fwd_row->DestinationPrefix.PrefixLength = (UINT8) msg->prefix_len;
  fwd_row->NextHop = sockaddr_inet (msg->family, &msg->gateway);

  if (msg->iface.index != -1)
    {
      fwd_row->InterfaceIndex = msg->iface.index;
    }
  else if (strlen (msg->iface.name))
    {
      NET_LUID luid;
      err = InterfaceLuid (msg->iface.name, &luid);
      if (err)
        goto out;
      fwd_row->InterfaceLuid = luid;
    }

  if (add)
    {
      err = CreateIpForwardEntry2 (fwd_row);
      if (err)
        goto out;

      err = AddListItem (&(*lists)[route], fwd_row);
      if (err)
        DeleteRoute (fwd_row);
    }
  else
    {
      err = DeleteRoute (fwd_row);
      if (err)
        goto out;

      free (RemoveListItem (&(*lists)[route], CmpRoute, fwd_row));
    }

out:
  if (!add || err)
    free (fwd_row);

  return err;
}


static DWORD
HandleFlushNeighborsMessage (flush_neighbors_message_t *msg)
{
  typedef NETIOAPI_API (*FlushIpNetTable2Fn) (ADDRESS_FAMILY, NET_IFINDEX);
  static FlushIpNetTable2Fn flush_fn = NULL;

  if (msg->family == AF_INET)
    return FlushIpNetTable (msg->iface.index);

  if (!flush_fn)
    {
      HMODULE iphlpapi = GetModuleHandle (TEXT("iphlpapi.dll"));
      if (iphlpapi == NULL)
        return GetLastError ();

      flush_fn = (FlushIpNetTable2Fn) GetProcAddress (iphlpapi, "FlushIpNetTable2");
      if (!flush_fn)
        {
          if (GetLastError () == ERROR_PROC_NOT_FOUND)
            return WSAEPFNOSUPPORT;
          else
            return GetLastError ();
        }
    }
  return flush_fn (msg->family, msg->iface.index);
}


static VOID
HandleMessage (HANDLE pipe, DWORD bytes, DWORD count, LPHANDLE events, undo_lists_t *lists)
{
  DWORD read;
  union {
    message_header_t header;
    address_message_t address;
    route_message_t route;
    flush_neighbors_message_t flush_neighbors;
  } msg;
  ack_message_t ack = {
    .header = {
      .type = msg_acknowledgement,
      .size = sizeof (ack),
      .message_id = -1
    },
    .error_number = ERROR_MESSAGE_DATA
  };

  read = ReadPipeAsync (pipe, &msg, bytes, count, events);
  if (read != bytes || read < sizeof (msg.header) || read != msg.header.size)
    goto out;

  ack.header.message_id = msg.header.message_id;

  switch (msg.header.type)
    {
    case msg_add_address:
    case msg_del_address:
      if (msg.header.size == sizeof (msg.address))
        ack.error_number = HandleAddressMessage (&msg.address, lists);
      break;

    case msg_add_route:
    case msg_del_route:
      if (msg.header.size == sizeof (msg.route))
        ack.error_number = HandleRouteMessage (&msg.route, lists);
      break;

    case msg_flush_neighbors:
      if (msg.header.size == sizeof (msg.flush_neighbors))
        ack.error_number = HandleFlushNeighborsMessage (&msg.flush_neighbors);
      break;

    default:
      ack.error_number = ERROR_MESSAGE_TYPE;
      break;
    }

out:
  WritePipeAsync (pipe, &ack, sizeof (ack), count, events);
}


static VOID
Undo (undo_lists_t *lists)
{
  undo_type_t type;
  for (type = 0; type < _undo_type_max; type++)
    {
      list_item_t **pnext = &(*lists)[type];
      while (*pnext)
        {
          list_item_t *item = *pnext;
          switch (type)
            {
            case address:
              DeleteAddress (item->data);
              break;

            case route:
              DeleteRoute (item->data);
              break;
            }

          /* Remove from the list and free memory */
          *pnext = item->next;
          free (item->data);
          free (item);
        }
    }
}

static DWORD WINAPI
RunOpenvpn (LPVOID p)
{
  HANDLE pipe = p;
  HANDLE ovpn_pipe, svc_pipe;
  PTOKEN_USER svc_user, ovpn_user;
  HANDLE svc_token = NULL, imp_token = NULL, pri_token = NULL;
  HANDLE stdin_read = NULL, stdin_write = NULL;
  HANDLE stdout_read = NULL, stdout_write = NULL;
  DWORD pipe_mode, len, exit_code = 0;
  STARTUP_DATA sud = { 0, 0, 0 };
  STARTUPINFOW startup_info;
  PROCESS_INFORMATION proc_info;
  LPVOID user_env = NULL;
  TCHAR ovpn_pipe_name[36];
  LPCWSTR exe_path;
  WCHAR *cmdline = NULL;
  size_t cmdline_size;
  undo_lists_t undo_lists;

  SECURITY_ATTRIBUTES inheritable = {
    .nLength = sizeof (inheritable),
    .lpSecurityDescriptor = NULL,
    .bInheritHandle = TRUE
  };

  PACL ovpn_dacl;
  EXPLICIT_ACCESS ea[2];
  SECURITY_DESCRIPTOR ovpn_sd;
  SECURITY_ATTRIBUTES ovpn_sa = {
    .nLength = sizeof (ovpn_sa),
    .lpSecurityDescriptor = &ovpn_sd,
    .bInheritHandle = FALSE
  };

  ZeroMemory (&ea, sizeof (ea));
  ZeroMemory (&startup_info, sizeof (startup_info));
  ZeroMemory (&undo_lists, sizeof (undo_lists));
  ZeroMemory (&proc_info, sizeof (proc_info));

  if (!GetStartupData (pipe, &sud))
    goto out;

  if (!InitializeSecurityDescriptor (&ovpn_sd, SECURITY_DESCRIPTOR_REVISION))
    {
      ReturnLastError (pipe, L"InitializeSecurityDescriptor");
      goto out;
    }

  /* Get SID of user the service is running under */
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &svc_token))
    {
      ReturnLastError (pipe, L"OpenProcessToken");
      goto out;
    }
  len = 0;
  svc_user = NULL;
  while (!GetTokenInformation (svc_token, TokenUser, svc_user, len, &len))
    {
      if (GetLastError () != ERROR_INSUFFICIENT_BUFFER)
        {
          ReturnLastError (pipe, L"GetTokenInformation (service token)");
          goto out;
        }
      free (svc_user);
      svc_user = malloc (len);
      if (svc_user == NULL)
        {
          ReturnLastError (pipe, L"malloc (service token user)");
          goto out;
        }
    }
  if (!IsValidSid (svc_user->User.Sid))
    {
      ReturnLastError (pipe, L"IsValidSid (service token user)");
      goto out;
    }

  if (!ImpersonateNamedPipeClient (pipe))
    {
      ReturnLastError (pipe, L"ImpersonateNamedPipeClient");
      goto out;
    }
  if (!OpenThreadToken (GetCurrentThread (), TOKEN_ALL_ACCESS, FALSE, &imp_token))
    {
      ReturnLastError (pipe, L"OpenThreadToken");
      goto out;
    }
  len = 0;
  ovpn_user = NULL;
  while (!GetTokenInformation (imp_token, TokenUser, ovpn_user, len, &len))
    {
      if (GetLastError () != ERROR_INSUFFICIENT_BUFFER)
        {
          ReturnLastError (pipe, L"GetTokenInformation (impersonation token)");
          goto out;
        }
      free (ovpn_user);
      ovpn_user = malloc (len);
      if (ovpn_user == NULL)
        {
          ReturnLastError (pipe, L"malloc (impersonation token user)");
          goto out;
        }
    }
  if (!IsValidSid (ovpn_user->User.Sid))
    {
      ReturnLastError (pipe, L"IsValidSid (impersonation token user)");
      goto out;
    }

  /* OpenVPN process DACL entry for access by service and user */
  ea[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
  ea[0].grfAccessMode = SET_ACCESS;
  ea[0].grfInheritance = NO_INHERITANCE;
  ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[0].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
  ea[0].Trustee.ptstrName = (LPTSTR) svc_user->User.Sid;
  ea[1].grfAccessPermissions = READ_CONTROL | SYNCHRONIZE | PROCESS_VM_READ |
                    SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
  ea[1].grfAccessMode = SET_ACCESS;
  ea[1].grfInheritance = NO_INHERITANCE;
  ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
  ea[1].Trustee.ptstrName = (LPTSTR) ovpn_user->User.Sid;

  /* Set owner and DACL of OpenVPN security descriptor */
  if (!SetSecurityDescriptorOwner (&ovpn_sd, svc_user->User.Sid, FALSE))
    {
      ReturnLastError (pipe, L"SetSecurityDescriptorOwner");
      goto out;
    }
  if (SetEntriesInAcl (2, ea, NULL, &ovpn_dacl) != ERROR_SUCCESS)
    {
      ReturnLastError (pipe, L"SetEntriesInAcl");
      goto out;
    }
  if (!SetSecurityDescriptorDacl (&ovpn_sd, TRUE, ovpn_dacl, FALSE))
    {
      ReturnLastError (pipe, L"SetSecurityDescriptorDacl");
      goto out;
    }

  /* Create primary token from impersonation token */
  if (!DuplicateTokenEx (imp_token, TOKEN_ALL_ACCESS, NULL, 0, TokenPrimary, &pri_token))
    {
      ReturnLastError (pipe, L"DuplicateTokenEx");
      goto out;
    }

  if (!CreatePipe(&stdin_read, &stdin_write, &inheritable, 0) ||
      !CreatePipe(&stdout_read, &stdout_write, &inheritable, 0) ||
      !SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0))
    {
      ReturnLastError (pipe, L"CreatePipe");
      goto out;
    }

  openvpn_sntprintf (ovpn_pipe_name, _countof (ovpn_pipe_name),
    TEXT("\\\\.\\pipe\\openvpn\\service_%lu"), GetCurrentThreadId ());
  ovpn_pipe = CreateNamedPipe (ovpn_pipe_name,
    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 128, 128, 0, NULL);
  if (ovpn_pipe == INVALID_HANDLE_VALUE)
    {
      ReturnLastError (pipe, L"CreateNamedPipe");
      goto out;
    }

  svc_pipe = CreateFile (ovpn_pipe_name, GENERIC_READ | GENERIC_WRITE, 0,
                         &inheritable, OPEN_EXISTING, 0, NULL);
  if (svc_pipe == INVALID_HANDLE_VALUE)
    {
      ReturnLastError (pipe, L"CreateFile");
      goto out;
    }

  pipe_mode = PIPE_READMODE_MESSAGE;
  if (!SetNamedPipeHandleState (svc_pipe, &pipe_mode, NULL, NULL))
    {
      ReturnLastError (pipe, L"SetNamedPipeHandleState");
      goto out;
    }

  cmdline_size = wcslen (sud.options) + 128;
  cmdline = malloc (cmdline_size * sizeof (*cmdline));
  if (cmdline == NULL)
    {
      ReturnLastError (pipe, L"malloc");
      goto out;
    }
  openvpn_sntprintf (cmdline, cmdline_size, L"openvpn %s --msg-channel %lu",
                     sud.options, svc_pipe);

  if (!CreateEnvironmentBlock (&user_env, imp_token, FALSE))
    {
      ReturnLastError (pipe, L"CreateEnvironmentBlock");
      goto out;
    }

  startup_info.cb = sizeof (startup_info);
  startup_info.lpDesktop = L"winsta0\\default";
  startup_info.dwFlags = STARTF_USESTDHANDLES;
  startup_info.hStdInput = stdin_read;
  startup_info.hStdOutput = stdout_write;
  startup_info.hStdError = stdout_write;

#ifdef UNICODE
  exe_path = settings.exe_path;
#else
  WCHAR wide_path[MAX_PATH];
  MultiByteToWideChar (CP_UTF8, 0, settings.exe_path, MAX_PATH, wide_path, MAX_PATH);
  exe_path = wide_path;
#endif

  // TODO: make sure HKCU is correct or call LoadUserProfile()
  if (!CreateProcessAsUserW (pri_token, exe_path, cmdline, &ovpn_sa, NULL, TRUE,
                             settings.priority | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                             user_env, sud.directory, &startup_info, &proc_info))
    {
      ReturnLastError (pipe, L"CreateProcessAsUser");
      goto out;
    }

  if (!RevertToSelf ())
    {
      TerminateProcess (proc_info.hProcess, 1);
      ReturnLastError (pipe, L"RevertToSelf");
      goto out;
    }

  CloseHandleEx (&stdout_write);
  CloseHandleEx (&stdin_read);
  CloseHandleEx (&svc_pipe);

  DWORD input_size = wcslen (sud.std_input) * 2;
  if (input_size)
    {
      DWORD written;
      LPSTR input = malloc (input_size);
      WideCharToMultiByte (CP_UTF8, 0, sud.std_input, -1, input, input_size, NULL, NULL);
      WriteFile (stdin_write, input, strlen (input), &written, NULL);
      free (input);
    }


  while (TRUE)
    {
      DWORD bytes = PeekNamedPipeAsync (ovpn_pipe, 1, &exit_event);
      if (bytes == 0)
        break;

      HandleMessage (ovpn_pipe, bytes, 1, &exit_event, &undo_lists);
    }

  WaitForSingleObject (proc_info.hProcess, IO_TIMEOUT);
  GetExitCodeProcess (proc_info.hProcess, &exit_code);
  if (exit_code == STILL_ACTIVE)
    TerminateProcess (proc_info.hProcess, 1);
  else if (exit_code != 0)
    ReturnOpenvpnOutput (pipe, stdout_read, 1, &exit_event);

  Undo (&undo_lists);

out:
  FlushFileBuffers (pipe);
  DisconnectNamedPipe (pipe);

  free (ovpn_user);
  free (svc_user);
  free (cmdline);
  DestroyEnvironmentBlock (user_env);
  FreeStartupData (&sud);
  CloseHandleEx (&proc_info.hProcess);
  CloseHandleEx (&proc_info.hThread);
  CloseHandleEx (&stdin_read);
  CloseHandleEx (&stdin_write);
  CloseHandleEx (&stdout_read);
  CloseHandleEx (&stdout_write);
  CloseHandleEx (&svc_token);
  CloseHandleEx (&imp_token);
  CloseHandleEx (&pri_token);
  CloseHandleEx (&ovpn_pipe);
  CloseHandleEx (&svc_pipe);
  CloseHandleEx (&pipe);

  return 0;
}


static DWORD WINAPI
ServiceCtrlInteractive (DWORD ctrl_code, DWORD event, LPVOID data, LPVOID ctx)
{
  SERVICE_STATUS *status = ctx;
  switch (ctrl_code)
    {
    case SERVICE_CONTROL_STOP:
      status->dwCurrentState = SERVICE_STOP_PENDING;
      ReportStatusToSCMgr (service, status);
      if (exit_event)
        SetEvent (exit_event);
      return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
      return NO_ERROR;

    default:
      return ERROR_CALL_NOT_IMPLEMENTED;
    }
}


static HANDLE
CreateClientPipeInstance (VOID)
{
  HANDLE pipe = NULL;
  PACL old_dacl, new_dacl;
  PSECURITY_DESCRIPTOR sd;
  static EXPLICIT_ACCESS ea[2];
  static BOOL initialized = FALSE;
  DWORD flags = PIPE_ACCESS_DUPLEX | WRITE_DAC | FILE_FLAG_OVERLAPPED;

  if (!initialized)
    {
      PSID everyone, anonymous;

      ConvertStringSidToSid (TEXT("S-1-1-0"), &everyone);
      ConvertStringSidToSid (TEXT("S-1-5-7"), &anonymous);

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

  pipe = CreateNamedPipe (TEXT("\\\\.\\pipe\\openvpn\\service"), flags,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
                PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);
  if (pipe == INVALID_HANDLE_VALUE)
    {
      MsgToEventLog (M_SYSERR, TEXT("Could not create named pipe"));
      return INVALID_HANDLE_VALUE;
    }

  if (GetSecurityInfo (pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &old_dacl, NULL, &sd) != ERROR_SUCCESS)
    {
      MsgToEventLog (M_SYSERR, TEXT("Could not get pipe security info"));
      return CloseHandleEx (&pipe);
    }

  if (SetEntriesInAcl (2, ea, old_dacl, &new_dacl) != ERROR_SUCCESS)
    {
      MsgToEventLog (M_SYSERR, TEXT("Could not set entries in new acl"));
      return CloseHandleEx (&pipe);
    }

  if (SetSecurityInfo (pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, new_dacl, NULL) != ERROR_SUCCESS)
    {
      MsgToEventLog (M_SYSERR, TEXT("Could not set pipe security info"));
      return CloseHandleEx (&pipe);
    }

  return pipe;
}


static DWORD
UpdateWaitHandles (LPHANDLE *handles_ptr, LPDWORD count,
                   HANDLE io_event, HANDLE exit_event, list_item_t *threads)
{
  static DWORD size = 10;
  static LPHANDLE handles = NULL;
  DWORD pos = 0;

  if (handles == NULL)
    {
      handles = malloc (size * sizeof (HANDLE));
      if (handles == NULL)
        return ERROR_OUTOFMEMORY;
    }

  handles[pos++] = io_event;

  if (!threads)
    handles[pos++] = exit_event;

  while (threads)
    {
      if (pos == size)
        {
          size += 10;
          handles = realloc (handles, size * sizeof (HANDLE));
          if (handles == NULL)
            return ERROR_OUTOFMEMORY;
        }
      handles[pos++] = threads->data;
      threads = threads->next;
    }

  *handles_ptr = handles;
  *count = pos;
  return NO_ERROR;
}


static VOID
FreeWaitHandles (LPHANDLE h)
{
  free (h);
}


VOID WINAPI
ServiceStartInteractive (DWORD dwArgc, LPTSTR *lpszArgv)
{
  HANDLE pipe, io_event = NULL;
  OVERLAPPED overlapped;
  DWORD error = NO_ERROR;
  list_item_t *threads = NULL;
  PHANDLE handles;
  DWORD handle_count;

  service = RegisterServiceCtrlHandlerEx (interactive_service.name, ServiceCtrlInteractive, &status);
  if (!service)
    return;

  status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
  status.dwCurrentState = SERVICE_START_PENDING;
  status.dwServiceSpecificExitCode = NO_ERROR;
  status.dwWin32ExitCode = NO_ERROR;
  status.dwWaitHint = 3000;
  ReportStatusToSCMgr (service, &status);

  /* Read info from registry in key HKLM\SOFTWARE\OpenVPN */
  error = GetOpenvpnSettings (&settings);
  if (error != ERROR_SUCCESS)
    goto out;

  io_event = InitOverlapped (&overlapped);
  exit_event = CreateEvent (NULL, FALSE, FALSE, NULL);
  if (!exit_event || !io_event)
    {
      error = MsgToEventLog (M_SYSERR, TEXT("Could not create event"));
      goto out;
    }

  error = UpdateWaitHandles (&handles, &handle_count, io_event, exit_event, threads);
  if (error != NO_ERROR)
    goto out;

  pipe = CreateClientPipeInstance ();
  if (pipe == INVALID_HANDLE_VALUE)
    goto out;

  status.dwCurrentState = SERVICE_RUNNING;
  status.dwWaitHint = 0;
  ReportStatusToSCMgr (service, &status);

  while (TRUE)
    {
      if (ConnectNamedPipe (pipe, &overlapped) == FALSE &&
          GetLastError () != ERROR_PIPE_CONNECTED &&
          GetLastError () != ERROR_IO_PENDING)
        {
          MsgToEventLog (M_SYSERR, TEXT("Could not connect pipe"));
          break;
        }

      error = WaitForMultipleObjects (handle_count, handles, FALSE, INFINITE);
      if (error == WAIT_OBJECT_0)
        {
          /* Client connected, spawn a worker thread for it */
          HANDLE next_pipe = CreateClientPipeInstance ();
          HANDLE thread = CreateThread (NULL, 0, RunOpenvpn, pipe, CREATE_SUSPENDED, NULL);
          if (thread)
            {
              error = AddListItem (&threads, thread) ||
                UpdateWaitHandles (&handles, &handle_count, io_event, exit_event, threads);
              if (error)
                {
                  TerminateThread (thread, 1);
                  CloseHandleEx (&thread);
                  CloseHandleEx (&pipe);
                  SetEvent (exit_event);
                }
              else
                ResumeThread (thread);
            }
          else
            CloseHandleEx (&pipe);

          ResetOverlapped (&overlapped);
          pipe = next_pipe;
        }
      else
        {
          CancelIo (pipe);
          if (error == WAIT_FAILED)
            {
              MsgToEventLog (M_SYSERR, TEXT("WaitForMultipleObjects failed"));
              continue;
            }
          if (!threads)
            {
              /* exit event signaled */
              CloseHandleEx (&pipe);
              error = NO_ERROR;
              break;
            }

          /* Worker thread ended */
          BOOL CmpHandle (LPVOID item, LPVOID hnd) { return item == hnd; }
          HANDLE thread = RemoveListItem (&threads, CmpHandle, handles[error]);
          UpdateWaitHandles (&handles, &handle_count, io_event, exit_event, threads);
          CloseHandleEx (&thread);
        }
    }

out:
  FreeWaitHandles (handles);
  CloseHandleEx (&io_event);
  CloseHandleEx (&exit_event);

  status.dwCurrentState = SERVICE_STOPPED;
  status.dwWin32ExitCode = error;
  ReportStatusToSCMgr (service, &status);
}
