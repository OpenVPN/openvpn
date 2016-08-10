/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *                2015-2016  <iam@valdikss.org.ru>
 *                2016 Selva Nair <selva.nair@gmail.com>
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

#ifdef WIN32

#include <fwpmu.h>
#include <initguid.h>
#include <fwpmtypes.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include "block_dns.h"

/*
 * WFP-related defines and GUIDs not in mingw32
 */

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

// c38d57d1-05a7-4c33-904f-7fbceee60e82
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V4,
   0xc38d57d1,
   0x05a7,
   0x4c33,
   0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V6,
   0x4a72393b,
   0x319f,
   0x44bc,
   0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
);

// d78e1e87-8644-4ea5-9437-d809ecefc971
DEFINE_GUID(
   FWPM_CONDITION_ALE_APP_ID,
   0xd78e1e87,
   0x8644,
   0x4ea5,
   0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
);

// c35a604d-d22b-4e1a-91b4-68f674ee674b
DEFINE_GUID(
   FWPM_CONDITION_IP_REMOTE_PORT,
   0xc35a604d,
   0xd22b,
   0x4e1a,
   0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b
);

// 4cd62a49-59c3-4969-b7f3-bda5d32890a4
DEFINE_GUID(
   FWPM_CONDITION_IP_LOCAL_INTERFACE,
   0x4cd62a49,
   0x59c3,
   0x4969,
   0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4
);

/*
 * Default msg handler does nothing
 */
static inline void
default_msg_handler (DWORD err, const char *msg)
{
  return;
}

#define CHECK_ERROR(err, msg) \
   if (err) { msg_handler (err, msg); goto out; }

/*
 * Block outgoing port 53 traffic except for
 * (i) adapter with the specified index
 * OR
 * (ii) processes with the specified executable path
 * The firewall filters added here are automatically removed when the process exits or
 * on calling delete_block_dns_filters().
 * Arguments:
 *   engine_handle : On successful return contains the handle for a newly opened fwp session
 *                   in which the filters are added.
 *                   May be closed by passing to delete_block_dns_filters to remove the filters.
 *   index         : The index of adapter for which traffic is permitted.
 *   exe_path      : Path of executable for which traffic is permitted.
 *   msg_handler   : An optional callback function for error reporting.
 * Returns 0 on success, a non-zero status code of the last failed action on failure.
 */

DWORD
add_block_dns_filters (HANDLE *engine_handle,
                       int index,
                       const WCHAR *exe_path,
                       block_dns_msg_handler_t msg_handler
                      )
{
  FWPM_SESSION0 session = {0};
  FWPM_SUBLAYER0 SubLayer = {0};
  NET_LUID tapluid;
  UINT64 filterid;
  FWP_BYTE_BLOB *openvpnblob = NULL;
  FWPM_FILTER0 Filter = {0};
  FWPM_FILTER_CONDITION0 Condition[2] = {0};
  WCHAR *FIREWALL_NAME = L"OpenVPN";
  DWORD err = 0;

  if (!msg_handler)
    msg_handler = default_msg_handler;

  /* Add temporary filters which don't survive reboots or crashes. */
  session.flags = FWPM_SESSION_FLAG_DYNAMIC;

  *engine_handle = NULL;

  err = FwpmEngineOpen0 (NULL, RPC_C_AUTHN_WINNT, NULL, &session, engine_handle);
  CHECK_ERROR (err, "FwpEngineOpen: open fwp session failed");

  err = UuidCreate (&SubLayer.subLayerKey);
  CHECK_ERROR (err, "UuidCreate: create sublayer key failed");

  /* Populate packet filter layer information. */
  SubLayer.displayData.name = FIREWALL_NAME;
  SubLayer.displayData.description = FIREWALL_NAME;
  SubLayer.flags = 0;
  SubLayer.weight = 0x100;

  /* Add sublayer to the session */
  err = FwpmSubLayerAdd0 (*engine_handle, &SubLayer, NULL);
  CHECK_ERROR (err, "FwpmSubLayerAdd: add sublayer to session failed");

  msg_handler (0, "Block_DNS: WFP engine opened");

  err = ConvertInterfaceIndexToLuid (index, &tapluid);
  CHECK_ERROR (err, "Convert interface index to luid failed");

  err = FwpmGetAppIdFromFileName0 (exe_path, &openvpnblob);
  CHECK_ERROR (err, "Get byte blob for openvpn executable name failed");

  /* Prepare filter. */
  Filter.subLayerKey = SubLayer.subLayerKey;
  Filter.displayData.name = FIREWALL_NAME;
  Filter.weight.type = FWP_UINT8;
  Filter.weight.uint8 = 0xF;
  Filter.filterCondition = Condition;
  Filter.numFilterConditions = 2;

  /* First filter. Permit IPv4 DNS queries from OpenVPN itself. */
  Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  Filter.action.type = FWP_ACTION_PERMIT;

  Condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
  Condition[0].matchType = FWP_MATCH_EQUAL;
  Condition[0].conditionValue.type = FWP_UINT16;
  Condition[0].conditionValue.uint16 = 53;

  Condition[1].fieldKey = FWPM_CONDITION_ALE_APP_ID;
  Condition[1].matchType = FWP_MATCH_EQUAL;
  Condition[1].conditionValue.type = FWP_BYTE_BLOB_TYPE;
  Condition[1].conditionValue.byteBlob = openvpnblob;

  err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
  CHECK_ERROR (err, "Add filter to permit IPv4 port 53 traffic from OpenVPN failed");

  /* Second filter. Permit IPv6 DNS queries from OpenVPN itself. */
  Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

  err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
  CHECK_ERROR (err, "Add filter to permit IPv6 port 53 traffic from OpenVPN failed");

  msg_handler (0, "Block_DNS: Added permit filters for exe_path");

  /* Third filter. Block all IPv4 DNS queries. */
  Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  Filter.action.type = FWP_ACTION_BLOCK;
  Filter.weight.type = FWP_EMPTY;
  Filter.numFilterConditions = 1;

  err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
  CHECK_ERROR (err, "Add filter to block IPv4 DNS traffic failed");

  msg_handler (0, "Block_DNS: Added block filters for all");

  /* Forth filter. Block all IPv6 DNS queries. */
  Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

  err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
  CHECK_ERROR (err, "Add filter to block IPv6 DNS traffic failed");

  /* Fifth filter. Permit IPv4 DNS queries from TAP. */
  Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  Filter.action.type = FWP_ACTION_PERMIT;
  Filter.numFilterConditions = 2;

  Condition[1].fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
  Condition[1].matchType = FWP_MATCH_EQUAL;
  Condition[1].conditionValue.type = FWP_UINT64;
  Condition[1].conditionValue.uint64 = &tapluid.Value;

  err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
  CHECK_ERROR (err, "Add filter to permit IPv4 DNS traffic through TAP failed");

  /* Sixth filter. Permit IPv6 DNS queries from TAP. */
  Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

  err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
  CHECK_ERROR (err, "Add filter to permit IPv6 DNS traffic through TAP failed");

  msg_handler (0, "Block_DNS: Added permit filters for TAP interface");

out:

  if (openvpnblob)
    FwpmFreeMemory0 ((void **)&openvpnblob);

  if (err && *engine_handle)
    {
      FwpmEngineClose0 (*engine_handle);
      *engine_handle = NULL;
    }

  return err;
}

DWORD
delete_block_dns_filters (HANDLE engine_handle)
{
  DWORD err = 0;
  /*
   * For dynamic sessions closing the engine removes all filters added in the session
   */
  if (engine_handle)
    {
      err = FwpmEngineClose0(engine_handle);
    }
  return err;
}

#endif
