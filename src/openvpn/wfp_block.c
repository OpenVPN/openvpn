/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#ifdef _WIN32

#include <fwpmu.h>
#include <initguid.h>
#include <fwpmtypes.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#include "wfp_block.h"

/*
 * WFP-related defines and GUIDs not in mingw32
 */

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

/* c38d57d1-05a7-4c33-904f-7fbceee60e82 */
DEFINE_GUID(
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    0xc38d57d1,
    0x05a7,
    0x4c33,
    0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
    );

/* 4a72393b-319f-44bc-84c3-ba54dcb3b6b4 */
DEFINE_GUID(
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    0x4a72393b,
    0x319f,
    0x44bc,
    0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
    );

/* d78e1e87-8644-4ea5-9437-d809ecefc971 */
DEFINE_GUID(
    FWPM_CONDITION_ALE_APP_ID,
    0xd78e1e87,
    0x8644,
    0x4ea5,
    0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
    );

/* c35a604d-d22b-4e1a-91b4-68f674ee674b */
DEFINE_GUID(
    FWPM_CONDITION_IP_REMOTE_PORT,
    0xc35a604d,
    0xd22b,
    0x4e1a,
    0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b
    );

/* 4cd62a49-59c3-4969-b7f3-bda5d32890a4 */
DEFINE_GUID(
    FWPM_CONDITION_IP_LOCAL_INTERFACE,
    0x4cd62a49,
    0x59c3,
    0x4969,
    0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4
    );

/* 632ce23b-5167-435c-86d7-e903684aa80c */
DEFINE_GUID(
    FWPM_CONDITION_FLAGS,
    0x632ce23b,
    0x5167,
    0x435c,
    0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c
    );

/* UUID of WFP sublayer used by all instances of openvpn
 * 2f660d7e-6a37-11e6-a181-001e8c6e04a2 */
DEFINE_GUID(
    OPENVPN_WFP_BLOCK_SUBLAYER,
    0x2f660d7e,
    0x6a37,
    0x11e6,
    0xa1, 0x81, 0x00, 0x1e, 0x8c, 0x6e, 0x04, 0xa2
    );

static WCHAR *FIREWALL_NAME = L"OpenVPN";

/*
 * Default msg handler does nothing
 */
static inline void
default_msg_handler(DWORD err, const char *msg)
{
    return;
}

#define OUT_ON_ERROR(err, msg) \
    if (err) { msg_handler(err, msg); goto out; }

/*
 * Add a persistent sublayer with specified uuid.
 */
static DWORD
add_sublayer(GUID uuid)
{
    FWPM_SESSION0 session;
    HANDLE engine = NULL;
    DWORD err = 0;
    FWPM_SUBLAYER0 sublayer;

    memset(&session, 0, sizeof(session));
    memset(&sublayer, 0, sizeof(sublayer));

    err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
    if (err != ERROR_SUCCESS)
    {
        goto out;
    }

    sublayer.subLayerKey = uuid;
    sublayer.displayData.name = FIREWALL_NAME;
    sublayer.displayData.description = FIREWALL_NAME;
    sublayer.flags = 0;
    sublayer.weight = 0x100;

    /* Add sublayer to the session */
    err = FwpmSubLayerAdd0(engine, &sublayer, NULL);

out:
    if (engine)
    {
        FwpmEngineClose0(engine);
    }
    return err;
}

/*
 * Block outgoing local traffic, possibly DNS only, except for
 * (i) adapter with the specified index (and loopback, if all is blocked)
 * OR
 * (ii) processes with the specified executable path
 * The firewall filters added here are automatically removed when the process exits or
 * on calling delete_wfp_block_filters().
 * Arguments:
 *   engine_handle : On successful return contains the handle for a newly opened fwp session
 *                   in which the filters are added.
 *                   May be closed by passing to delete_wfp_block_filters to remove the filters.
 *   index         : The index of adapter for which traffic is permitted.
 *   exe_path      : Path of executable for which traffic is permitted.
 *   msg_handler   : An optional callback function for error reporting.
 *   dns_only      : Whether the blocking filters should apply for DNS only.
 * Returns 0 on success, a non-zero status code of the last failed action on failure.
 */

DWORD
add_wfp_block_filters(HANDLE *engine_handle,
                      int index,
                      const WCHAR *exe_path,
                      wfp_block_msg_handler_t msg_handler,
                      BOOL dns_only)
{
    FWPM_SESSION0 session = {0};
    FWPM_SUBLAYER0 *sublayer_ptr = NULL;
    NET_LUID itf_luid;
    UINT64 filterid;
    FWP_BYTE_BLOB *openvpnblob = NULL;
    FWPM_FILTER0 Filter = {0};
    FWPM_FILTER_CONDITION0 Condition[2];
    FWPM_FILTER_CONDITION0 match_openvpn = {0};
    FWPM_FILTER_CONDITION0 match_port_53 = {0};
    FWPM_FILTER_CONDITION0 match_interface = {0};
    FWPM_FILTER_CONDITION0 match_loopback = {0};
    FWPM_FILTER_CONDITION0 match_not_loopback = {0};
    DWORD err = 0;

    if (!msg_handler)
    {
        msg_handler = default_msg_handler;
    }

    /* Add temporary filters which don't survive reboots or crashes. */
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    *engine_handle = NULL;

    err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, engine_handle);
    OUT_ON_ERROR(err, "FwpEngineOpen: open fwp session failed");
    msg_handler(0, "WFP Block: WFP engine opened");

    /* Check sublayer exists and add one if it does not. */
    if (FwpmSubLayerGetByKey0(*engine_handle, &OPENVPN_WFP_BLOCK_SUBLAYER, &sublayer_ptr)
        == ERROR_SUCCESS)
    {
        msg_handler(0, "WFP Block: Using existing sublayer");
        FwpmFreeMemory0((void **)&sublayer_ptr);
    }
    else
    {  /* Add a new sublayer -- as another process may add it in the meantime,
        * do not treat "already exists" as an error */
        err = add_sublayer(OPENVPN_WFP_BLOCK_SUBLAYER);

        if (err == FWP_E_ALREADY_EXISTS || err == ERROR_SUCCESS)
        {
            msg_handler(0, "WFP Block: Added a persistent sublayer with pre-defined UUID");
        }
        else
        {
            OUT_ON_ERROR(err, "add_sublayer: failed to add persistent sublayer");
        }
    }

    err = ConvertInterfaceIndexToLuid(index, &itf_luid);
    OUT_ON_ERROR(err, "Convert interface index to luid failed");

    err = FwpmGetAppIdFromFileName0(exe_path, &openvpnblob);
    OUT_ON_ERROR(err, "Get byte blob for openvpn executable name failed");

    /* Prepare match conditions */
    match_openvpn.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    match_openvpn.matchType = FWP_MATCH_EQUAL;
    match_openvpn.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    match_openvpn.conditionValue.byteBlob = openvpnblob;

    match_port_53.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    match_port_53.matchType = FWP_MATCH_EQUAL;
    match_port_53.conditionValue.type = FWP_UINT16;
    match_port_53.conditionValue.uint16 = 53;

    match_interface.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
    match_interface.matchType = FWP_MATCH_EQUAL;
    match_interface.conditionValue.type = FWP_UINT64;
    match_interface.conditionValue.uint64 = &itf_luid.Value;

    match_loopback.fieldKey = FWPM_CONDITION_FLAGS;
    match_loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
    match_loopback.conditionValue.type = FWP_UINT32;
    match_loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

    match_not_loopback.fieldKey = FWPM_CONDITION_FLAGS;
    match_not_loopback.matchType = FWP_MATCH_FLAGS_NONE_SET;
    match_not_loopback.conditionValue.type = FWP_UINT32;
    match_not_loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

    /* Prepare filter. */
    Filter.subLayerKey = OPENVPN_WFP_BLOCK_SUBLAYER;
    Filter.displayData.name = FIREWALL_NAME;
    Filter.weight.type = FWP_UINT8;
    Filter.weight.uint8 = 0xF;
    Filter.filterCondition = Condition;
    Filter.numFilterConditions = 1;

    /* First filter. Permit IPv4 from OpenVPN itself. */
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Filter.action.type = FWP_ACTION_PERMIT;
    Condition[0] = match_openvpn;
    if (dns_only)
    {
        Filter.numFilterConditions = 2;
        Condition[1] = match_port_53;
    }
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to permit IPv4 traffic from OpenVPN failed");

    /* Second filter. Permit IPv6 from OpenVPN itself. */
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to permit IPv6 traffic from OpenVPN failed");

    msg_handler(0, "WFP Block: Added permit filters for exe_path");

    /* Third filter. Block IPv4 to port 53 or all except loopback. */
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Filter.action.type = FWP_ACTION_BLOCK;
    Filter.weight.type = FWP_EMPTY;
    Filter.numFilterConditions = 1;
    Condition[0] = match_not_loopback;
    if (dns_only)
    {
        Filter.numFilterConditions = 2;
        Condition[1] = match_port_53;
    }
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to block IPv4 traffic failed");

    /* Fourth filter. Block IPv6 to port 53 or all besides loopback */
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to block IPv6 traffic failed");

    msg_handler(0, "WFP Block: Added block filters for all interfaces");

    /* Fifth filter. Permit all IPv4 or just DNS traffic for the VPN interface.
     * Use a non-zero weight so that the permit filters get higher priority
     * over the block filter added with automatic weighting */
    Filter.weight.type = FWP_UINT8;
    Filter.weight.uint8 = 0xE;
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Filter.action.type = FWP_ACTION_PERMIT;
    Filter.numFilterConditions = 1;
    Condition[0] = match_interface;
    if (dns_only)
    {
        Filter.numFilterConditions = 2;
        Condition[1] = match_port_53;
    }
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to permit IPv4 traffic through VPN interface failed");

    /* Sixth filter. Permit all IPv6 or just DNS traffic for the VPN interface.
     * Use same weight as IPv4 filter */
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to permit IPv6 traffic through VPN interface failed");

    msg_handler(0, "WFP Block: Added permit filters for VPN interface");

    /* Seventh Filter. Block IPv4 DNS requests to loopback from other apps */
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Filter.action.type = FWP_ACTION_BLOCK;
    Filter.weight.type = FWP_EMPTY;
    Filter.numFilterConditions = 2;
    Condition[0] = match_loopback;
    Condition[1] = match_port_53;
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to block IPv4 DNS traffic to loopback failed");

    /* Eighth Filter. Block IPv6 DNS requests to loopback from other apps */
    Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    err = FwpmFilterAdd0(*engine_handle, &Filter, NULL, &filterid);
    OUT_ON_ERROR(err, "Add filter to block IPv6 DNS traffic to loopback failed");

    msg_handler(0, "WFP Block: Added block filters for DNS traffic to loopback");

out:
    if (openvpnblob)
    {
        FwpmFreeMemory0((void **)&openvpnblob);
    }

    if (err && *engine_handle)
    {
        FwpmEngineClose0(*engine_handle);
        *engine_handle = NULL;
    }

    return err;
}

DWORD
delete_wfp_block_filters(HANDLE engine_handle)
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

/*
 * Return interface metric value for the specified interface index.
 *
 * Arguments:
 *   index         : The index of TAP adapter.
 *   family        : Address family (AF_INET for IPv4 and AF_INET6 for IPv6).
 *   is_auto       : On return set to true if automatic metric is in use.
 *                   Unused if NULL.
 *
 * Returns positive metric value or -1 on error.
 */
int
get_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family, int *is_auto)
{
    DWORD err = 0;
    MIB_IPINTERFACE_ROW ipiface;
    InitializeIpInterfaceEntry(&ipiface);
    ipiface.Family = family;
    ipiface.InterfaceIndex = index;

    if (is_auto)
    {
        *is_auto = 0;
    }
    err = GetIpInterfaceEntry(&ipiface);

    /* On Windows metric is never > INT_MAX so return value of int is ok.
     * But we check for overflow nevertheless.
     */
    if (err == NO_ERROR && ipiface.Metric <= INT_MAX)
    {
        if (is_auto)
        {
            *is_auto = ipiface.UseAutomaticMetric;
        }
        return (int)ipiface.Metric;
    }
    return -1;
}

/*
 * Sets interface metric value for specified interface index.
 *
 * Arguments:
 *   index         : The index of TAP adapter.
 *   family        : Address family (AF_INET for IPv4 and AF_INET6 for IPv6).
 *   metric        : Metric value. 0 for automatic metric.
 * Returns 0 on success, a non-zero status code of the last failed action on failure.
 */

DWORD
set_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family,
                     const ULONG metric)
{
    DWORD err = 0;
    MIB_IPINTERFACE_ROW ipiface;
    InitializeIpInterfaceEntry(&ipiface);
    ipiface.Family = family;
    ipiface.InterfaceIndex = index;
    err = GetIpInterfaceEntry(&ipiface);
    if (err == NO_ERROR)
    {
        if (family == AF_INET)
        {
            /* required for IPv4 as per MSDN */
            ipiface.SitePrefixLength = 0;
        }
        ipiface.Metric = metric;
        if (metric == 0)
        {
            ipiface.UseAutomaticMetric = TRUE;
        }
        else
        {
            ipiface.UseAutomaticMetric = FALSE;
        }
        err = SetIpInterfaceEntry(&ipiface);
        if (err == NO_ERROR)
        {
            return 0;
        }
    }
    return err;
}

#endif /* ifdef _WIN32 */
