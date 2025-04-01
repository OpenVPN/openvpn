/*
 *  Interface to ovpn-win-dco networking code
 *
 *  Copyright (C) 2020-2024 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(_WIN32)

#include "syshead.h"

#include "dco.h"
#include "forward.h"
#include "tun.h"
#include "crypto.h"
#include "ssl_common.h"
#include "openvpn.h"

#include <bcrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#if defined(__MINGW32__)
const IN_ADDR in4addr_any = { 0 };
#endif

/* Sometimes IP Helper API, which we use for setting IP address etc,
 * complains that interface is not found. Give it some time to settle
 */
static void
dco_wait_ready(DWORD idx)
{
    for (int i = 0; i < 20; ++i)
    {
        MIB_IPINTERFACE_ROW row = { .InterfaceIndex = idx, .Family = AF_INET };
        if (GetIpInterfaceEntry(&row) != ERROR_NOT_FOUND)
        {
            break;
        }
        msg(D_DCO_DEBUG, "interface %ld not yet ready, retrying", idx);
        Sleep(50);
    }
}

/**
 * Gets version of dco-win driver
 *
 * Fills Major/Minor/Patch fields in a passed OVPN_VERSION
 * struct. If version cannot be obtained, fields are set to 0.
 *
 * @param version pointer to OVPN_VERSION struct
 * @returns true if version has been obtained, false otherwise
 */
static bool
dco_get_version(OVPN_VERSION *version)
{
    CLEAR(*version);

    bool res = false;

    HANDLE h = CreateFile("\\\\.\\ovpn-dco-ver", GENERIC_READ,
                          0, NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        /* fallback to a "normal" device, this will fail if device is already in use */
        h = CreateFile("\\\\.\\ovpn-dco", GENERIC_READ,
                       0, NULL, OPEN_EXISTING, 0, NULL);
    }

    if (h == INVALID_HANDLE_VALUE)
    {
        goto done;
    }

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(h, OVPN_IOCTL_GET_VERSION, NULL, 0,
                         version, sizeof(*version), &bytes_returned, NULL))
    {
        goto done;
    }

    res = true;

done:
    if (h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
    }

    msg(D_DCO_DEBUG, "dco version: %ld.%ld.%ld", version->Major, version->Minor, version->Patch);

    return res;
}

/**
 * @brief Initializes the DCO adapter in multipeer mode and sets it to "connected" state.
 *
 * Opens the DCO device, sets the adapter mode using `OVPN_IOCTL_SET_MODE`,
 * which transitions the adapter to the "connected" state, and waits for it to become ready.
 *
 * @param dco Pointer to the `dco_context_t` structure representing the DCO context.
 * @param dev_node Device node string for the DCO adapter.
 */
void
ovpn_dco_init_mp(dco_context_t *dco, const char *dev_node)
{
    ASSERT(dco->ifmode == DCO_MODE_UNINIT);
    dco->ifmode = DCO_MODE_MP;

    /* Use manual reset event so it remains signalled until
     * explicitly reset. This way we won't lose notifications
     */
    dco->ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (dco->ov.hEvent == NULL)
    {
        msg(M_ERR, "Error: ovpn_dco_init: CreateEvent failed");
    }

    dco->rwhandle.read = dco->ov.hEvent;

    /* open DCO device */
    struct gc_arena gc = gc_new();
    const char *device_guid;
    tun_open_device(dco->tt, dev_node, &device_guid, &gc);
    gc_free(&gc);

    /* set mp mode */
    OVPN_MODE m = OVPN_MODE_MP;
    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_SET_MODE, &m, sizeof(m), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_SET_MODE) failed");
    }

    dco_wait_ready(dco->tt->adapter_index);
}

/**
 * @brief Transitions the DCO adapter to the connected state in P2P mode.
 *
 * Sends `OVPN_IOCTL_START_VPN` to start the VPN and waits for the adapter
 * to become ready.
 *
 * @param tt Pointer to the `tuntap` structure representing the adapter.
 */
void
dco_p2p_start_vpn(struct tuntap *tt)
{
    DWORD bytes_returned = 0;
    if (!DeviceIoControl(tt->hand, OVPN_IOCTL_START_VPN, NULL, 0, NULL, 0, &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_START_VPN) failed");
    }

    /* Sometimes IP Helper API, which we use for setting IP address etc,
     * complains that interface is not found. Give it some time to settle
     */
    dco_wait_ready(tt->adapter_index);
}


/**
 * @brief Initializes DCO depends on `mode`
 *
 *  - for P2P it puts adapter in "connected" state. The peer should
 * be already added by dco_p2p_new_peer().
 *
 *  - for multipeer it opens DCO adapter and puts it into "connected"
 * state. The server socket should be initialized later by dco_mp_start_vpn().
 */
bool
ovpn_dco_init(int mode, dco_context_t *dco, const char *dev_node)
{
    switch (mode)
    {
        case MODE_POINT_TO_POINT:
            dco->ifmode = DCO_MODE_P2P;
            dco_p2p_start_vpn(dco->tt);
            break;

        case MODE_SERVER:
            ovpn_dco_init_mp(dco, dev_node);
            break;

        default:
            ASSERT(false);
    }

    return true;
}

int
open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev)
{
    ASSERT(0);
    return 0;
}

static void
dco_connect_wait(HANDLE handle, OVERLAPPED *ov, int timeout, struct signal_info *sig_info)
{
    volatile int *signal_received = &sig_info->signal_received;
    /* GetOverlappedResultEx is available starting from Windows 8 */
    typedef BOOL (WINAPI *get_overlapped_result_ex_t)(HANDLE, LPOVERLAPPED, LPDWORD, DWORD, BOOL);
    get_overlapped_result_ex_t get_overlapped_result_ex =
        (get_overlapped_result_ex_t)GetProcAddress(GetModuleHandle("Kernel32.dll"),
                                                   "GetOverlappedResultEx");

    if (get_overlapped_result_ex == NULL)
    {
        msg(M_ERR, "Failed to load GetOverlappedResult()");
    }

    DWORD timeout_msec = timeout * 1000;
    const int poll_interval_ms = 50;

    while (timeout_msec > 0)
    {
        timeout_msec -= poll_interval_ms;

        DWORD transferred;
        if (get_overlapped_result_ex(handle, ov, &transferred, poll_interval_ms, FALSE) != 0)
        {
            /* TCP connection established by dco */
            return;
        }

        DWORD err = GetLastError();
        if ((err != WAIT_TIMEOUT) && (err != ERROR_IO_INCOMPLETE))
        {
            /* dco reported connection error */
            msg(M_NONFATAL | M_ERRNO, "dco connect error");
            register_signal(sig_info, SIGUSR1, "dco-connect-error");
            return;
        }

        get_signal(signal_received);
        if (*signal_received)
        {
            return;
        }

        management_sleep(0);
    }

    /* we end up here when timeout occurs in userspace */
    msg(M_NONFATAL, "dco connect timeout");
    register_signal(sig_info, SIGUSR1, "dco-connect-timeout");
}

/**
 * @brief Initializes and binds the kernel UDP transport socket for multipeer mode.
 *
 * Sends `OVPN_IOCTL_MP_START_VPN` to create a kernel-mode UDP socket, binds it to
 * the specified address, ready for incoming connections.
 *
 * @param handle Device handle for the DCO adapter.
 * @param sock Pointer to the `link_socket` structure containing socket information.
 */
void
dco_mp_start_vpn(HANDLE handle, struct link_socket *sock)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    int ai_family = sock->info.lsa->bind_local->ai_family;
    struct addrinfo *local = sock->info.lsa->bind_local;
    struct addrinfo *cur = NULL;

    for (cur = local; cur; cur = cur->ai_next)
    {
        if (cur->ai_family == ai_family)
        {
            break;
        }
    }
    if (!cur)
    {
        msg(M_FATAL, "%s: Socket bind failed: Addr to bind has no %s record",
            __func__, addr_family_name(ai_family));
    }

    OVPN_MP_START_VPN in, out;
    in.IPv6Only = sock->info.bind_ipv6_only ? 1 : 0;
    if (ai_family == AF_INET)
    {
        memcpy(&in.ListenAddress.Addr4, cur->ai_addr, sizeof(struct sockaddr_in));
    }
    else
    {
        memcpy(&in.ListenAddress.Addr6, cur->ai_addr, sizeof(struct sockaddr_in6));
    }

    /* in multipeer mode control channel packets are prepended with remote peer's sockaddr */
    sock->sockflags |= SF_PREPEND_SA;

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(handle, OVPN_IOCTL_MP_START_VPN, &in, sizeof(in), &out, sizeof(out),
                         &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_MP_START_VPN) failed");
    }
}

void
dco_p2p_new_peer(HANDLE handle, OVERLAPPED *ov, struct link_socket *sock, struct signal_info *sig_info)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    OVPN_NEW_PEER peer = { 0 };

    struct addrinfo *remoteaddr = sock->info.lsa->current_remote;

    struct sockaddr *local = NULL;
    struct sockaddr *remote = remoteaddr->ai_addr;

    if (remoteaddr->ai_protocol == IPPROTO_TCP
        || remoteaddr->ai_socktype == SOCK_STREAM)
    {
        peer.Proto = OVPN_PROTO_TCP;
    }
    else
    {
        peer.Proto = OVPN_PROTO_UDP;
    }

    if (sock->bind_local)
    {
        /* Use first local address with correct address family */
        struct addrinfo *bind = sock->info.lsa->bind_local;
        while (bind && !local)
        {
            if (bind->ai_family == remote->sa_family)
            {
                local = bind->ai_addr;
            }
            bind = bind->ai_next;
        }
    }

    if (sock->bind_local && !local)
    {
        msg(M_FATAL, "DCO: Socket bind failed: Address to bind lacks %s record",
            addr_family_name(remote->sa_family));
    }

    if (remote->sa_family == AF_INET6)
    {
        peer.Remote.Addr6 = *((SOCKADDR_IN6 *)(remoteaddr->ai_addr));
        if (local)
        {
            peer.Local.Addr6 = *((SOCKADDR_IN6 *)local);
        }
        else
        {
            peer.Local.Addr6.sin6_addr = in6addr_any;
            peer.Local.Addr6.sin6_port = 0;
            peer.Local.Addr6.sin6_family = AF_INET6;
        }
    }
    else if (remote->sa_family == AF_INET)
    {
        peer.Remote.Addr4 = *((SOCKADDR_IN *)(remoteaddr->ai_addr));
        if (local)
        {
            peer.Local.Addr4 = *((SOCKADDR_IN *)local);
        }
        else
        {
            peer.Local.Addr4.sin_addr = in4addr_any;
            peer.Local.Addr4.sin_port = 0;
            peer.Local.Addr4.sin_family = AF_INET;
        }
    }
    else
    {
        ASSERT(0);
    }

    CLEAR(*ov);
    if (!DeviceIoControl(handle, OVPN_IOCTL_NEW_PEER, &peer, sizeof(peer), NULL, 0, NULL, ov))
    {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_NEW_PEER) failed");
        }
        else
        {
            dco_connect_wait(handle, ov, get_server_poll_remaining_time(sock->server_poll_timeout), sig_info);
        }
    }
}

int
dco_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
             struct sockaddr *localaddr, struct sockaddr *remoteaddr,
             struct in_addr *vpn_ipv4, struct in6_addr *vpn_ipv6)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d", __func__, peerid, sd);

    if (dco->ifmode == DCO_MODE_P2P)
    {
        /* no-op for p2p */
        return 0;
    }

    OVPN_MP_NEW_PEER newPeer = {0};

    if (remoteaddr)
    {
        /* while the driver doesn't use the local address yet it requires its AF to be valid */
        newPeer.Local.Addr4.sin_family = remoteaddr->sa_family;

        if (remoteaddr->sa_family == AF_INET)
        {
            memcpy(&newPeer.Remote.Addr4, remoteaddr, sizeof(struct sockaddr_in));
        }
        else
        {
            memcpy(&newPeer.Remote.Addr6, remoteaddr, sizeof(struct sockaddr_in6));
        }
    }

    if (vpn_ipv4)
    {
        newPeer.VpnAddr4 = *vpn_ipv4;
    }

    if (vpn_ipv6)
    {
        newPeer.VpnAddr6 = *vpn_ipv6;
    }

    newPeer.PeerId = peerid;

    DWORD bytesReturned;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_MP_NEW_PEER, &newPeer, sizeof(newPeer), NULL, 0, &bytesReturned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_MP_NEW_PEER) failed");
    }

    return 0;
}

int
dco_del_peer(dco_context_t *dco, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    OVPN_MP_DEL_PEER del_peer = { peerid };
    VOID *buf = NULL;
    DWORD len = 0;
    DWORD ioctl = OVPN_IOCTL_DEL_PEER;

    if (dco->ifmode == DCO_MODE_MP)
    {
        ioctl = OVPN_IOCTL_MP_DEL_PEER;
        buf = &del_peer;
        len = sizeof(del_peer);
    }

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, ioctl, buf, len, NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_DEL_PEER) failed");
        return -1;
    }
    return 0;
}

int
dco_set_peer(dco_context_t *dco, unsigned int peerid,
             int keepalive_interval, int keepalive_timeout, int mss)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, keepalive %d/%d, mss %d", __func__,
        peerid, keepalive_interval, keepalive_timeout, mss);

    OVPN_MP_SET_PEER mp_peer = { peerid, keepalive_interval, keepalive_timeout, mss };
    OVPN_SET_PEER peer = { keepalive_interval, keepalive_timeout, mss };
    VOID *buf = NULL;
    DWORD len = 0;
    DWORD ioctl = (dco->ifmode == DCO_MODE_MP) ? OVPN_IOCTL_MP_SET_PEER : OVPN_IOCTL_SET_PEER;

    if (dco->ifmode == DCO_MODE_MP)
    {
        buf = &mp_peer;
        len = sizeof(OVPN_MP_SET_PEER);
    }
    else
    {
        buf = &peer;
        len = sizeof(OVPN_SET_PEER);
    }

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, ioctl, buf, len, NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_MP_SET_PEER) failed");
        return -1;
    }

    return 0;
}

int
dco_new_key(dco_context_t *dco, unsigned int peerid, int keyid,
            dco_key_slot_t slot,
            const uint8_t *encrypt_key, const uint8_t *encrypt_iv,
            const uint8_t *decrypt_key, const uint8_t *decrypt_iv,
            const char *ciphername)
{
    msg(D_DCO_DEBUG, "%s: slot %d, key-id %d, peer-id %d, cipher %s",
        __func__, slot, keyid, peerid, ciphername);

    const int nonce_len = 8;
    size_t key_len = cipher_kt_key_size(ciphername);

    OVPN_CRYPTO_DATA crypto_data;
    ZeroMemory(&crypto_data, sizeof(crypto_data));

    crypto_data.CipherAlg = dco_get_cipher(ciphername);
    crypto_data.KeyId = keyid;
    crypto_data.PeerId = peerid;
    crypto_data.KeySlot = slot;

    CopyMemory(crypto_data.Encrypt.Key, encrypt_key, key_len);
    crypto_data.Encrypt.KeyLen = (char)key_len;
    CopyMemory(crypto_data.Encrypt.NonceTail, encrypt_iv, nonce_len);

    CopyMemory(crypto_data.Decrypt.Key, decrypt_key, key_len);
    crypto_data.Decrypt.KeyLen = (char)key_len;
    CopyMemory(crypto_data.Decrypt.NonceTail, decrypt_iv, nonce_len);

    ASSERT(crypto_data.CipherAlg > 0);

    DWORD bytes_returned = 0;

    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_NEW_KEY, &crypto_data,
                         sizeof(crypto_data), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_NEW_KEY) failed");
        return -1;
    }
    return 0;
}
int
dco_del_key(dco_context_t *dco, unsigned int peerid, dco_key_slot_t slot)
{
    msg(D_DCO, "%s: peer-id %d, slot %d called but ignored", __func__, peerid,
        slot);
    /* FIXME: Implement in driver first */
    return 0;
}

int
dco_swap_keys(dco_context_t *dco, unsigned int peer_id)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peer_id);

    OVPN_MP_SWAP_KEYS swap = {peer_id};
    DWORD ioctl = OVPN_IOCTL_SWAP_KEYS;
    VOID *buf = NULL;
    DWORD len = 0;

    if (dco->ifmode == DCO_MODE_MP)
    {
        ioctl = OVPN_IOCTL_MP_SWAP_KEYS;
        buf = &swap;
        len = sizeof(swap);
    }

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, ioctl, buf, len, NULL, 0, &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_SWAP_KEYS) failed");
        return -1;
    }
    return 0;
}

bool
dco_available(int msglevel)
{
    /* try to open device by symbolic name */
    HANDLE h = CreateFile("\\\\.\\ovpn-dco", GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);

    if (h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
        return true;
    }

    DWORD err = GetLastError();
    if (err == ERROR_ACCESS_DENIED)
    {
        /* this likely means that device exists but is already in use,
         * don't bail out since later we try to open all existing dco
         * devices and then bail out if all devices are in use
         */
        return true;
    }

    msg(msglevel, "Note: ovpn-dco-win driver is missing, disabling data channel offload.");
    return false;
}

const char *
dco_version_string(struct gc_arena *gc)
{
    OVPN_VERSION version = {0};
    if (dco_get_version(&version))
    {
        struct buffer out = alloc_buf_gc(256, gc);
        buf_printf(&out, "%ld.%ld.%ld", version.Major, version.Minor, version.Patch);
        return BSTR(&out);
    }
    else
    {
        return "N/A";
    }
}

/**
 * @brief Handles successful completion of overlapped operation.
 *
 * We use overlapped I/O (Windows term for asynchronous I/O) to get
 * notifications from kernel to userspace. This gets the result of overlapped
 * operation and, in case of success, copies data from kernel-filled buffer
 * into userspace-provided dco context.
 *
 * @param dco Pointer to the dco context
 * @param queued true if operation was queued, false if it has completed immediately
 */
static void
dco_handle_overlapped_success(dco_context_t *dco, bool queued)
{
    DWORD bytes_read = 0;
    BOOL res = GetOverlappedResult(dco->tt->hand, &dco->ov, &bytes_read, FALSE);
    if (res)
    {
        msg(D_DCO_DEBUG, "%s: completion%s success [%ld]", __func__, queued ? "" : " non-queued", bytes_read);

        dco->dco_message_peer_id = dco->notif_buf.PeerId;
        dco->dco_message_type = dco->notif_buf.Cmd;
        dco->dco_del_peer_reason = dco->notif_buf.DelPeerReason;
    }
    else
    {
        msg(D_DCO_DEBUG | M_ERRNO, "%s: completion%s error", __func__, queued ? "" : " non-queued");
    }
}

int
dco_do_read(dco_context_t *dco)
{
    if (dco->ifmode != DCO_MODE_MP)
    {
        ASSERT(false);
    }

    dco->dco_message_peer_id = -1;
    dco->dco_message_type = 0;

    switch (dco->iostate)
    {
        case IOSTATE_QUEUED:
            dco_handle_overlapped_success(dco, true);

            ASSERT(ResetEvent(dco->ov.hEvent));
            dco->iostate = IOSTATE_INITIAL;

            break;

        case IOSTATE_IMMEDIATE_RETURN:
            dco->iostate = IOSTATE_INITIAL;
            ASSERT(ResetEvent(dco->ov.hEvent));

            if (dco->ov_ret == ERROR_SUCCESS)
            {
                dco_handle_overlapped_success(dco, false);
            }
            else
            {
                SetLastError(dco->ov_ret);
                msg(D_DCO_DEBUG | M_ERRNO, "%s: completion non-queued error", __func__);
            }

            break;
    }

    return 0;
}

int
dco_get_peer_stats_multi(dco_context_t *dco, struct multi_context *m,
                         const bool raise_sigusr1_on_err)
{
    /* Not implemented. */
    return 0;
}

int
dco_get_peer_stats(struct context *c, const bool raise_sigusr1_on_err)
{
    struct tuntap *tt = c->c1.tuntap;

    if (!tuntap_defined(tt))
    {
        return -1;
    }

    OVPN_STATS stats;
    ZeroMemory(&stats, sizeof(OVPN_STATS));

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(tt->hand, OVPN_IOCTL_GET_STATS, NULL, 0,
                         &stats, sizeof(stats), &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_GET_STATS) failed");
        return -1;
    }

    c->c2.dco_read_bytes = stats.TransportBytesReceived;
    c->c2.dco_write_bytes = stats.TransportBytesSent;
    c->c2.tun_read_bytes = stats.TunBytesReceived;
    c->c2.tun_write_bytes = stats.TunBytesSent;

    return 0;
}

void
dco_event_set(dco_context_t *dco, struct event_set *es, void *arg)
{
    if (dco->ifmode != DCO_MODE_MP)
    {
        /* mp only */
        return;
    }

    event_ctl(es, &dco->rwhandle, EVENT_READ, arg);

    if (dco->iostate == IOSTATE_INITIAL)
    {
        /* the overlapped IOCTL will signal this event on I/O completion */
        ASSERT(ResetEvent(dco->ov.hEvent));

        if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_NOTIFY_EVENT, NULL, 0, &dco->notif_buf, sizeof(dco->notif_buf), NULL, &dco->ov))
        {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) /* operation queued? */
            {
                dco->iostate = IOSTATE_QUEUED;
                dco->ov_ret = ERROR_SUCCESS;

                msg(D_DCO_DEBUG, "%s: notify ioctl queued", __func__);
            }
            else
            {
                /* error occured */
                ASSERT(SetEvent(dco->ov.hEvent));
                dco->iostate = IOSTATE_IMMEDIATE_RETURN;
                dco->ov_ret = err;

                msg(D_DCO_DEBUG | M_ERRNO, "%s: notify ioctl error", __func__);
            }
        }
        else
        {
            ASSERT(SetEvent(dco->ov.hEvent));
            dco->iostate = IOSTATE_IMMEDIATE_RETURN;
            dco->ov_ret = ERROR_SUCCESS;

            msg(D_DCO_DEBUG, "%s: notify ioctl immediate return", __func__);
        }
    }
}

const char *
dco_get_supported_ciphers(void)
{
    /*
     * this API can be called either from user mode or kernel mode,
     * which enables us to probe driver's chachapoly support
     * (available starting from Windows 11)
     */

    BCRYPT_ALG_HANDLE h;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h, L"CHACHA20_POLY1305", NULL, 0);
    if (BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(h, 0);
        return "AES-128-GCM:AES-256-GCM:AES-192-GCM:CHACHA20-POLY1305";
    }
    else
    {
        return "AES-128-GCM:AES-256-GCM:AES-192-GCM";
    }
}

bool
dco_win_supports_multipeer(void)
{
    OVPN_VERSION ver = { 0 };
    return dco_get_version(&ver) && ver.Major >= 2;
}

void
dco_win_add_iroute_ipv4(dco_context_t *dco, in_addr_t dst, unsigned int netbits, unsigned int peer_id)
{
    struct gc_arena gc = gc_new();

    OVPN_MP_IROUTE route = {.Addr.Addr4.S_un.S_addr = dst, .Netbits = netbits, .PeerId = peer_id, .IPv6 = 0};

    msg(D_DCO_DEBUG, "%s: %s/%d -> peer %d", __func__, print_in_addr_t(dst, IA_NET_ORDER, &gc), netbits, peer_id);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_MP_ADD_IROUTE, &route,
                         sizeof(route), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_MP_ADD_IROUTE) failed");
    }

    gc_free(&gc);
}

void
dco_win_add_iroute_ipv6(dco_context_t *dco, struct in6_addr dst, unsigned int netbits, unsigned int peer_id)
{
    struct gc_arena gc = gc_new();

    OVPN_MP_IROUTE route = { .Addr.Addr6 = dst, .Netbits = netbits, .PeerId = peer_id, .IPv6 = 1 };

    msg(D_DCO_DEBUG, "%s: %s/%d -> peer %d", __func__, print_in6_addr(dst, IA_NET_ORDER, &gc), netbits, peer_id);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_MP_ADD_IROUTE, &route,
                         sizeof(route), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_MP_ADD_IROUTE) failed");
    }

    gc_free(&gc);
}

void
dco_win_del_iroute_ipv4(dco_context_t *dco, in_addr_t dst, unsigned int netbits)
{
    struct gc_arena gc = gc_new();

    OVPN_MP_IROUTE route = { .Addr.Addr4.S_un.S_addr = dst, .Netbits = netbits, .PeerId = -1, .IPv6 = 0 };

    msg(D_DCO_DEBUG, "%s: %s/%d", __func__, print_in_addr_t(dst, IA_NET_ORDER, &gc), netbits);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_MP_DEL_IROUTE, &route,
                         sizeof(route), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_MP_DEL_IROUTE) failed");
    }

    gc_free(&gc);
}

void
dco_win_del_iroute_ipv6(dco_context_t *dco, struct in6_addr dst, unsigned int netbits)
{
    struct gc_arena gc = gc_new();

    OVPN_MP_IROUTE route = { .Addr.Addr6 = dst, .Netbits = netbits, .PeerId = -1, .IPv6 = 1 };

    msg(D_DCO_DEBUG, "%s: %s/%d", __func__, print_in6_addr(dst, IA_NET_ORDER, &gc), netbits);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_MP_DEL_IROUTE, &route,
                         sizeof(route), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_MP_DEL_IROUTE) failed");
    }

    gc_free(&gc);
}

#endif /* defined(_WIN32) */
