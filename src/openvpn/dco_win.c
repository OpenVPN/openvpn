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

struct tuntap
create_dco_handle(const char *devname, struct gc_arena *gc)
{
    struct tuntap tt = { .windows_driver = WINDOWS_DRIVER_DCO };
    const char *device_guid;

    tun_open_device(&tt, devname, &device_guid, gc);

    return tt;
}

bool
ovpn_dco_init(int mode, dco_context_t *dco)
{
    return true;
}

int
open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev)
{
    ASSERT(0);
    return 0;
}

static void
dco_wait_ready(DWORD idx)
{
    for (int i = 0; i < 20; ++i)
    {
        MIB_IPINTERFACE_ROW row = {.InterfaceIndex = idx, .Family = AF_INET};
        if (GetIpInterfaceEntry(&row) != ERROR_NOT_FOUND)
        {
            break;
        }
        msg(D_DCO_DEBUG, "interface %ld not yet ready, retrying", idx);
        Sleep(50);
    }
}

void
dco_start_tun(struct tuntap *tt)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    /* reference the tt object inside the DCO context, because the latter will
     * be passed around
     */
    tt->dco.tt = tt;

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(tt->hand, OVPN_IOCTL_START_VPN, NULL, 0, NULL, 0,
                         &bytes_returned, NULL))
    {
        msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_START_VPN) failed");
    }

    /* Sometimes IP Helper API, which we use for setting IP address etc,
     * complains that interface is not found. Give it some time to settle
     */
    dco_wait_ready(tt->adapter_index);
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

void
dco_create_socket(HANDLE handle, struct addrinfo *remoteaddr, bool bind_local,
                  struct addrinfo *bind, int timeout,
                  struct signal_info *sig_info)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    OVPN_NEW_PEER peer = { 0 };

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

    if (bind_local)
    {
        /* Use first local address with correct address family */
        while (bind && !local)
        {
            if (bind->ai_family == remote->sa_family)
            {
                local = bind->ai_addr;
            }
            bind = bind->ai_next;
        }
    }

    if (bind_local && !local)
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

    OVERLAPPED ov = { 0 };
    if (!DeviceIoControl(handle, OVPN_IOCTL_NEW_PEER, &peer, sizeof(peer), NULL, 0, NULL, &ov))
    {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            msg(M_ERR, "DeviceIoControl(OVPN_IOCTL_NEW_PEER) failed");
        }
        else
        {
            dco_connect_wait(handle, &ov, timeout, sig_info);
        }
    }
}

int
dco_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
             struct sockaddr *localaddr, struct sockaddr *remoteaddr,
             struct in_addr *remote_in4, struct in6_addr *remote_in6)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d", __func__, peerid, sd);
    return 0;
}

int
dco_del_peer(dco_context_t *dco, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_DEL_PEER, NULL,
                         0, NULL, 0, &bytes_returned, NULL))
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

    OVPN_SET_PEER peer;

    peer.KeepaliveInterval =  keepalive_interval;
    peer.KeepaliveTimeout = keepalive_timeout;
    peer.MSS = mss;

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_SET_PEER, &peer,
                         sizeof(peer), NULL, 0, &bytes_returned, NULL))
    {
        msg(M_WARN | M_ERRNO, "DeviceIoControl(OVPN_IOCTL_SET_PEER) failed");
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

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(dco->tt->hand, OVPN_IOCTL_SWAP_KEYS, NULL, 0, NULL, 0,
                         &bytes_returned, NULL))
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
    OVPN_VERSION version;
    ZeroMemory(&version, sizeof(OVPN_VERSION));

    /* first, try a non-exclusive control device, available from 1.3.0 */
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
        return "N/A";
    }

    DWORD bytes_returned = 0;
    if (!DeviceIoControl(h, OVPN_IOCTL_GET_VERSION, NULL, 0,
                         &version, sizeof(version), &bytes_returned, NULL))
    {
        CloseHandle(h);
        return "N/A";
    }

    CloseHandle(h);

    struct buffer out = alloc_buf_gc(256, gc);
    buf_printf(&out, "%ld.%ld.%ld", version.Major, version.Minor, version.Patch);

    return BSTR(&out);
}

int
dco_do_read(dco_context_t *dco)
{
    /* no-op on windows */
    ASSERT(0);
    return 0;
}

int
dco_get_peer_stats_multi(dco_context_t *dco, struct multi_context *m)
{
    /* Not implemented. */
    return 0;
}

int
dco_get_peer_stats(struct context *c)
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
    /* no-op on windows */
    ASSERT(0);
}

const char *
dco_get_supported_ciphers()
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

#endif /* defined(_WIN32) */
