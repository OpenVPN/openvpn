/*
 *  Interface to FreeBSD dco networking code
 *
 *  Copyright (C) 2022 Rubicon Communications, LLC (Netgate). All Rights Reserved.
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

#if defined(ENABLE_DCO) && defined(TARGET_FREEBSD)

#include "syshead.h"

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/nv.h>
#include <sys/utsname.h>

#include <netinet/in.h>

#include "dco_freebsd.h"
#include "dco.h"
#include "tun.h"
#include "crypto.h"
#include "multi.h"
#include "ssl_common.h"

static nvlist_t *
sockaddr_to_nvlist(const struct sockaddr *sa)
{
    nvlist_t *nvl = nvlist_create(0);

    nvlist_add_number(nvl, "af", sa->sa_family);

    switch (sa->sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
            nvlist_add_binary(nvl, "address", &in->sin_addr, sizeof(in->sin_addr));
            nvlist_add_number(nvl, "port", in->sin_port);
            break;
        }

        case AF_INET6:
        {
            const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
            nvlist_add_binary(nvl, "address", &in6->sin6_addr, sizeof(in6->sin6_addr));
            nvlist_add_number(nvl, "port", in6->sin6_port);
            break;
        }

        default:
            ASSERT(0);
    }

    return (nvl);
}

int
dco_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
             struct sockaddr *localaddr, struct sockaddr *remoteaddr,
             struct in_addr *remote_in4, struct in6_addr *remote_in6)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    int ret;

    nvl = nvlist_create(0);

    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d", __func__, peerid, sd);

    if (localaddr)
    {
        nvlist_add_nvlist(nvl, "local", sockaddr_to_nvlist(localaddr));
    }

    if (remoteaddr)
    {
        nvlist_add_nvlist(nvl, "remote", sockaddr_to_nvlist(remoteaddr));
    }

    if (remote_in4)
    {
        nvlist_add_binary(nvl, "vpn_ipv4", &remote_in4->s_addr,
                          sizeof(remote_in4->s_addr));
    }

    if (remote_in6)
    {
        nvlist_add_binary(nvl, "vpn_ipv6", remote_in6, sizeof(*remote_in6));
    }

    nvlist_add_number(nvl, "fd", sd);
    nvlist_add_number(nvl, "peerid", peerid);

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_NEW_PEER;
    drv.ifd_data = nvlist_pack(nvl, &drv.ifd_len);

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_ERR | M_ERRNO, "Failed to create new peer");
    }

    free(drv.ifd_data);
    nvlist_destroy(nvl);

    return ret;
}

static int
open_fd(dco_context_t *dco)
{
    int ret;

    ret = pipe2(dco->pipefd, O_CLOEXEC | O_NONBLOCK);
    if (ret != 0)
    {
        return -1;
    }

    dco->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (dco->fd != -1)
    {
        dco->open = true;
    }

    return dco->fd;
}

static void
close_fd(dco_context_t *dco)
{
    close(dco->pipefd[0]);
    close(dco->pipefd[1]);
    close(dco->fd);
}

bool
ovpn_dco_init(int mode, dco_context_t *dco)
{
    if (open_fd(dco) < 0)
    {
        msg(M_ERR, "Failed to open socket");
        return false;
    }
    return true;
}

static int
dco_set_ifmode(dco_context_t *dco, int ifmode)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    int ret;

    nvl = nvlist_create(0);
    nvlist_add_number(nvl, "ifmode", ifmode);

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_SET_IFMODE;
    drv.ifd_data = nvlist_pack(nvl, &drv.ifd_len);

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "dco_set_ifmode: failed to set ifmode=%08x", ifmode);
    }

    free(drv.ifd_data);
    nvlist_destroy(nvl);

    return ret;
}

static int
create_interface(struct tuntap *tt, const char *dev)
{
    int ret;
    struct ifreq ifr;

    CLEAR(ifr);

    /* Create ovpnx first, then rename it. */
    snprintf(ifr.ifr_name, IFNAMSIZ, "ovpn");
    ret = ioctl(tt->dco.fd, SIOCIFCREATE2, &ifr);
    if (ret)
    {
        ret = -errno;
        msg(M_WARN|M_ERRNO, "Failed to create interface %s (SIOCIFCREATE2)", ifr.ifr_name);
        return ret;
    }

    /* Rename */
    if (!strcmp(dev, "tun"))
    {
        ifr.ifr_data = "ovpn";
    }
    else
    {
        ifr.ifr_data = (char *)dev;
    }
    ret = ioctl(tt->dco.fd, SIOCSIFNAME, &ifr);
    if (ret)
    {
        ret = -errno;
        /* Delete the created interface again. */
        (void)ioctl(tt->dco.fd, SIOCIFDESTROY, &ifr);
        msg(M_WARN|M_ERRNO, "Failed to create interface %s (SIOCSIFNAME)", ifr.ifr_data);
        return ret;
    }

    snprintf(tt->dco.ifname, IFNAMSIZ, "%s", ifr.ifr_data);

    /* see "Interface Flags" in ifnet(9) */
    int i = IFF_POINTOPOINT | IFF_MULTICAST;
    if (tt->topology == TOP_SUBNET)
    {
        i = IFF_BROADCAST | IFF_MULTICAST;
    }
    dco_set_ifmode(&tt->dco, i);

    return 0;
}

static int
remove_interface(struct tuntap *tt)
{
    int ret;
    struct ifreq ifr;

    CLEAR(ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tt->dco.ifname);

    ret = ioctl(tt->dco.fd, SIOCIFDESTROY, &ifr);
    if (ret)
    {
        msg(M_ERR | M_ERRNO, "Failed to remove interface %s", ifr.ifr_name);
    }

    tt->dco.ifname[0] = 0;

    return ret;
}

int
open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev)
{
    return create_interface(tt, dev);
}

void
close_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    remove_interface(tt);
    close_fd(&tt->dco);
}

int
dco_swap_keys(dco_context_t *dco, unsigned int peerid)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    int ret;

    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    nvl = nvlist_create(0);
    nvlist_add_number(nvl, "peerid", peerid);

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_SWAP_KEYS;
    drv.ifd_data = nvlist_pack(nvl, &drv.ifd_len);

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "Failed to swap keys");
    }

    free(drv.ifd_data);
    nvlist_destroy(nvl);

    return ret;
}

int
dco_del_peer(dco_context_t *dco, unsigned int peerid)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    int ret;

    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    nvl = nvlist_create(0);
    nvlist_add_number(nvl, "peerid", peerid);

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_DEL_PEER;
    drv.ifd_data = nvlist_pack(nvl, &drv.ifd_len);

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "Failed to delete peer");
    }

    free(drv.ifd_data);
    nvlist_destroy(nvl);

    return ret;
}

int
dco_del_key(dco_context_t *dco, unsigned int peerid,
            dco_key_slot_t slot)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    int ret;

    msg(D_DCO_DEBUG, "%s: peer-id %d, slot %d", __func__, peerid, slot);

    nvl = nvlist_create(0);
    nvlist_add_number(nvl, "slot", slot);
    nvlist_add_number(nvl, "peerid", peerid);

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_DEL_KEY;
    drv.ifd_data = nvlist_pack(nvl, &drv.ifd_len);

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "Failed to delete key");
    }

    free(drv.ifd_data);
    nvlist_destroy(nvl);

    return ret;
}

static nvlist_t *
key_to_nvlist(const uint8_t *key, const uint8_t *implicit_iv, const char *ciphername)
{
    nvlist_t *nvl;
    size_t key_len;

    nvl = nvlist_create(0);

    nvlist_add_string(nvl, "cipher", ciphername);

    if (strcmp(ciphername, "none") != 0)
    {
        key_len = cipher_kt_key_size(ciphername);

        nvlist_add_binary(nvl, "key", key, key_len);
        nvlist_add_binary(nvl, "iv", implicit_iv, 8);
    }

    return (nvl);
}

static int
start_tun(dco_context_t *dco)
{
    struct ifdrv drv;
    int ret;

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_START_VPN;

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_ERR | M_ERRNO, "Failed to start vpn");
    }

    return ret;
}

int
dco_new_key(dco_context_t *dco, unsigned int peerid, int keyid,
            dco_key_slot_t slot,
            const uint8_t *encrypt_key, const uint8_t *encrypt_iv,
            const uint8_t *decrypt_key, const uint8_t *decrypt_iv,
            const char *ciphername)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    int ret;

    msg(D_DCO_DEBUG, "%s: slot %d, key-id %d, peer-id %d, cipher %s",
        __func__, slot, keyid, peerid, ciphername);

    nvl = nvlist_create(0);

    nvlist_add_number(nvl, "slot", slot);
    nvlist_add_number(nvl, "keyid", keyid);
    nvlist_add_number(nvl, "peerid", peerid);

    nvlist_add_nvlist(nvl, "encrypt",
                      key_to_nvlist(encrypt_key, encrypt_iv, ciphername));
    nvlist_add_nvlist(nvl, "decrypt",
                      key_to_nvlist(decrypt_key, decrypt_iv, ciphername));

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_NEW_KEY;
    drv.ifd_data = nvlist_pack(nvl, &drv.ifd_len);

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_ERR | M_ERRNO, "Failed to set key");
    }
    else
    {
        ret = start_tun(dco);
    }

    free(drv.ifd_data);
    nvlist_destroy(nvl);

    return ret;
}

int
dco_set_peer(dco_context_t *dco, unsigned int peerid,
             int keepalive_interval, int keepalive_timeout,
             int mss)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    int ret;

    msg(D_DCO_DEBUG, "%s: peer-id %d, ping interval %d, ping timeout %d",
        __func__, peerid, keepalive_interval, keepalive_timeout);

    nvl = nvlist_create(0);
    nvlist_add_number(nvl, "peerid", peerid);
    nvlist_add_number(nvl, "interval", keepalive_interval);
    nvlist_add_number(nvl, "timeout", keepalive_timeout);

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_SET_PEER;
    drv.ifd_data = nvlist_pack(nvl, &drv.ifd_len);

    ret = ioctl(dco->fd, SIOCSDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "Failed to set keepalive");
    }

    free(drv.ifd_data);
    nvlist_destroy(nvl);

    return ret;
}

int
dco_do_read(dco_context_t *dco)
{
    struct ifdrv drv;
    uint8_t buf[4096];
    nvlist_t *nvl;
    enum ovpn_notif_type type;
    int ret;

    /* Flush any pending data from the pipe. */
    (void)read(dco->pipefd[1], buf, sizeof(buf));

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_GET_PKT;
    drv.ifd_data = buf;
    drv.ifd_len = sizeof(buf);

    ret = ioctl(dco->fd, SIOCGDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "Failed to read control packet");
        return -errno;
    }

    nvl = nvlist_unpack(buf, drv.ifd_len, 0);
    if (!nvl)
    {
        msg(M_WARN, "Failed to unpack nvlist");
        return -EINVAL;
    }

    dco->dco_message_peer_id = nvlist_get_number(nvl, "peerid");

    type = nvlist_get_number(nvl, "notification");
    switch (type)
    {
        case OVPN_NOTIF_DEL_PEER:
            dco->dco_del_peer_reason = OVPN_DEL_PEER_REASON_EXPIRED;

            if (nvlist_exists_number(nvl, "del_reason"))
            {
                uint32_t reason = nvlist_get_number(nvl, "del_reason");
                if (reason == OVPN_DEL_REASON_TIMEOUT)
                {
                    dco->dco_del_peer_reason = OVPN_DEL_PEER_REASON_EXPIRED;
                }
                else
                {
                    dco->dco_del_peer_reason = OVPN_DEL_PEER_REASON_USERSPACE;
                }
            }

            if (nvlist_exists_nvlist(nvl, "bytes"))
            {
                const nvlist_t *bytes = nvlist_get_nvlist(nvl, "bytes");

                dco->dco_read_bytes = nvlist_get_number(bytes, "in");
                dco->dco_write_bytes = nvlist_get_number(bytes, "out");
            }

            dco->dco_message_type = OVPN_CMD_DEL_PEER;
            break;

        case OVPN_NOTIF_ROTATE_KEY:
            dco->dco_message_type = OVPN_CMD_SWAP_KEYS;
            break;

        default:
            msg(M_WARN, "Unknown kernel notification %d", type);
            break;
    }

    nvlist_destroy(nvl);

    return 0;
}

bool
dco_available(int msglevel)
{
    struct if_clonereq ifcr;
    char *buf = NULL;
    int fd;
    int ret;
    bool available = false;

    /* Attempt to load the module. Ignore errors, because it might already be
     * loaded, or built into the kernel. */
    (void)kldload("if_ovpn");

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        return false;
    }

    CLEAR(ifcr);

    /* List cloners and check if openvpn is there. That tells us if this kernel
     * supports if_ovpn (i.e. DCO) or not. */
    ret = ioctl(fd, SIOCIFGCLONERS, &ifcr);
    if (ret != 0)
    {
        goto out;
    }

    buf = malloc(ifcr.ifcr_total * IFNAMSIZ);
    if (!buf)
    {
        goto out;
    }

    ifcr.ifcr_count = ifcr.ifcr_total;
    ifcr.ifcr_buffer = buf;
    ret = ioctl(fd, SIOCIFGCLONERS, &ifcr);
    if (ret != 0)
    {
        goto out;
    }

    for (int i = 0; i < ifcr.ifcr_total; i++)
    {
        if (strcmp(buf + (i * IFNAMSIZ), "openvpn") == 0)
        {
            available = true;
            goto out;
        }
    }

out:
    free(buf);
    close(fd);

    return available;
}

const char *
dco_version_string(struct gc_arena *gc)
{
    struct utsname *uts;
    ALLOC_OBJ_GC(uts, struct utsname, gc);

    if (uname(uts) != 0)
    {
        return "N/A";
    }

    return uts->version;
}

void
dco_event_set(dco_context_t *dco, struct event_set *es, void *arg)
{
    struct ifdrv drv;
    nvlist_t *nvl;
    uint8_t buf[128];
    int ret;

    if (!dco || !dco->open)
    {
        return;
    }

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_POLL_PKT;
    drv.ifd_len = sizeof(buf);
    drv.ifd_data = buf;

    ret = ioctl(dco->fd, SIOCGDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "Failed to poll for packets");
        return;
    }

    nvl = nvlist_unpack(buf, drv.ifd_len, 0);
    if (!nvl)
    {
        msg(M_WARN, "Failed to unpack nvlist");
        return;
    }

    if (nvlist_get_number(nvl, "pending") > 0)
    {
        (void)write(dco->pipefd[0], " ", 1);
        event_ctl(es, dco->pipefd[1], EVENT_READ, arg);
    }

    nvlist_destroy(nvl);
}

static void
dco_update_peer_stat(struct multi_context *m, uint32_t peerid, const nvlist_t *nvl)
{

    if (peerid >= m->max_clients || !m->instances[peerid])
    {
        msg(M_WARN, "dco_update_peer_stat: invalid peer ID %d returned by kernel", peerid);
        return;
    }

    struct multi_instance *mi = m->instances[peerid];

    mi->context.c2.dco_read_bytes = nvlist_get_number(nvl, "in");
    mi->context.c2.dco_write_bytes = nvlist_get_number(nvl, "out");
}

int
dco_get_peer_stats_multi(dco_context_t *dco, struct multi_context *m)
{

    struct ifdrv drv;
    uint8_t buf[4096];
    nvlist_t *nvl;
    const nvlist_t *const *nvpeers;
    size_t npeers;
    int ret;

    if (!dco || !dco->open)
    {
        return 0;
    }

    CLEAR(drv);
    snprintf(drv.ifd_name, IFNAMSIZ, "%s", dco->ifname);
    drv.ifd_cmd = OVPN_GET_PEER_STATS;
    drv.ifd_len = sizeof(buf);
    drv.ifd_data = buf;

    ret = ioctl(dco->fd, SIOCGDRVSPEC, &drv);
    if (ret)
    {
        msg(M_WARN | M_ERRNO, "Failed to get peer stats");
        return -EINVAL;
    }

    nvl = nvlist_unpack(buf, drv.ifd_len, 0);
    if (!nvl)
    {
        msg(M_WARN, "Failed to unpack nvlist");
        return -EINVAL;
    }

    if (!nvlist_exists_nvlist_array(nvl, "peers"))
    {
        /* no peers */
        return 0;
    }

    nvpeers = nvlist_get_nvlist_array(nvl, "peers", &npeers);
    for (size_t i = 0; i < npeers; i++)
    {
        const nvlist_t *peer = nvpeers[i];
        uint32_t peerid = nvlist_get_number(peer, "peerid");

        dco_update_peer_stat(m, peerid, nvlist_get_nvlist(peer, "bytes"));
    }

    return 0;
}

int
dco_get_peer_stats(struct context *c)
{
    /* Not implemented. */
    return 0;
}

const char *
dco_get_supported_ciphers()
{
    return "none:AES-256-GCM:AES-192-GCM:AES-128-GCM:CHACHA20-POLY1305";
}

#endif /* defined(ENABLE_DCO) && defined(TARGET_FREEBSD) */
