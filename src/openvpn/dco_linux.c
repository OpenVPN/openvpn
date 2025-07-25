/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020-2025 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2020-2025 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2025 OpenVPN Inc <sales@openvpn.net>
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

#if defined(ENABLE_DCO) && defined(TARGET_LINUX)

#include "syshead.h"

#include "dco_linux.h"
#include "errlevel.h"
#include "buffer.h"
#include "networking.h"
#include "openvpn.h"

#include "socket.h"
#include "tun.h"
#include "ssl.h"
#include "fdmisc.h"
#include "multi.h"
#include "ssl_verify.h"

#include "ovpn_dco_linux.h"

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>


/* libnl < 3.5.0 does not set the NLA_F_NESTED on its own, therefore we
 * have to explicitly do it to prevent the kernel from failing upon
 * parsing of the message
 */
#define nla_nest_start(_msg, _type) \
    nla_nest_start(_msg, (_type) | NLA_F_NESTED)

static int ovpn_get_mcast_id(dco_context_t *dco);

void dco_check_key_ctx(const struct key_ctx_bi *key);

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

/**
 * @brief resolves the netlink ID for ovpn-dco
 *
 * This function queries the kernel via a netlink socket
 * whether the ovpn-dco netlink namespace is available
 *
 * This function can be used to determine if the kernel
 * supports DCO offloading.
 *
 * @return ID on success, negative error code on error
 */
static int
resolve_ovpn_netlink_id(int msglevel)
{
    int ret;
    struct nl_sock *nl_sock = nl_socket_alloc();

    if (!nl_sock)
    {
        msg(msglevel, "Allocating net link socket failed");
        return -ENOMEM;
    }

    ret = genl_connect(nl_sock);
    if (ret)
    {
        msg(msglevel, "Cannot connect to generic netlink: %s",
            nl_geterror(ret));
        goto err_sock;
    }
    set_cloexec(nl_socket_get_fd(nl_sock));

    ret = genl_ctrl_resolve(nl_sock, OVPN_FAMILY_NAME);
    if (ret < 0)
    {
        msg(msglevel, "Cannot find ovpn_dco netlink component: %s",
            nl_geterror(ret));
    }

err_sock:
    nl_socket_free(nl_sock);
    return ret;
}

static struct nl_msg *
ovpn_dco_nlmsg_create(dco_context_t *dco, int cmd)
{
    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
    {
        msg(M_FATAL, "cannot allocate netlink message");
        return NULL;
    }

    genlmsg_put(nl_msg, 0, 0, dco->ovpn_dco_id, 0, 0, cmd, 0);
    NLA_PUT_U32(nl_msg, OVPN_A_IFINDEX, dco->ifindex);

    return nl_msg;
nla_put_failure:
    nlmsg_free(nl_msg);
    msg(M_INFO, "cannot put into netlink message");
    return NULL;
}

static int
ovpn_nl_recvmsgs(dco_context_t *dco, const char *prefix)
{
    int ret = nl_recvmsgs(dco->nl_sock, dco->nl_cb);

    switch (ret)
    {
        case -NLE_INTR:
            msg(M_WARN, "%s: netlink received interrupt due to signal - ignoring", prefix);
            break;

        case -NLE_NOMEM:
            msg(M_FATAL, "%s: netlink out of memory error", prefix);
            break;

        case -NLE_AGAIN:
            msg(M_WARN, "%s: netlink reports blocking read - aborting wait", prefix);
            break;

        case -NLE_NODEV:
            msg(M_FATAL, "%s: netlink reports device not found:", prefix);
            break;

        case -NLE_OBJ_NOTFOUND:
            msg(M_INFO, "%s: netlink reports object not found, ovpn-dco unloaded?", prefix);
            break;

        default:
            if (ret)
            {
                msg(M_NONFATAL, "%s: netlink reports error (%d): %s", prefix, ret, nl_geterror(-ret));
            }
            break;
    }

    return ret;
}

/**
 * Send a prepared netlink message.
 *
 * The method will also free nl_msg
 * @param dco       The dco context to use
 * @param nl_msg    the message to use
 * @param prefix    A prefix to report in the error message to give the user context
 * @return          status of sending the message
 */
static int
ovpn_nl_msg_send(dco_context_t *dco, struct nl_msg *nl_msg, const char *prefix)
{
    dco->status = 1;

    nl_send_auto(dco->nl_sock, nl_msg);

    while (dco->status == 1)
    {
        ovpn_nl_recvmsgs(dco, prefix);
    }

    if (dco->status < 0)
    {
        msg(M_INFO, "%s: failed to send netlink message: %s (%d)",
            prefix, strerror(-dco->status), dco->status);
    }

    return dco->status;
}

struct sockaddr *
mapped_v4_to_v6(struct sockaddr *sock, struct gc_arena *gc)
{
    struct sockaddr_in6 *sock6 = (struct sockaddr_in6 *)sock;
    if (sock->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&sock6->sin6_addr))
    {

        struct sockaddr_in *sock4;
        ALLOC_OBJ_CLEAR_GC(sock4, struct sockaddr_in, gc);
        memcpy(&sock4->sin_addr, sock6->sin6_addr.s6_addr + 12, 4);
        sock4->sin_port = sock6->sin6_port;
        sock4->sin_family = AF_INET;
        return (struct sockaddr *)sock4;
    }
    return sock;
}

int
dco_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
             struct sockaddr *localaddr, struct sockaddr *remoteaddr,
             struct in_addr *vpn_ipv4, struct in6_addr *vpn_ipv6)
{
    struct gc_arena gc = gc_new();
    const char *remotestr = "[undefined]";
    if (remoteaddr)
    {
        remotestr = print_sockaddr(remoteaddr, &gc);
    }
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d, remote addr: %s", __func__,
        peerid, sd, remotestr);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_PEER_NEW);
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_A_PEER);
    int ret = -EMSGSIZE;

    NLA_PUT_U32(nl_msg, OVPN_A_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_A_PEER_SOCKET, sd);

    /* Set the remote endpoint if defined (for UDP) */
    if (remoteaddr)
    {
        remoteaddr = mapped_v4_to_v6(remoteaddr, &gc);

        if (remoteaddr->sa_family == AF_INET)
        {
            NLA_PUT(nl_msg, OVPN_A_PEER_REMOTE_IPV4, sizeof(struct in_addr),
                    &((struct sockaddr_in *)remoteaddr)->sin_addr);
            NLA_PUT_U16(nl_msg, OVPN_A_PEER_REMOTE_PORT, ((struct sockaddr_in *)remoteaddr)->sin_port);
        }
        else if (remoteaddr->sa_family == AF_INET6)
        {
            NLA_PUT(nl_msg, OVPN_A_PEER_REMOTE_IPV6, sizeof(struct in6_addr),
                    &((struct sockaddr_in6 *)remoteaddr)->sin6_addr);
            NLA_PUT_U16(nl_msg, OVPN_A_PEER_REMOTE_PORT, ((struct sockaddr_in6 *)remoteaddr)->sin6_port);
            NLA_PUT_U32(nl_msg, OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID, ((struct sockaddr_in6 *)remoteaddr)->sin6_scope_id);
        }
    }

    if (localaddr)
    {
        localaddr = mapped_v4_to_v6(localaddr, &gc);
        if (localaddr->sa_family == AF_INET)
        {
            NLA_PUT(nl_msg, OVPN_A_PEER_LOCAL_IPV4, sizeof(struct in_addr),
                    &((struct sockaddr_in *)localaddr)->sin_addr);
        }
        else if (localaddr->sa_family == AF_INET6)
        {
            NLA_PUT(nl_msg, OVPN_A_PEER_LOCAL_IPV6, sizeof(struct in6_addr),
                    &((struct sockaddr_in6 *)localaddr)->sin6_addr);
        }
    }

    /* Set the primary VPN IP addresses of the peer */
    if (vpn_ipv4)
    {
        NLA_PUT_U32(nl_msg, OVPN_A_PEER_VPN_IPV4, vpn_ipv4->s_addr);
    }
    if (vpn_ipv6)
    {
        NLA_PUT(nl_msg, OVPN_A_PEER_VPN_IPV6, sizeof(struct in6_addr),
                vpn_ipv6);
    }
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    gc_free(&gc);
    return ret;
}

static int
ovpn_nl_cb_finish(struct nl_msg (*msg) __attribute__ ((unused)), void *arg)
{
    int *status = arg;

    *status = 0;
    return NL_SKIP;
}

/* The following enum members exist in netlink.h since linux-6.1.
 * However, some distro we support still ship an old header, thus
 * failing the OpenVPN compilation.
 *
 * For the time being we add the needed defines manually.
 * We will drop this definition once we stop supporting those old
 * distros.
 *
 * @NLMSGERR_ATTR_MISS_TYPE: type of a missing required attribute,
 *  %NLMSGERR_ATTR_MISS_NEST will not be present if the attribute was
 *  missing at the message level
 * @NLMSGERR_ATTR_MISS_NEST: offset of the nest where attribute was missing
 */
enum ovpn_nlmsgerr_attrs {
    OVPN_NLMSGERR_ATTR_MISS_TYPE = 5,
    OVPN_NLMSGERR_ATTR_MISS_NEST = 6,
    OVPN_NLMSGERR_ATTR_MAX = 6,
};

/* This function is used as error callback on the netlink socket.
 * When something goes wrong and the kernel returns an error, this function is
 * invoked.
 *
 * We pass the error code to the user by means of a variable pointed by *arg
 * (supplied by the user when setting this callback) and we parse the kernel
 * reply to see if it contains a human-readable error. If found, it is printed.
 */
static int
ovpn_nl_cb_error(struct sockaddr_nl (*nla) __attribute__ ((unused)),
                 struct nlmsgerr *err, void *arg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
    struct nlattr *tb_msg[OVPN_NLMSGERR_ATTR_MAX + 1];
    int len = nlh->nlmsg_len;
    struct nlattr *attrs;
    int *ret = arg;
    int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

    *ret = err->error;

    if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
    {
        return NL_STOP;
    }

    if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
    {
        ack_len += err->msg.nlmsg_len - sizeof(*nlh);
    }

    if (len <= ack_len)
    {
        return NL_STOP;
    }

    attrs = (void *)((unsigned char *)nlh + ack_len);
    len -= ack_len;

    nla_parse(tb_msg, OVPN_NLMSGERR_ATTR_MAX, attrs, len, NULL);
    if (tb_msg[NLMSGERR_ATTR_MSG])
    {
        len = strnlen((char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]),
                      nla_len(tb_msg[NLMSGERR_ATTR_MSG]));
        msg(M_WARN, "kernel error: %*s", len,
            (char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]));
    }

    if (tb_msg[OVPN_NLMSGERR_ATTR_MISS_NEST])
    {
        msg(M_WARN, "kernel error: missing required nesting type %u",
            nla_get_u32(tb_msg[OVPN_NLMSGERR_ATTR_MISS_NEST]));
    }

    if (tb_msg[OVPN_NLMSGERR_ATTR_MISS_TYPE])
    {
        msg(M_WARN, "kernel error: missing required attribute type %u",
            nla_get_u32(tb_msg[OVPN_NLMSGERR_ATTR_MISS_TYPE]));
    }

    return NL_STOP;
}

static void
ovpn_dco_register(dco_context_t *dco)
{
    msg(D_DCO_DEBUG, __func__);
    ovpn_get_mcast_id(dco);

    if (dco->ovpn_dco_mcast_id < 0)
    {
        msg(M_FATAL, "cannot get mcast group: %s",  nl_geterror(dco->ovpn_dco_mcast_id));
    }

    /* Register for ovpn-dco specific multicast messages that the kernel may
     * send
     */
    int ret = nl_socket_add_membership(dco->nl_sock, dco->ovpn_dco_mcast_id);
    if (ret)
    {
        msg(M_FATAL, "%s: failed to join groups: %d", __func__, ret);
    }
}

static int ovpn_handle_msg(struct nl_msg *msg, void *arg);

static void
ovpn_dco_init_netlink(dco_context_t *dco)
{
    dco->ovpn_dco_id = resolve_ovpn_netlink_id(M_FATAL);

    dco->nl_sock = nl_socket_alloc();

    if (!dco->nl_sock)
    {
        msg(M_FATAL, "Cannot create netlink socket");
    }

    int ret = genl_connect(dco->nl_sock);
    if (ret)
    {
        msg(M_FATAL, "Cannot connect to generic netlink: %s",
            nl_geterror(ret));
    }

    /* enable Extended ACK for detailed error reporting */
    ret = 1;
    setsockopt(nl_socket_get_fd(dco->nl_sock), SOL_NETLINK, NETLINK_EXT_ACK,
               &ret, sizeof(ret));

    /* set close on exec and non-block on the netlink socket */
    set_cloexec(nl_socket_get_fd(dco->nl_sock));
    set_nonblock(nl_socket_get_fd(dco->nl_sock));

    dco->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!dco->nl_cb)
    {
        msg(M_FATAL, "failed to allocate netlink callback");
    }

    nl_socket_set_cb(dco->nl_sock, dco->nl_cb);

    dco->dco_message_peer_id = -1;
    nl_cb_err(dco->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, ovpn_handle_msg, dco);

    ovpn_dco_register(dco);

    /* The async PACKET messages confuse libnl and it will drop them with
     * wrong sequence numbers (NLE_SEQ_MISMATCH), so disable libnl's sequence
     * number check */
    nl_socket_disable_seq_check(dco->nl_sock);

    /* nl library sets the buffer size to 32k/32k by default which is sometimes
     * overrun with very fast connecting/disconnecting clients.
     * TODO: fix this in a better and more reliable way */
    ASSERT(!nl_socket_set_buffer_size(dco->nl_sock, 1024*1024, 1024*1024));
}

bool
ovpn_dco_init(struct context *c)
{
    dco_context_t *dco = &c->c1.tuntap->dco;

    switch (c->mode)
    {
        case CM_TOP:
            dco->ifmode = OVPN_MODE_MP;
            break;

        case CM_P2P:
            dco->ifmode = OVPN_MODE_P2P;
            break;

        default:
            ASSERT(false);
    }

    /* store pointer to context as it may be required by message
     * parsing routines
     */
    dco->c = c;
    ovpn_dco_init_netlink(dco);
    return true;
}

static void
ovpn_dco_uninit_netlink(dco_context_t *dco)
{
    nl_socket_free(dco->nl_sock);
    dco->nl_sock = NULL;

    /* Decrease reference count */
    nl_cb_put(dco->nl_cb);

    CLEAR(dco);
}

int
open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev)
{
    msg(D_DCO_DEBUG, "%s: %s", __func__, dev);
    ASSERT(tt->type == DEV_TYPE_TUN);

    int ret = net_iface_new(ctx, dev, OVPN_FAMILY_NAME, &tt->dco);
    if (ret < 0)
    {
        msg(D_DCO_DEBUG, "Cannot create DCO interface %s: %d", dev, ret);
        return ret;
    }

    tt->dco.ifindex = if_nametoindex(dev);
    if (!tt->dco.ifindex)
    {
        msg(M_FATAL, "DCO: cannot retrieve ifindex for interface %s", dev);
    }

    return 0;
}

void
close_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    msg(D_DCO_DEBUG, __func__);

    net_iface_del(ctx, tt->actual_name);
    ovpn_dco_uninit_netlink(&tt->dco);
}

int
dco_swap_keys(dco_context_t *dco, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_KEY_SWAP);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_A_KEYCONF);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_A_KEYCONF_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}


int
dco_del_peer(dco_context_t *dco, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_PEER_DEL);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_A_PEER);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_A_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}


int
dco_del_key(dco_context_t *dco, unsigned int peerid,
            dco_key_slot_t slot)
{
    int ret = -EMSGSIZE;
    msg(D_DCO_DEBUG, "%s: peer-id %d, slot %d", __func__, peerid, slot);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_KEY_DEL);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *keyconf = nla_nest_start(nl_msg, OVPN_A_KEYCONF);
    NLA_PUT_U32(nl_msg, OVPN_A_KEYCONF_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_A_KEYCONF_SLOT, slot);
    nla_nest_end(nl_msg, keyconf);

    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
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

    const size_t key_len = cipher_kt_key_size(ciphername);
    const int nonce_tail_len = 8;

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_KEY_NEW);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    dco_cipher_t dco_cipher = dco_get_cipher(ciphername);

    int ret = -EMSGSIZE;

    struct nlattr *key_conf = nla_nest_start(nl_msg, OVPN_A_KEYCONF);
    NLA_PUT_U32(nl_msg, OVPN_A_KEYCONF_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_A_KEYCONF_SLOT, slot);
    NLA_PUT_U32(nl_msg, OVPN_A_KEYCONF_KEY_ID, keyid);
    NLA_PUT_U32(nl_msg, OVPN_A_KEYCONF_CIPHER_ALG, dco_cipher);

    struct nlattr *key_enc = nla_nest_start(nl_msg,
                                            OVPN_A_KEYCONF_ENCRYPT_DIR);
    if (dco_cipher != OVPN_CIPHER_ALG_NONE)
    {
        NLA_PUT(nl_msg, OVPN_A_KEYDIR_CIPHER_KEY, key_len, encrypt_key);
        NLA_PUT(nl_msg, OVPN_A_KEYDIR_NONCE_TAIL, nonce_tail_len,
                encrypt_iv);
    }
    nla_nest_end(nl_msg, key_enc);

    struct nlattr *key_dec = nla_nest_start(nl_msg,
                                            OVPN_A_KEYCONF_DECRYPT_DIR);
    if (dco_cipher != OVPN_CIPHER_ALG_NONE)
    {
        NLA_PUT(nl_msg, OVPN_A_KEYDIR_CIPHER_KEY, key_len, decrypt_key);
        NLA_PUT(nl_msg, OVPN_A_KEYDIR_NONCE_TAIL, nonce_tail_len,
                decrypt_iv);
    }
    nla_nest_end(nl_msg, key_dec);

    nla_nest_end(nl_msg, key_conf);


    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

int
dco_set_peer(dco_context_t *dco, unsigned int peerid,
             int keepalive_interval, int keepalive_timeout, int mss)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, keepalive %d/%d, mss %d", __func__,
        peerid, keepalive_interval, keepalive_timeout, mss);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_PEER_SET);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_A_PEER);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_A_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_A_PEER_KEEPALIVE_INTERVAL,
                keepalive_interval);
    NLA_PUT_U32(nl_msg, OVPN_A_PEER_KEEPALIVE_TIMEOUT,
                keepalive_timeout);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

/* This function parses the reply provided by the kernel to the CTRL_CMD_GETFAMILY
 * message. We parse the reply and we retrieve the multicast group ID associated
 * with the "ovpn-dco" netlink family.
 *
 * The ID is later used to subscribe to the multicast group and be notified
 * about any multicast message sent by the ovpn-dco kernel module.
 */
static int
mcast_family_handler(struct nl_msg *msg, void *arg)
{
    dco_context_t *dco = arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[CTRL_ATTR_MCAST_GROUPS])
    {
        return NL_SKIP;
    }

    struct nlattr *mcgrp;
    int rem_mcgrp;
    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp)
    {
        struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
                  nla_data(mcgrp), nla_len(mcgrp), NULL);

        if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]
            || !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
        {
            continue;
        }

        if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                    OVPN_MCGRP_PEERS,
                    nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
        {
            continue;
        }
        dco->ovpn_dco_mcast_id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    }

    return NL_SKIP;
}
/**
 * Lookup the multicast id for OpenVPN. This method and its help method currently
 * hardcode the lookup to OVPN_FAMILY_NAME and OVPN_MCGRP_PEERS but
 * extended in the future if we need to lookup more than one mcast id.
 */
static int
ovpn_get_mcast_id(dco_context_t *dco)
{
    dco->ovpn_dco_mcast_id = -ENOENT;

    /* Even though 'nlctrl' is a constant, there seem to be no library
     * provided define for it */
    dco->ctrlid = genl_ctrl_resolve(dco->nl_sock, "nlctrl");

    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    genlmsg_put(nl_msg, 0, 0, dco->ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

    int ret = -EMSGSIZE;
    NLA_PUT_STRING(nl_msg, CTRL_ATTR_FAMILY_NAME, OVPN_FAMILY_NAME);

    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

static bool
ovpn_parse_float_addr(struct nlattr **attrs, struct sockaddr *out)
{
    if (!attrs[OVPN_A_PEER_REMOTE_PORT])
    {
        msg(D_DCO, "ovpn-dco: no remote port in PEER_FLOAT_NTF message");
        return false;
    }

    if (attrs[OVPN_A_PEER_REMOTE_IPV4])
    {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)out;
        CLEAR(*addr4);
        addr4->sin_family = AF_INET;
        addr4->sin_port = nla_get_u16(attrs[OVPN_A_PEER_REMOTE_PORT]);
        addr4->sin_addr.s_addr = nla_get_u32(attrs[OVPN_A_PEER_REMOTE_IPV4]);
        return true;
    }
    else if (attrs[OVPN_A_PEER_REMOTE_IPV6]
             && nla_len(attrs[OVPN_A_PEER_REMOTE_IPV6]) == sizeof(struct in6_addr))
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)out;
        CLEAR(*addr6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = nla_get_u16(attrs[OVPN_A_PEER_REMOTE_PORT]);
        memcpy(&addr6->sin6_addr, nla_data(attrs[OVPN_A_PEER_REMOTE_IPV6]),
               sizeof(addr6->sin6_addr));
        if (attrs[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID])
        {
            addr6->sin6_scope_id = nla_get_u32(attrs[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID]);
        }
        return true;
    }

    msg(D_DCO, "ovpn-dco: no valid remote IP address in PEER_FLOAT_NTF message");
    return false;
}

/* libnl < 3.11.0 does not implement nla_get_uint() */
static uint64_t
ovpn_nla_get_uint(struct nlattr *attr)
{
    if (nla_len(attr) == sizeof(uint32_t))
    {
        return nla_get_u32(attr);
    }
    else
    {
        return nla_get_u64(attr);
    }
}

static void
dco_update_peer_stat(struct context_2 *c2, struct nlattr *tb[], uint32_t id)
{
    if (tb[OVPN_A_PEER_LINK_RX_BYTES])
    {
        c2->dco_read_bytes = ovpn_nla_get_uint(tb[OVPN_A_PEER_LINK_RX_BYTES]);
        msg(D_DCO_DEBUG, "%s / dco_read_bytes: " counter_format, __func__,
            c2->dco_read_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no link RX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_A_PEER_LINK_TX_BYTES])
    {
        c2->dco_write_bytes = ovpn_nla_get_uint(tb[OVPN_A_PEER_LINK_TX_BYTES]);
        msg(D_DCO_DEBUG, "%s / dco_write_bytes: " counter_format, __func__,
            c2->dco_write_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no link TX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_A_PEER_VPN_RX_BYTES])
    {
        c2->tun_read_bytes = ovpn_nla_get_uint(tb[OVPN_A_PEER_VPN_RX_BYTES]);
        msg(D_DCO_DEBUG, "%s / tun_read_bytes: " counter_format, __func__,
            c2->tun_read_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no VPN RX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_A_PEER_VPN_TX_BYTES])
    {
        c2->tun_write_bytes = ovpn_nla_get_uint(tb[OVPN_A_PEER_VPN_TX_BYTES]);
        msg(D_DCO_DEBUG, "%s / tun_write_bytes: " counter_format, __func__,
            c2->tun_write_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no VPN TX bytes provided in reply for peer %u",
            __func__, id);
    }
}

static int
ovpn_handle_peer(dco_context_t *dco, struct nlattr *attrs[])
{
    if (!attrs[OVPN_A_PEER])
    {
        msg(D_DCO_DEBUG, "%s: malformed reply", __func__);
        return NL_SKIP;
    }

    struct nlattr *tb_peer[OVPN_A_PEER_MAX + 1];
    nla_parse_nested(tb_peer, OVPN_A_PEER_MAX, attrs[OVPN_A_PEER], NULL);

    if (!tb_peer[OVPN_A_PEER_ID])
    {
        msg(M_WARN, "ovpn-dco: no peer-id provided in PEER_GET reply");
        return NL_SKIP;
    }

    uint32_t peer_id = nla_get_u32(tb_peer[OVPN_A_PEER_ID]);
    struct context_2 *c2;

    msg(D_DCO_DEBUG, "%s: parsing message for peer %u...", __func__, peer_id);

    if (dco->ifmode == OVPN_MODE_P2P)
    {
        c2 = &dco->c->c2;
        if (c2->tls_multi->dco_peer_id != peer_id)
        {
            return NL_SKIP;
        }
    }
    else
    {
        if (peer_id >= dco->c->multi->max_clients)
        {
            msg(M_WARN, "%s: received out of bound peer_id %u (max=%u)", __func__, peer_id,
                dco->c->multi->max_clients);
            return NL_SKIP;
        }

        struct multi_instance *mi = dco->c->multi->instances[peer_id];
        if (!mi)
        {
            msg(M_WARN, "%s: received data for a non-existing peer %u", __func__, peer_id);
            return NL_SKIP;
        }

        c2 = &mi->context.c2;
    }

    dco_update_peer_stat(c2, tb_peer, peer_id);

    return NL_OK;
}

static bool
ovpn_iface_check(dco_context_t *dco, struct nlattr *attrs[])
{
    /* we must know which interface this message is referring to in order to
     * avoid mixing messages for other instances
     */
    if (!attrs[OVPN_A_IFINDEX])
    {
        msg(D_DCO, "ovpn-dco: Received message without ifindex");
        return false;
    }

    uint32_t ifindex = nla_get_u32(attrs[OVPN_A_IFINDEX]);
    if (ifindex != dco->ifindex)
    {
        msg(D_DCO_DEBUG,
            "ovpn-dco: ignoring message for foreign ifindex %d", ifindex);
        return false;
    }

    return true;
}

static int
ovpn_handle_peer_del_ntf(dco_context_t *dco, struct nlattr *attrs[])
{
    if (!ovpn_iface_check(dco, attrs))
    {
        return NL_STOP;
    }

    if (!attrs[OVPN_A_PEER])
    {
        msg(D_DCO, "ovpn-dco: no peer in PEER_DEL_NTF message");
        return NL_STOP;
    }

    struct nlattr *dp_attrs[OVPN_A_PEER_MAX + 1];
    if (nla_parse_nested(dp_attrs, OVPN_A_PEER_MAX, attrs[OVPN_A_PEER],
                         NULL))
    {
        msg(D_DCO, "ovpn-dco: can't parse peer in PEER_DEL_NTF messsage");
        return NL_STOP;
    }

    if (!dp_attrs[OVPN_A_PEER_DEL_REASON])
    {
        msg(D_DCO, "ovpn-dco: no reason in PEER_DEL_NTF message");
        return NL_STOP;
    }
    if (!dp_attrs[OVPN_A_PEER_ID])
    {
        msg(D_DCO, "ovpn-dco: no peer-id in PEER_DEL_NTF message");
        return NL_STOP;
    }

    int reason = nla_get_u32(dp_attrs[OVPN_A_PEER_DEL_REASON]);
    unsigned int peerid = nla_get_u32(dp_attrs[OVPN_A_PEER_ID]);

    msg(D_DCO_DEBUG, "ovpn-dco: received CMD_PEER_DEL_NTF, ifindex: %d, peer-id %u, reason: %d",
        dco->ifindex, peerid, reason);
    dco->dco_message_peer_id = peerid;
    dco->dco_del_peer_reason = reason;
    dco->dco_message_type = OVPN_CMD_PEER_DEL_NTF;

    return NL_OK;
}

static int
ovpn_handle_peer_float_ntf(dco_context_t *dco, struct nlattr *attrs[])
{
    if (!ovpn_iface_check(dco, attrs))
    {
        return NL_STOP;
    }

    if (!attrs[OVPN_A_PEER])
    {
        msg(D_DCO, "ovpn-dco: no peer in PEER_FLOAT_NTF message");
        return NL_STOP;
    }

    struct nlattr *fp_attrs[OVPN_A_PEER_MAX + 1];
    if (nla_parse_nested(fp_attrs, OVPN_A_PEER_MAX, attrs[OVPN_A_PEER],
                         NULL))
    {
        msg(D_DCO, "ovpn-dco: can't parse peer in PEER_FLOAT_NTF messsage");
        return NL_STOP;
    }

    if (!fp_attrs[OVPN_A_PEER_ID])
    {
        msg(D_DCO, "ovpn-dco: no peer-id in PEER_FLOAT_NTF message");
        return NL_STOP;
    }
    uint32_t peerid = nla_get_u32(fp_attrs[OVPN_A_PEER_ID]);

    if (!ovpn_parse_float_addr(fp_attrs, (struct sockaddr *)&dco->dco_float_peer_ss))
    {
        return NL_STOP;
    }

    struct gc_arena gc = gc_new();
    msg(D_DCO_DEBUG,
        "ovpn-dco: received CMD_PEER_FLOAT_NTF, ifindex: %u, peer-id %u, address: %s",
        dco->ifindex, peerid, print_sockaddr((struct sockaddr *)&dco->dco_float_peer_ss, &gc));
    dco->dco_message_peer_id = (int)peerid;
    dco->dco_message_type = OVPN_CMD_PEER_FLOAT_NTF;

    gc_free(&gc);

    return NL_OK;
}

static int
ovpn_handle_key_swap_ntf(dco_context_t *dco, struct nlattr *attrs[])
{
    if (!ovpn_iface_check(dco, attrs))
    {
        return NL_STOP;
    }

    if (!attrs[OVPN_A_KEYCONF])
    {
        msg(D_DCO, "ovpn-dco: no keyconf in KEY_SWAP_NTF message");
        return NL_STOP;
    }

    struct nlattr *dp_attrs[OVPN_A_KEYCONF_MAX + 1];
    if (nla_parse_nested(dp_attrs, OVPN_A_KEYCONF_MAX,
                         attrs[OVPN_A_KEYCONF], NULL))
    {
        msg(D_DCO, "ovpn-dco: can't parse keyconf in KEY_SWAP_NTF message");
        return NL_STOP;
    }
    if (!dp_attrs[OVPN_A_KEYCONF_PEER_ID])
    {
        msg(D_DCO, "ovpn-dco: no peer-id in KEY_SWAP_NTF message");
        return NL_STOP;
    }
    if (!dp_attrs[OVPN_A_KEYCONF_KEY_ID])
    {
        msg(D_DCO, "ovpn-dco: no key-id in KEY_SWAP_NTF message");
        return NL_STOP;
    }

    int key_id = nla_get_u16(dp_attrs[OVPN_A_KEYCONF_KEY_ID]);
    unsigned int peer_id = nla_get_u32(dp_attrs[OVPN_A_KEYCONF_PEER_ID]);

    msg(D_DCO_DEBUG, "ovpn-dco: received CMD_KEY_SWAP_NTF, ifindex: %d, peer-id %u, key-id: %d",
        dco->ifindex, peer_id, key_id);
    dco->dco_message_peer_id = peer_id;
    dco->dco_message_key_id = key_id;
    dco->dco_message_type = OVPN_CMD_KEY_SWAP_NTF;

    return NL_OK;
}

/* This function parses any netlink message sent by ovpn-dco to userspace */
static int
ovpn_handle_msg(struct nl_msg *msg, void *arg)
{
    dco_context_t *dco = arg;

    struct nlattr *attrs[OVPN_A_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = genlmsg_hdr(nlh);

    msg(D_DCO_DEBUG, "ovpn-dco: received netlink message type=%u cmd=%u flags=%#.4x",
        nlh->nlmsg_type, gnlh->cmd, nlh->nlmsg_flags);

    /* if we get a message from the NLCTRL family, it means
     * this is the reply to the mcast ID resolution request
     * and we parse it accordingly.
     */
    if (nlh->nlmsg_type == dco->ctrlid)
    {
        msg(D_DCO_DEBUG, "ovpn-dco: received CTRLID message");
        return mcast_family_handler(msg, dco);
    }

    if (!genlmsg_valid_hdr(nlh, 0))
    {
        msg(D_DCO, "ovpn-dco: invalid header");
        return NL_STOP;
    }

    if (nla_parse(attrs, OVPN_A_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL))
    {
        msg(D_DCO, "received bogus data from ovpn-dco");
        return NL_STOP;
    }

    /* based on the message type, we parse the subobject contained in the
     * message, that stores the type-specific attributes.
     *
     * the "dco" object is then filled accordingly with the information
     * retrieved from the message, so that the rest of the OpenVPN code can
     * react as need be.
     */
    switch (gnlh->cmd)
    {
        case OVPN_CMD_PEER_GET:
        {
            return ovpn_handle_peer(dco, attrs);
        }

        case OVPN_CMD_PEER_DEL_NTF:
        {
            return ovpn_handle_peer_del_ntf(dco, attrs);
        }

        case OVPN_CMD_PEER_FLOAT_NTF:
        {
            return ovpn_handle_peer_float_ntf(dco, attrs);
        }

        case OVPN_CMD_KEY_SWAP_NTF:
        {
            return ovpn_handle_key_swap_ntf(dco, attrs);
        }

        default:
            msg(D_DCO, "ovpn-dco: received unknown command: %d", gnlh->cmd);
            dco->dco_message_type = 0;
            return NL_STOP;
    }

    return NL_OK;
}

int
dco_do_read(dco_context_t *dco)
{
    msg(D_DCO_DEBUG, __func__);

    return ovpn_nl_recvmsgs(dco, __func__);
}

static int
dco_get_peer(dco_context_t *dco, int peer_id, const bool raise_sigusr1_on_err)
{
    /* peer_id == -1 means "dump all peers", but this is allowed in MP mode only.
     * If it happens in P2P mode it means that the DCO peer was deleted and we
     * can simply bail out
     */
    if (peer_id == -1 && dco->ifmode == OVPN_MODE_P2P)
    {
        return 0;
    }

    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peer_id);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_PEER_GET);
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_A_PEER);
    int ret = -EMSGSIZE;

    if (peer_id != -1)
    {
        NLA_PUT_U32(nl_msg, OVPN_A_PEER_ID, peer_id);
    }
    else
    {
        nlmsg_hdr(nl_msg)->nlmsg_flags |= NLM_F_DUMP;
    }
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);

    if (raise_sigusr1_on_err && ret < 0)
    {
        msg(M_WARN, "Error retrieving DCO peer stats: the underlying DCO peer"
            "may have been deleted from the kernel without notifying "
            "userspace. Restarting the session");
        register_signal(dco->c->sig, SIGUSR1, "dco peer stats error");
    }
    return ret;
}

int
dco_get_peer_stats(struct context *c, const bool raise_sigusr1_on_err)
{
    return dco_get_peer(&c->c1.tuntap->dco, c->c2.tls_multi->dco_peer_id, raise_sigusr1_on_err);
}

int
dco_get_peer_stats_multi(dco_context_t *dco, const bool raise_sigusr1_on_err)
{
    return dco_get_peer(dco, -1, raise_sigusr1_on_err);
}

bool
dco_available(int msglevel)
{
    if (resolve_ovpn_netlink_id(D_DCO_DEBUG) < 0)
    {
        msg(msglevel,
            "Note: Kernel support for ovpn-dco missing, disabling data channel offload.");
        return false;
    }

    return true;
}

/**
 * There's no version indicator in the ovpn in-tree module, so we return a
 * string containing info about the kernel version and release.
 */
static const char *
dco_version_string_in_tree(struct gc_arena *gc)
{
    struct buffer buf = alloc_buf_gc(256, gc);
    struct utsname system;

    if (uname(&system))
    {
        return "ERR";
    }

    buf_puts(&buf, system.release);
    buf_puts(&buf, " ");
    buf_puts(&buf, system.version);
    return BSTR(&buf);
}

/**
 * When the module is loaded, the backports version of ovpn has a version file
 * in sysfs. Read it and return the string.
 *
 * The caller is responsible for closing the file pointer.
 */
static const char *
dco_version_string_backports(FILE *fp, struct gc_arena *gc)
{
    char *str = gc_malloc(PATH_MAX, false, gc);

    if (!fgets(str, PATH_MAX, fp))
    {
        return "ERR";
    }

    /* remove potential newline at the end of the string */
    char *nl = strchr(str, '\n');
    if (nl)
    {
        *nl = '\0';
    }

    return str;
}

const char *
dco_version_string(struct gc_arena *gc)
{
    const char *version;
    struct stat sb;
    FILE *fp;

    if (stat("/sys/module/ovpn", &sb) != 0 || !S_ISDIR(sb.st_mode))
    {
        return "N/A";
    }

    /* now that we know for sure that the module is loaded, if there's no
     * version file it means we're dealing with the in-tree version, otherwise
     * it's backports */
    fp = fopen("/sys/module/ovpn/version", "r");
    if (!fp)
    {
        return dco_version_string_in_tree(gc);
    }
    version = dco_version_string_backports(fp, gc);

    fclose(fp);
    return version;
}

void
dco_event_set(dco_context_t *dco, struct event_set *es, void *arg)
{
    if (dco && dco->nl_sock)
    {
        event_ctl(es, nl_socket_get_fd(dco->nl_sock), EVENT_READ, arg);
    }
}

const char *
dco_get_supported_ciphers(void)
{
    return "AES-128-GCM:AES-256-GCM:AES-192-GCM:CHACHA20-POLY1305";
}

#endif /* defined(ENABLE_DCO) && defined(TARGET_LINUX) */
