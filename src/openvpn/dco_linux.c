/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020-2023 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2020-2023 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2023 OpenVPN Inc <sales@openvpn.net>
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

    ret = genl_connect(nl_sock);
    if (ret)
    {
        msg(msglevel, "Cannot connect to generic netlink: %s",
            nl_geterror(ret));
        goto err_sock;
    }
    set_cloexec(nl_socket_get_fd(nl_sock));

    ret = genl_ctrl_resolve(nl_sock, OVPN_NL_NAME);
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
ovpn_dco_nlmsg_create(dco_context_t *dco, enum ovpn_nl_commands cmd)
{
    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
    {
        msg(M_ERR, "cannot allocate netlink message");
        return NULL;
    }

    genlmsg_put(nl_msg, 0, 0, dco->ovpn_dco_id, 0, 0, cmd, 0);
    NLA_PUT_U32(nl_msg, OVPN_ATTR_IFINDEX, dco->ifindex);

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
            msg(M_ERR, "%s: netlink out of memory error", prefix);
            break;

        case -M_ERR:
            msg(M_WARN, "%s: netlink reports blocking read - aborting wait", prefix);
            break;

        case -NLE_NODEV:
            msg(M_ERR, "%s: netlink reports device not found:", prefix);
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
 * Send a prepared netlink message and registers cb as callback if non-null.
 *
 * The method will also free nl_msg
 * @param dco       The dco context to use
 * @param nl_msg    the message to use
 * @param cb        An optional callback if the caller expects an answer
 * @param cb_arg    An optional param to pass to the callback
 * @param prefix    A prefix to report in the error message to give the user context
 * @return          status of sending the message
 */
static int
ovpn_nl_msg_send(dco_context_t *dco, struct nl_msg *nl_msg, ovpn_nl_cb cb,
                 void *cb_arg, const char *prefix)
{
    dco->status = 1;

    nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, cb_arg);
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
             struct in_addr *remote_in4, struct in6_addr *remote_in6)
{
    struct gc_arena gc = gc_new();
    const char *remotestr = "[undefined]";
    if (remoteaddr)
    {
        remotestr = print_sockaddr(remoteaddr, &gc);
    }
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d, remote addr: %s", __func__,
        peerid, sd, remotestr);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_NEW_PEER);
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_NEW_PEER);
    int ret = -EMSGSIZE;

    NLA_PUT_U32(nl_msg, OVPN_NEW_PEER_ATTR_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_NEW_PEER_ATTR_SOCKET, sd);

    /* Set the remote endpoint if defined (for UDP) */
    if (remoteaddr)
    {
        remoteaddr = mapped_v4_to_v6(remoteaddr, &gc);
        int alen = af_addr_size(remoteaddr->sa_family);

        NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, alen, remoteaddr);
    }

    if (localaddr)
    {
        localaddr = mapped_v4_to_v6(localaddr, &gc);
        if (localaddr->sa_family == AF_INET)
        {
            NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_LOCAL_IP, sizeof(struct in_addr),
                    &((struct sockaddr_in *)localaddr)->sin_addr);
        }
        else if (localaddr->sa_family == AF_INET6)
        {
            NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_LOCAL_IP, sizeof(struct in6_addr),
                    &((struct sockaddr_in6 *)localaddr)->sin6_addr);
        }
    }

    /* Set the primary VPN IP addresses of the peer */
    if (remote_in4)
    {
        NLA_PUT_U32(nl_msg, OVPN_NEW_PEER_ATTR_IPV4, remote_in4->s_addr);
    }
    if (remote_in6)
    {
        NLA_PUT(nl_msg, OVPN_NEW_PEER_ATTR_IPV6, sizeof(struct in6_addr),
                remote_in6);
    }
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

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
    struct nlattr *tb_msg[NLMSGERR_ATTR_MAX + 1];
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

    nla_parse(tb_msg, NLMSGERR_ATTR_MAX, attrs, len, NULL);
    if (tb_msg[NLMSGERR_ATTR_MSG])
    {
        len = strnlen((char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]),
                      nla_len(tb_msg[NLMSGERR_ATTR_MSG]));
        msg(M_WARN, "kernel error: %*s\n", len,
            (char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]));
    }

    return NL_STOP;
}

static void
ovpn_dco_init_netlink(dco_context_t *dco)
{
    dco->ovpn_dco_id = resolve_ovpn_netlink_id(M_ERR);

    dco->nl_sock = nl_socket_alloc();

    if (!dco->nl_sock)
    {
        msg(M_ERR, "Cannot create netlink socket");
    }

    int ret = genl_connect(dco->nl_sock);
    if (ret)
    {
        msg(M_ERR, "Cannot connect to generic netlink: %s",
            nl_geterror(ret));
    }

    /* set close on exec and non-block on the netlink socket */
    set_cloexec(nl_socket_get_fd(dco->nl_sock));
    set_nonblock(nl_socket_get_fd(dco->nl_sock));

    dco->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!dco->nl_cb)
    {
        msg(M_ERR, "failed to allocate netlink callback");
    }

    nl_socket_set_cb(dco->nl_sock, dco->nl_cb);

    nl_cb_err(dco->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);

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
ovpn_dco_init(int mode, dco_context_t *dco)
{
    switch (mode)
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

static void
ovpn_dco_register(dco_context_t *dco)
{
    msg(D_DCO_DEBUG, __func__);
    ovpn_get_mcast_id(dco);

    if (dco->ovpn_dco_mcast_id < 0)
    {
        msg(M_ERR, "cannot get mcast group: %s",  nl_geterror(dco->ovpn_dco_mcast_id));
    }

    /* Register for ovpn-dco specific multicast messages that the kernel may
     * send
     */
    int ret = nl_socket_add_membership(dco->nl_sock, dco->ovpn_dco_mcast_id);
    if (ret)
    {
        msg(M_ERR, "%s: failed to join groups: %d", __func__, ret);
    }
}

int
open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev)
{
    msg(D_DCO_DEBUG, "%s: %s", __func__, dev);
    ASSERT(tt->type == DEV_TYPE_TUN);

    int ret = net_iface_new(ctx, dev, "ovpn-dco", &tt->dco);
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

    tt->dco.dco_message_peer_id = -1;

    ovpn_dco_register(&tt->dco);

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

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_SWAP_KEYS);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_SWAP_KEYS);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_SWAP_KEYS_ATTR_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}


int
dco_del_peer(dco_context_t *dco, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_DEL_PEER);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_DEL_PEER);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_DEL_PEER_ATTR_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}


int
dco_del_key(dco_context_t *dco, unsigned int peerid,
            dco_key_slot_t slot)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, slot %d", __func__, peerid, slot);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_DEL_KEY);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_DEL_KEY);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_DEL_KEY_ATTR_PEER_ID, peerid);
    NLA_PUT_U8(nl_msg, OVPN_DEL_KEY_ATTR_KEY_SLOT, slot);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

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

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_NEW_KEY);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    dco_cipher_t dco_cipher = dco_get_cipher(ciphername);

    int ret = -EMSGSIZE;
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_NEW_KEY);
    NLA_PUT_U32(nl_msg, OVPN_NEW_KEY_ATTR_PEER_ID, peerid);
    NLA_PUT_U8(nl_msg, OVPN_NEW_KEY_ATTR_KEY_SLOT, slot);
    NLA_PUT_U8(nl_msg, OVPN_NEW_KEY_ATTR_KEY_ID, keyid);
    NLA_PUT_U16(nl_msg, OVPN_NEW_KEY_ATTR_CIPHER_ALG, dco_cipher);

    struct nlattr *key_enc = nla_nest_start(nl_msg,
                                            OVPN_NEW_KEY_ATTR_ENCRYPT_KEY);
    if (dco_cipher != OVPN_CIPHER_ALG_NONE)
    {
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, key_len, encrypt_key);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, nonce_tail_len,
                encrypt_iv);
    }
    nla_nest_end(nl_msg, key_enc);

    struct nlattr *key_dec = nla_nest_start(nl_msg,
                                            OVPN_NEW_KEY_ATTR_DECRYPT_KEY);
    if (dco_cipher != OVPN_CIPHER_ALG_NONE)
    {
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, key_len, decrypt_key);
        NLA_PUT(nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, nonce_tail_len,
                decrypt_iv);
    }
    nla_nest_end(nl_msg, key_dec);

    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

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

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_SET_PEER);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_SET_PEER);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_SET_PEER_ATTR_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_SET_PEER_ATTR_KEEPALIVE_INTERVAL,
                keepalive_interval);
    NLA_PUT_U32(nl_msg, OVPN_SET_PEER_ATTR_KEEPALIVE_TIMEOUT,
                keepalive_timeout);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

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
                    OVPN_NL_MULTICAST_GROUP_PEERS,
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
 * hardcode the lookup to OVPN_NL_NAME and OVPN_NL_MULTICAST_GROUP_PEERS but
 * extended in the future if we need to lookup more than one mcast id.
 */
static int
ovpn_get_mcast_id(dco_context_t *dco)
{
    dco->ovpn_dco_mcast_id = -ENOENT;

    /* Even though 'nlctrl' is a constant, there seem to be no library
     * provided define for it */
    int ctrlid = genl_ctrl_resolve(dco->nl_sock, "nlctrl");

    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    genlmsg_put(nl_msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

    int ret = -EMSGSIZE;
    NLA_PUT_STRING(nl_msg, CTRL_ATTR_FAMILY_NAME, OVPN_NL_NAME);

    ret = ovpn_nl_msg_send(dco, nl_msg, mcast_family_handler, dco, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

/* This function parses any netlink message sent by ovpn-dco to userspace */
static int
ovpn_handle_msg(struct nl_msg *msg, void *arg)
{
    dco_context_t *dco = arg;

    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[OVPN_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(msg);

    if (!genlmsg_valid_hdr(nlh, 0))
    {
        msg(D_DCO, "ovpn-dco: invalid header");
        return NL_SKIP;
    }

    if (nla_parse(attrs, OVPN_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL))
    {
        msg(D_DCO, "received bogus data from ovpn-dco");
        return NL_SKIP;
    }

    /* we must know which interface this message is referring to in order to
     * avoid mixing messages for other instances
     */
    if (!attrs[OVPN_ATTR_IFINDEX])
    {
        msg(D_DCO, "ovpn-dco: Received message without ifindex");
        return NL_SKIP;
    }

    uint32_t ifindex = nla_get_u32(attrs[OVPN_ATTR_IFINDEX]);
    if (ifindex != dco->ifindex)
    {
        msg(D_DCO_DEBUG,
            "ovpn-dco: ignoring message (type=%d) for foreign ifindex %d",
            gnlh->cmd, ifindex);
        return NL_SKIP;
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
        case OVPN_CMD_DEL_PEER:
        {
            if (!attrs[OVPN_ATTR_DEL_PEER])
            {
                msg(D_DCO, "ovpn-dco: no attributes in OVPN_DEL_PEER message");
                return NL_SKIP;
            }

            struct nlattr *dp_attrs[OVPN_DEL_PEER_ATTR_MAX + 1];
            if (nla_parse_nested(dp_attrs, OVPN_DEL_PEER_ATTR_MAX,
                                 attrs[OVPN_ATTR_DEL_PEER], NULL))
            {
                msg(D_DCO, "received bogus del peer packet data from ovpn-dco");
                return NL_SKIP;
            }

            if (!dp_attrs[OVPN_DEL_PEER_ATTR_REASON])
            {
                msg(D_DCO, "ovpn-dco: no reason in DEL_PEER message");
                return NL_SKIP;
            }
            if (!dp_attrs[OVPN_DEL_PEER_ATTR_PEER_ID])
            {
                msg(D_DCO, "ovpn-dco: no peer-id in DEL_PEER message");
                return NL_SKIP;
            }
            int reason = nla_get_u8(dp_attrs[OVPN_DEL_PEER_ATTR_REASON]);
            unsigned int peerid = nla_get_u32(dp_attrs[OVPN_DEL_PEER_ATTR_PEER_ID]);

            msg(D_DCO_DEBUG, "ovpn-dco: received CMD_DEL_PEER, ifindex: %d, peer-id %d, reason: %d",
                ifindex, peerid, reason);
            dco->dco_message_peer_id = peerid;
            dco->dco_del_peer_reason = reason;
            dco->dco_message_type = OVPN_CMD_DEL_PEER;

            break;
        }

        default:
            msg(D_DCO, "ovpn-dco: received unknown command: %d", gnlh->cmd);
            dco->dco_message_type = 0;
            return NL_SKIP;
    }

    return NL_OK;
}

int
dco_do_read(dco_context_t *dco)
{
    msg(D_DCO_DEBUG, __func__);
    nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, ovpn_handle_msg, dco);

    return ovpn_nl_recvmsgs(dco, __func__);
}

static void
dco_update_peer_stat(struct context_2 *c2, struct nlattr *tb[], uint32_t id)
{
    if (tb[OVPN_GET_PEER_RESP_ATTR_LINK_RX_BYTES])
    {
        c2->dco_read_bytes = nla_get_u64(tb[OVPN_GET_PEER_RESP_ATTR_LINK_RX_BYTES]);
        msg(D_DCO_DEBUG, "%s / dco_read_bytes: " counter_format, __func__,
            c2->dco_read_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no link RX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_GET_PEER_RESP_ATTR_LINK_TX_BYTES])
    {
        c2->dco_write_bytes = nla_get_u64(tb[OVPN_GET_PEER_RESP_ATTR_LINK_TX_BYTES]);
        msg(D_DCO_DEBUG, "%s / dco_write_bytes: " counter_format, __func__,
            c2->dco_write_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no link TX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_GET_PEER_RESP_ATTR_VPN_RX_BYTES])
    {
        c2->tun_read_bytes = nla_get_u64(tb[OVPN_GET_PEER_RESP_ATTR_VPN_RX_BYTES]);
        msg(D_DCO_DEBUG, "%s / tun_read_bytes: " counter_format, __func__,
            c2->tun_read_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no VPN RX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_GET_PEER_RESP_ATTR_VPN_TX_BYTES])
    {
        c2->tun_write_bytes = nla_get_u64(tb[OVPN_GET_PEER_RESP_ATTR_VPN_TX_BYTES]);
        msg(D_DCO_DEBUG, "%s / tun_write_bytes: " counter_format, __func__,
            c2->tun_write_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no VPN TX bytes provided in reply for peer %u",
            __func__, id);
    }
}

int
dco_parse_peer_multi(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[OVPN_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    msg(D_DCO_DEBUG, "%s: parsing message...", __func__);

    nla_parse(tb, OVPN_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[OVPN_ATTR_GET_PEER])
    {
        return NL_SKIP;
    }

    struct nlattr *tb_peer[OVPN_GET_PEER_RESP_ATTR_MAX + 1];

    nla_parse(tb_peer, OVPN_GET_PEER_RESP_ATTR_MAX,
              nla_data(tb[OVPN_ATTR_GET_PEER]),
              nla_len(tb[OVPN_ATTR_GET_PEER]), NULL);

    if (!tb_peer[OVPN_GET_PEER_RESP_ATTR_PEER_ID])
    {
        msg(M_WARN, "%s: no peer-id provided in reply", __func__);
        return NL_SKIP;
    }

    struct multi_context *m = arg;
    uint32_t peer_id = nla_get_u32(tb_peer[OVPN_GET_PEER_RESP_ATTR_PEER_ID]);

    if (peer_id >= m->max_clients || !m->instances[peer_id])
    {
        msg(M_WARN, "%s: cannot store DCO stats for peer %u", __func__,
            peer_id);
        return NL_SKIP;
    }

    dco_update_peer_stat(&m->instances[peer_id]->context.c2, tb_peer, peer_id);

    return NL_OK;
}

int
dco_get_peer_stats_multi(dco_context_t *dco, struct multi_context *m)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_GET_PEER);

    nlmsg_hdr(nl_msg)->nlmsg_flags |= NLM_F_DUMP;

    int ret = ovpn_nl_msg_send(dco, nl_msg, dco_parse_peer_multi, m, __func__);

    nlmsg_free(nl_msg);
    return ret;
}

static int
dco_parse_peer(struct nl_msg *msg, void *arg)
{
    struct context *c = arg;
    struct nlattr *tb[OVPN_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    msg(D_DCO_DEBUG, "%s: parsing message...", __func__);

    nla_parse(tb, OVPN_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[OVPN_ATTR_GET_PEER])
    {
        msg(D_DCO_DEBUG, "%s: malformed reply", __func__);
        return NL_SKIP;
    }

    struct nlattr *tb_peer[OVPN_GET_PEER_RESP_ATTR_MAX + 1];

    nla_parse(tb_peer, OVPN_GET_PEER_RESP_ATTR_MAX,
              nla_data(tb[OVPN_ATTR_GET_PEER]),
              nla_len(tb[OVPN_ATTR_GET_PEER]), NULL);

    if (!tb_peer[OVPN_GET_PEER_RESP_ATTR_PEER_ID])
    {
        msg(M_WARN, "%s: no peer-id provided in reply", __func__);
        return NL_SKIP;
    }

    uint32_t peer_id = nla_get_u32(tb_peer[OVPN_GET_PEER_RESP_ATTR_PEER_ID]);
    if (c->c2.tls_multi->dco_peer_id != peer_id)
    {
        return NL_SKIP;
    }

    dco_update_peer_stat(&c->c2, tb_peer, peer_id);

    return NL_OK;
}

int
dco_get_peer_stats(struct context *c)
{
    uint32_t peer_id = c->c2.tls_multi->dco_peer_id;
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peer_id);

    if (!c->c1.tuntap)
    {
        return 0;
    }

    dco_context_t *dco = &c->c1.tuntap->dco;
    struct nl_msg *nl_msg = ovpn_dco_nlmsg_create(dco, OVPN_CMD_GET_PEER);
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_ATTR_GET_PEER);
    int ret = -EMSGSIZE;

    NLA_PUT_U32(nl_msg, OVPN_GET_PEER_ATTR_PEER_ID, peer_id);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, dco_parse_peer, c, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
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

const char *
dco_version_string(struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    FILE *fp = fopen("/sys/module/ovpn_dco_v2/version", "r");
    if (!fp)
    {
        return "N/A";
    }

    if (!fgets(BSTR(&out), BCAP(&out), fp))
    {
        fclose(fp);
        return "ERR";
    }

    /* remove potential newline at the end of the string */
    char *str = BSTR(&out);
    char *nl = strchr(str, '\n');
    if (nl)
    {
        *nl = '\0';
    }

    fclose(fp);
    return BSTR(&out);
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
dco_get_supported_ciphers()
{
    return "AES-128-GCM:AES-256-GCM:AES-192-GCM:CHACHA20-POLY1305";
}

#endif /* defined(ENABLE_DCO) && defined(TARGET_LINUX) */
