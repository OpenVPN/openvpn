/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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

/**
 * @file SSL control channel wrap/unwrap and decode functions. This file
 *        (and its .c file) is designed to to be included in units/etc without
 *        pulling in a lot of dependencies
 */

#ifndef SSL_PKT_H
#define SSL_PKT_H

#include "buffer.h"
#include "ssl_backend.h"
#include "ssl_common.h"

/* packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte */
#define P_KEY_ID_MASK                  0x07
#define P_OPCODE_SHIFT                 3

/* packet opcodes -- the V1 is intended to allow protocol changes in the future */
#define P_CONTROL_HARD_RESET_CLIENT_V1 1     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V1 2     /* initial key from server, forget previous state */
#define P_CONTROL_SOFT_RESET_V1        3     /* new key, graceful transition from old to new key */
#define P_CONTROL_V1                   4     /* control channel packet (usually TLS ciphertext) */
#define P_ACK_V1                       5     /* acknowledgement for packets received */
#define P_DATA_V1                      6     /* data channel packet */
#define P_DATA_V2                      9     /* data channel packet with peer-id */

/* indicates key_method >= 2 */
#define P_CONTROL_HARD_RESET_CLIENT_V2 7     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V2 8     /* initial key from server, forget previous state */

/* indicates key_method >= 2 and client-specific tls-crypt key */
#define P_CONTROL_HARD_RESET_CLIENT_V3 10    /* initial key from client, forget previous state */

/* Variant of P_CONTROL_V1 but with appended wrapped key
 * like P_CONTROL_HARD_RESET_CLIENT_V3 */
#define P_CONTROL_WKC_V1               11

/* define the range of legal opcodes
 * Since we do no longer support key-method 1 we consider
 * the v1 op codes invalid */
#define P_FIRST_OPCODE                 3
#define P_LAST_OPCODE                  11

/*
 * Define number of buffers for send and receive in the reliability layer.
 */
#define TLS_RELIABLE_N_SEND_BUFFERS  6 /* also window size for reliability layer */
#define TLS_RELIABLE_N_REC_BUFFERS   12

/*
 * Used in --mode server mode to check tls-auth signature on initial
 * packets received from new clients.
 */
struct tls_auth_standalone
{
    struct tls_wrap_ctx tls_wrap;
    struct buffer workbuf;
    struct frame frame;
};

enum first_packet_verdict {
    /** This packet is a valid reset packet from the peer (all but tls-crypt-v2) */
    VERDICT_VALID_RESET_V2,
    /** This is a valid v3 reset (tls-crypt-v2) */
    VERDICT_VALID_RESET_V3,
    /** This packet is a valid control packet from the peer */
    VERDICT_VALID_CONTROL_V1,
    /** This packet is a valid ACK control packet from the peer,
     * i.e. it has a valid session id hmac in it */
    VERDICT_VALID_ACK_V1,
    /** The packet is a valid control packet with appended wrapped client key */
    VERDICT_VALID_WKC_V1,
    /** the packet failed on of the various checks */
    VERDICT_INVALID
};

/**
 * struct that stores the temporary data for the tls lite decrypt
 * functions
 */
struct tls_pre_decrypt_state {
    struct tls_wrap_ctx tls_wrap_tmp;
    struct buffer newbuf;
    struct session_id peer_session_id;
    struct session_id server_session_id;
};

/**
 *
 * @param state
 */
void free_tls_pre_decrypt_state(struct tls_pre_decrypt_state *state);

/**
 * Inspect an incoming packet for which no VPN tunnel is active, and
 * determine whether a new VPN tunnel should be created.
 * @ingroup data_crypto
 *
 * This function receives the initial incoming packet from a client that
 * wishes to establish a new VPN tunnel, and determines the packet is a
 * valid initial packet.  It is only used when OpenVPN is running in
 * server mode.
 *
 * The tests performed by this function are whether the packet's opcode is
 * correct for establishing a new VPN tunnel, whether its key ID is 0, and
 * whether its size is not too large.  This function also performs the
 * initial HMAC firewall test, if configured to do so.
 *
 * The incoming packet and the local VPN tunnel state are not modified by
 * this function.  Its sole purpose is to inspect the packet and determine
 * whether a new VPN tunnel should be created.  If so, that new VPN tunnel
 * instance will handle processing of the packet.
 *
 * This function is only used in the UDP p2mp server code path
 *
 * @param tas - The standalone TLS authentication setting structure for
 *     this process.
 * @param from - The source address of the packet.
 * @param buf - A buffer structure containing the incoming packet.
 *
 * @return
 * @li True if the packet is valid and a new VPN tunnel should be created
 *     for this client.
 * @li False if the packet is not valid, did not pass the HMAC firewall
 *     test, or some other error occurred.
 */
enum first_packet_verdict
tls_pre_decrypt_lite(const struct tls_auth_standalone *tas,
                     struct tls_pre_decrypt_state *state,
                     const struct link_socket_actual *from,
                     const struct buffer *buf);

/* Creates an SHA256 HMAC context with a random key that is used for the
 * session id.
 *
 * We do not support loading this from a config file since continuing session
 * between restarts of OpenVPN has never been supported and that includes
 * early session setup.
 */
hmac_ctx_t *session_id_hmac_init(void);

/**
 * Calculates the HMAC based server session id based on a client session id
 * and socket addr.
 *
 * @param client_sid    session id of the client
 * @param from          link_socket from the client
 * @param hmac          the hmac context to use for the calculation
 * @param handwindow    the quantisation of the current time
 * @param offset        offset to 'now' to use
 * @return              the expected server session id
 */
struct session_id
calculate_session_id_hmac(struct session_id client_sid,
                          const struct openvpn_sockaddr *from,
                          hmac_ctx_t *hmac,
                          int handwindow, int offset);

/**
 * Checks if a control packet has a correct HMAC server session id
 *
 * @param client_sid    session id of the client
 * @param from          link_socket from the client
 * @param hmac          the hmac context to use for the calculation
 * @param handwindow    the quantisation of the current time
 * @return              the expected server session id
 */
bool
check_session_id_hmac(struct tls_pre_decrypt_state *state,
                      const struct openvpn_sockaddr *from,
                      hmac_ctx_t *hmac,
                      int handwindow);

/*
 * Write a control channel authentication record.
 */
void
write_control_auth(struct tls_session *session,
                   struct key_state *ks,
                   struct buffer *buf,
                   struct link_socket_actual **to_link_addr,
                   int opcode,
                   int max_ack,
                   bool prepend_ack);


/*
 * Read a control channel authentication record.
 */
bool
read_control_auth(struct buffer *buf,
                  struct tls_wrap_ctx *ctx,
                  const struct link_socket_actual *from,
                  const struct tls_options *opt);


/**
 * This function creates a reset packet using the information
 * from the tls pre decrypt state.
 *
 */
struct buffer
tls_reset_standalone(struct tls_wrap_ctx *ctx,
                     struct tls_auth_standalone *tas,
                     struct session_id *own_sid,
                     struct session_id *remote_sid,
                     uint8_t header,
                     bool request_resend_wkc);

static inline const char *
packet_opcode_name(int op)
{
    switch (op)
    {
        case P_CONTROL_HARD_RESET_CLIENT_V1:
            return "P_CONTROL_HARD_RESET_CLIENT_V1";

        case P_CONTROL_HARD_RESET_SERVER_V1:
            return "P_CONTROL_HARD_RESET_SERVER_V1";

        case P_CONTROL_HARD_RESET_CLIENT_V2:
            return "P_CONTROL_HARD_RESET_CLIENT_V2";

        case P_CONTROL_HARD_RESET_SERVER_V2:
            return "P_CONTROL_HARD_RESET_SERVER_V2";

        case P_CONTROL_HARD_RESET_CLIENT_V3:
            return "P_CONTROL_HARD_RESET_CLIENT_V3";

        case P_CONTROL_SOFT_RESET_V1:
            return "P_CONTROL_SOFT_RESET_V1";

        case P_CONTROL_V1:
            return "P_CONTROL_V1";

        case P_CONTROL_WKC_V1:
            return "P_CONTROL_WKC_V1";

        case P_ACK_V1:
            return "P_ACK_V1";

        case P_DATA_V1:
            return "P_DATA_V1";

        case P_DATA_V2:
            return "P_DATA_V2";

        default:
            return "P_???";
    }
}

/**
 * Determines if the current session should use the renegotiation tls wrap
 * struct instead the normal one and returns it.
 *
 * @param session
 * @param key_id    key_id of the received/or to be send packet
 * @return
 */
static inline struct tls_wrap_ctx *
tls_session_get_tls_wrap(struct tls_session *session, int key_id)
{
    /* OpenVPN has the hardcoded assumption in its protocol that
     * key-id 0 is always first session and renegotiations use key-id
     * 1 to 7 and wrap around to 1 after that. So key-id > 0 is equivalent
     * to "this is a renegotiation"
     */
    if (key_id > 0 && session->tls_wrap_reneg.mode == TLS_WRAP_CRYPT)
    {
        return &session->tls_wrap_reneg;
    }
    else
    {
        return &session->tls_wrap;
    }
}

/* initial packet id (instead of 0) that indicates that the peer supports
 * early protocol negotiation. This will make the packet id turn a bit faster
 * but the network time part of the packet id takes care of that. And
 * this is also a rather theoretical scenario as it still needs more than
 * 2^31 control channel packets to happen */
#define EARLY_NEG_MASK          0xff000000
#define EARLY_NEG_START         0x0f000000


/* Early negotiation that part of the server response in the RESET_V2 packet.
 * Since clients that announce early negotiation support will treat the payload
 * of reset packets special and parse it as TLV messages.
 * as TLV (type, length, value) */
#define TLV_TYPE_EARLY_NEG_FLAGS        0x0001
#define EARLY_NEG_FLAG_RESEND_WKC       0x0001
#endif /* ifndef SSL_PKT_H */
