/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
 * @file Control Channel SSL/Data channel negotiation module
 */

#ifndef OPENVPN_SSL_H
#define OPENVPN_SSL_H

#include "basic.h"
#include "common.h"
#include "crypto.h"
#include "packet_id.h"
#include "session_id.h"
#include "reliable.h"
#include "socket.h"
#include "mtu.h"
#include "options.h"
#include "plugin.h"

#include "ssl_common.h"
#include "ssl_backend.h"

/* Used in the TLS PRF function */
#define KEY_EXPANSION_ID "OpenVPN"

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

/* define the range of legal opcodes
 * Since we do no longer support key-method 1 we consider
 * the v1 op codes invalid */
#define P_FIRST_OPCODE                 3
#define P_LAST_OPCODE                  10

/*
 * Set the max number of acknowledgments that can "hitch a ride" on an outgoing
 * non-P_ACK_V1 control packet.
 */
#define CONTROL_SEND_ACK_MAX 4

/*
 * Define number of buffers for send and receive in the reliability layer.
 */
#define TLS_RELIABLE_N_SEND_BUFFERS  4 /* also window size for reliability layer */
#define TLS_RELIABLE_N_REC_BUFFERS   8

/*
 * Various timeouts
 */
#define TLS_MULTI_REFRESH 15    /* call tls_multi_process once every n seconds */
#define TLS_MULTI_HORIZON 2     /* call tls_multi_process frequently for n seconds after
                                 * every packet sent/received action */

/* Interval that tls_multi_process should call tls_authentication_status */
#define TLS_MULTI_AUTH_STATUS_INTERVAL 10

/*
 * Buffer sizes (also see mtu.h).
 */

/* Maximum length of OCC options string passed as part of auth handshake */
#define TLS_OPTIONS_LEN 512

/* Definitions of the bits in the IV_PROTO bitfield
 *
 * In older OpenVPN versions this used in a comparison
 * IV_PROTO >= 2 to determine if DATA_V2 is supported.
 * Therefore any client announcing any of the flags must
 * also announce IV_PROTO_DATA_V2. We also treat bit 0
 * as reserved for this reason */

/** Support P_DATA_V2 */
#define IV_PROTO_DATA_V2        (1<<1)

/** Assume client will send a push request and server does not need
 * to wait for a push-request to send a push-reply */
#define IV_PROTO_REQUEST_PUSH   (1<<2)


/* Default field in X509 to be username */
#define X509_USERNAME_FIELD_DEFAULT "CN"

#define KEY_METHOD_2  2

/* key method taken from lower 4 bits */
#define KEY_METHOD_MASK 0x0F

/*
 * Measure success rate of TLS handshakes, for debugging only
 */
/* #define MEASURE_TLS_HANDSHAKE_STATS */

/*
 * Used in --mode server mode to check tls-auth signature on initial
 * packets received from new clients.
 */
struct tls_auth_standalone
{
    struct tls_wrap_ctx tls_wrap;
    struct frame frame;
};

/*
 * Prepare the SSL library for use
 */
void init_ssl_lib(void);

/*
 * Free any internal state that the SSL library might have
 */
void free_ssl_lib(void);

/**
 * Build master SSL context object that serves for the whole of OpenVPN
 * instantiation
 */
void init_ssl(const struct options *options, struct tls_root_ctx *ctx, bool in_chroot);

/** @addtogroup control_processor
 *  @{ */

/** @name Functions for initialization and cleanup of tls_multi structures
 *  @{ */

/**
 * Allocate and initialize a \c tls_multi structure.
 * @ingroup control_processor
 *
 * This function allocates a new \c tls_multi structure, and performs some
 * amount of initialization.  Afterwards, the \c tls_multi_init_finalize()
 * function must be called to finalize the structure's initialization
 * process.
 *
 * @param tls_options  - The configuration options to be used for this VPN
 *                       tunnel.
 *
 * @return A newly allocated and initialized \c tls_multi structure.
 */
struct tls_multi *tls_multi_init(struct tls_options *tls_options);

/**
 * Finalize initialization of a \c tls_multi structure.
 * @ingroup control_processor
 *
 * This function initializes the \c TM_ACTIVE \c tls_session, and in
 * server mode also the \c TM_UNTRUSTED \c tls_session, associated with
 * this \c tls_multi structure.  It also configures the control channel's
 * \c frame structure based on the data channel's \c frame given in
 * argument \a frame.
 *
 * @param multi        - The \c tls_multi structure of which to finalize
 *                       initialization.
 * @param frame        - The data channel's \c frame structure.
 */
void tls_multi_init_finalize(struct tls_multi *multi,
                             const struct frame *frame);

/*
 * Initialize a standalone tls-auth verification object.
 */
struct tls_auth_standalone *tls_auth_standalone_init(struct tls_options *tls_options,
                                                     struct gc_arena *gc);

/*
 * Finalize a standalone tls-auth verification object.
 */
void tls_auth_standalone_finalize(struct tls_auth_standalone *tas,
                                  const struct frame *frame);

/*
 * Set local and remote option compatibility strings.
 * Used to verify compatibility of local and remote option
 * sets.
 */
void tls_multi_init_set_options(struct tls_multi *multi,
                                const char *local,
                                const char *remote);

/**
 * Cleanup a \c tls_multi structure and free associated memory
 * allocations.
 * @ingroup control_processor
 *
 * This function cleans up a \c tls_multi structure.  This includes
 * cleaning up all associated \c tls_session structures.
 *
 * @param multi        - The \c tls_multi structure to clean up in free.
 * @param clear        - Whether the memory allocated for the \a multi
 *                       object should be overwritten with 0s.
 */
void tls_multi_free(struct tls_multi *multi, bool clear);

/** @} name Functions for initialization and cleanup of tls_multi structures */

/** @} addtogroup control_processor */

#define TLSMP_INACTIVE 0
#define TLSMP_ACTIVE   1
#define TLSMP_KILL     2

/*
 * Called by the top-level event loop.
 *
 * Basically decides if we should call tls_process for
 * the active or untrusted sessions.
 */
int tls_multi_process(struct tls_multi *multi,
                      struct buffer *to_link,
                      struct link_socket_actual **to_link_addr,
                      struct link_socket_info *to_link_socket_info,
                      interval_t *wakeup);


/**************************************************************************/
/**
 * Determine whether an incoming packet is a data channel or control
 * channel packet, and process accordingly.
 * @ingroup external_multiplexer
 *
 * When OpenVPN is in TLS mode, this is the first function to process an
 * incoming packet.  It inspects the packet's one-byte header which
 * contains the packet's opcode and key ID.  Depending on the opcode, the
 * packet is processed as a data channel or as a control channel packet.
 *
 * @par Data channel packets
 *
 * If the opcode indicates the packet is a data channel packet, then the
 * packet's key ID is used to find the local TLS state it is associated
 * with.  This state is checked whether it is active, authenticated, and
 * its remote peer is the source of this packet.  If these checks passed,
 * the state's security parameters are loaded into the \a opt crypto
 * options so that \p openvpn_decrypt() can later use them to authenticate
 * and decrypt the packet.
 *
 * This function then returns false.  The \a buf buffer has not been
 * modified, except for removing the header.
 *
 * @par Control channel packets
 *
 * If the opcode indicates the packet is a control channel packet, then
 * this function will process it based on its plaintext header. depending
 * on the packet's opcode and session ID this function determines if it is
 * destined for an active TLS session, or whether a new TLS session should
 * be started.  This function also initiates data channel session key
 * renegotiation if the received opcode requests that.
 *
 * If the incoming packet is destined for an active TLS session, then the
 * packet is inserted into the Reliability Layer and will be handled
 * later.
 *
 * @param multi - The TLS multi structure associated with the VPN tunnel
 *     of this packet.
 * @param from - The source address of the packet.
 * @param buf - A buffer structure containing the incoming packet.
 * @param opt - Returns a crypto options structure with the appropriate security
 *     parameters to handle the packet if it is a data channel packet.
 * @param ad_start - Returns a pointer to the start of the authenticated data of
 *     of this packet
 *
 * @return
 * @li True if the packet is a control channel packet that has been
 *     processed successfully.
 * @li False if the packet is a data channel packet, or if an error
 *     occurred during processing of a control channel packet.
 */
bool tls_pre_decrypt(struct tls_multi *multi,
                     const struct link_socket_actual *from,
                     struct buffer *buf,
                     struct crypto_options **opt,
                     bool floated,
                     const uint8_t **ad_start);


/**************************************************************************/
/** @name Functions for managing security parameter state for data channel packets
 *  @{ */

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
bool tls_pre_decrypt_lite(const struct tls_auth_standalone *tas,
                          const struct link_socket_actual *from,
                          const struct buffer *buf);


/**
 * Choose the appropriate security parameters with which to process an
 * outgoing packet.
 * @ingroup data_crypto
 *
 * If no appropriate security parameters can be found, or if some other
 * error occurs, then the buffer is set to empty, and the parameters to a NULL
 * pointer.
 *
 * @param multi - The TLS state for this packet's destination VPN tunnel.
 * @param buf - The buffer containing the outgoing packet.
 * @param opt - Returns a crypto options structure with the security parameters.
 */
void tls_pre_encrypt(struct tls_multi *multi,
                     struct buffer *buf, struct crypto_options **opt);


/**
 * Prepend a one-byte OpenVPN data channel P_DATA_V1 opcode to the packet.
 *
 * The opcode identifies the packet as a V1 data channel packet and gives the
 * low-permutation version of the key-id to the recipient, so it knows which
 * decrypt key to use.
 *
 * @param multi - The TLS state for this packet's destination VPN tunnel.
 * @param buf - The buffer to write the header to.
 *
 * @ingroup data_crypto
 */
void
tls_prepend_opcode_v1(const struct tls_multi *multi, struct buffer *buf);

/**
 * Prepend an OpenVPN data channel P_DATA_V2 header to the packet.  The
 * P_DATA_V2 header consists of a 1-byte opcode, followed by a 3-byte peer-id.
 *
 * The opcode identifies the packet as a V2 data channel packet and gives the
 * low-permutation version of the key-id to the recipient, so it knows which
 * decrypt key to use.
 *
 * The peer-id is sent by clients to servers to help the server determine to
 * select the decrypt key when the client is roaming between addresses/ports.
 *
 * @param multi - The TLS state for this packet's destination VPN tunnel.
 * @param buf - The buffer to write the header to.
 *
 * @ingroup data_crypto
 */
void
tls_prepend_opcode_v2(const struct tls_multi *multi, struct buffer *buf);

/**
 * Perform some accounting for the key state used.
 * @ingroup data_crypto
 *
 * @param multi - The TLS state for this packet's destination VPN tunnel.
 * @param buf - The buffer containing the outgoing packet.
 */
void tls_post_encrypt(struct tls_multi *multi, struct buffer *buf);

/** @} name Functions for managing security parameter state for data channel packets */

/*
 * Setup private key file password. If auth_file is given, use the
 * credentials stored in the file.
 */
void pem_password_setup(const char *auth_file);

/*
 * Setup authentication username and password. If auth_file is given, use the
 * credentials stored in the file.
 */
void auth_user_pass_setup(const char *auth_file, const struct static_challenge_info *sc_info);

/*
 * Ensure that no caching is performed on authentication information
 */
void ssl_set_auth_nocache(void);

/*
 * Purge any stored authentication information, both for key files and tunnel
 * authentication. If PCKS #11 is enabled, purge authentication for that too.
 */
void ssl_purge_auth(const bool auth_user_pass_only);

void ssl_set_auth_token(const char *token);

void ssl_set_auth_token_user(const char *username);

bool ssl_clean_auth_token(void);

#ifdef ENABLE_MANAGEMENT
/*
 * ssl_get_auth_challenge will parse the server-pushed auth-failed
 * reason string and return a dynamically allocated
 * auth_challenge_info struct.
 */
void ssl_purge_auth_challenge(void);

void ssl_put_auth_challenge(const char *cr_str);

#endif

/*
 * Reserve any extra space required on frames.
 */
void tls_adjust_frame_parameters(struct frame *frame);

/*
 * Send a payload over the TLS control channel
 */
bool tls_send_payload(struct tls_multi *multi,
                      const uint8_t *data,
                      int size);

/*
 * Receive a payload through the TLS control channel
 */
bool tls_rec_payload(struct tls_multi *multi,
                     struct buffer *buf);

/**
 * Updates remote address in TLS sessions.
 *
 * @param multi - Tunnel to update
 * @param addr - new address
 */
void tls_update_remote_addr(struct tls_multi *multi,
                            const struct link_socket_actual *addr);

/**
 * Update TLS session crypto parameters (cipher and auth) and derive data
 * channel keys based on the supplied options. Does nothing if keys are already
 * generated.
 *
 * @param session         The TLS session to update.
 * @param options         The options to use when updating session.
 * @param frame           The frame options for this session (frame overhead is
 *                        adjusted based on the selected cipher/auth).
 * @param frame_fragment  The fragment frame options.
 *
 * @return true if updating succeeded or keys are already generated, false otherwise.
 */
bool tls_session_update_crypto_params(struct tls_session *session,
                                      struct options *options,
                                      struct frame *frame,
                                      struct frame *frame_fragment);

#ifdef MANAGEMENT_DEF_AUTH
static inline char *
tls_get_peer_info(const struct tls_multi *multi)
{
    return multi->peer_info;
}
#endif

/*
 * inline functions
 */

/** Free the elements of a tls_wrap_ctx structure */
static inline void
tls_wrap_free(struct tls_wrap_ctx *tls_wrap)
{
    if (packet_id_initialized(&tls_wrap->opt.packet_id))
    {
        packet_id_free(&tls_wrap->opt.packet_id);
    }

    if (tls_wrap->cleanup_key_ctx)
    {
        free_key_ctx_bi(&tls_wrap->opt.key_ctx_bi);
    }

    free_buf(&tls_wrap->tls_crypt_v2_metadata);
    free_buf(&tls_wrap->work);
}

static inline bool
tls_initial_packet_received(const struct tls_multi *multi)
{
    return multi->n_sessions > 0;
}

static inline bool
tls_test_auth_deferred_interval(const struct tls_multi *multi)
{
    if (multi)
    {
        const struct key_state *ks = &multi->session[TM_ACTIVE].key[KS_PRIMARY];
        return now < ks->auth_deferred_expire;
    }
    return false;
}

static inline int
tls_test_payload_len(const struct tls_multi *multi)
{
    if (multi)
    {
        const struct key_state *ks = &multi->session[TM_ACTIVE].key[KS_PRIMARY];
        if (ks->state >= S_ACTIVE)
        {
            return BLEN(&ks->plaintext_read_buf);
        }
    }
    return 0;
}

static inline void
tls_set_single_session(struct tls_multi *multi)
{
    if (multi)
    {
        multi->opt.single_session = true;
    }
}

/*
 * protocol_dump() flags
 */
#define PD_TLS_AUTH_HMAC_SIZE_MASK 0xFF
#define PD_SHOW_DATA               (1<<8)
#define PD_TLS                     (1<<9)
#define PD_VERBOSE                 (1<<10)

const char *protocol_dump(struct buffer *buffer,
                          unsigned int flags,
                          struct gc_arena *gc);

/*
 * debugging code
 */

#ifdef MEASURE_TLS_HANDSHAKE_STATS
void show_tls_performance_stats(void);

#endif

/*#define EXTRACT_X509_FIELD_TEST*/
void extract_x509_field_test(void);

/**
 * Given a key_method, return true if opcode represents the one of the
 * hard_reset op codes for key-method 2
 *
 */
bool is_hard_reset_method2(int op);

/**
 * Cleans the saved user/password unless auth-nocache is in use.
 */
void ssl_clean_user_pass(void);


/*
 * Show the TLS ciphers that are available for us to use in the SSL
 * library with headers hinting their usage and warnings about usage.
 *
 * @param cipher_list       list of allowed TLS cipher, or NULL.
 * @param cipher_list_tls13 list of allowed TLS 1.3+ cipher, or NULL
 * @param tls_cert_profile  TLS certificate crypto profile name.
 */
void
show_available_tls_ciphers(const char *cipher_list,
                           const char *cipher_list_tls13,
                           const char *tls_cert_profile);

#endif /* ifndef OPENVPN_SSL_H */
