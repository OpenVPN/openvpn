/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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
 * @file Control Channel Common Data Structures
 */

#ifndef SSL_COMMON_H_
#define SSL_COMMON_H_

#include "session_id.h"
#include "socket.h"
#include "packet_id.h"
#include "crypto.h"
#include "options.h"

#include "ssl_backend.h"

/* passwords */
#define UP_TYPE_AUTH        "Auth"
#define UP_TYPE_PRIVATE_KEY "Private Key"

/** @addtogroup control_processor
 *  @{ */
/**
 * @name Control channel negotiation states
 *
 * These states represent the different phases of control channel
 * negotiation between OpenVPN peers.  OpenVPN servers and clients
 * progress through the states in a different order, because of their
 * different roles during exchange of random material.  The references to
 * the \c key_source2 structure in the list below is only valid if %key
 * method 2 is being used.  See the \link key_generation data channel key
 * generation\endlink related page for more information.
 *
 * Clients follow this order:
 *   -# \c S_INITIAL, ready to begin three-way handshake and control
 *      channel negotiation.
 *   -# \c S_PRE_START, have started three-way handshake, waiting for
 *      acknowledgment from remote.
 *   -# \c S_START, initial three-way handshake complete.
 *   -# \c S_SENT_KEY, have sent local part of \c key_source2 random
 *      material.
 *   -# \c S_GOT_KEY, have received remote part of \c key_source2 random
 *      material.
 *   -# \c S_ACTIVE, control channel successfully established
 *   -# \c S_GENERATED_KEYS, the data channel keys have been generated
 *
 * Servers follow the same order, except for \c S_SENT_KEY and \c
 * S_GOT_KEY being reversed, because the server first receives the
 * client's \c key_source2 random material before generating and sending
 * its own.
 *
 * @{
 */
#define S_ERROR          -1     /**< Error state.  */
#define S_UNDEF           0     /**< Undefined state, used after a \c
                                 *   key_state is cleaned up. */
#define S_INITIAL         1     /**< Initial \c key_state state after
                                 *   initialization by \c key_state_init()
                                 *   before start of three-way handshake. */
#define S_PRE_START       2     /**< Waiting for the remote OpenVPN peer
                                 *   to acknowledge during the initial
                                 *   three-way handshake. */
#define S_START           3     /**< Three-way handshake is complete,
                                 *   start of key exchange. */
#define S_SENT_KEY        4     /**< Local OpenVPN process has sent its
                                 *   part of the key material. */
#define S_GOT_KEY         5     /**< Local OpenVPN process has received
                                 *   the remote's part of the key
                                 *   material. */
#define S_ACTIVE          6     /**< Operational \c key_state state
                                 *   immediately after negotiation has
                                 *   completed while still within the
                                 *   handshake window.  Deferred auth and
                                 *   client connect can still be pending. */
#define S_GENERATED_KEYS  7     /**< The data channel keys have been generated
                                 *  The TLS session is fully authenticated
                                 *  when reaching this state. */

/* Note that earlier versions also had a S_OP_NORMAL state that was
 * virtually identical with S_ACTIVE and the code still assumes everything
 * >= S_ACTIVE to be fully operational */
/** @} name Control channel negotiation states */
/** @} addtogroup control_processor */

/**
 * Container for one half of random material to be used in %key method 2
 * \ref key_generation "data channel key generation".
 * @ingroup control_processor
 */
struct key_source {
    uint8_t pre_master[48];     /**< Random used for master secret
                                 *   generation, provided only by client
                                 *   OpenVPN peer. */
    uint8_t random1[32];        /**< Seed used for master secret
                                 *   generation, provided by both client
                                 *   and server. */
    uint8_t random2[32];        /**< Seed used for key expansion, provided
                                 *   by both client and server. */
};


/**
 * Container for both halves of random material to be used in %key method
 * 2 \ref key_generation "data channel key generation".
 * @ingroup control_processor
 */
struct key_source2 {
    struct key_source client;   /**< Random provided by client. */
    struct key_source server;   /**< Random provided by server. */
};


/**
 * This reflects the (server side) authentication state after the TLS
 * session has been established and key_method_2_read is called. If async auth
 * is enabled the state will first move to KS_AUTH_DEFERRED before eventually
 * being set to KS_AUTH_TRUE or KS_AUTH_FALSE
 * Only KS_AUTH_TRUE is fully authenticated
 */
enum ks_auth_state {
    KS_AUTH_FALSE,            /**< Key state is not authenticated  */
    KS_AUTH_DEFERRED,         /**< Key state authentication is being deferred,
                               * by async auth */
    KS_AUTH_TRUE              /**< Key state is authenticated. TLS and user/pass
                               * succeeded. This includes AUTH_PENDING/OOB
                               * authentication as those hold the
                               * connection artificially in KS_AUTH_DEFERRED
                               */
};

struct auth_deferred_status
{
    char *auth_control_file;
    char *auth_pending_file;
    char *auth_failed_reason_file;
    unsigned int auth_control_status;
};

/* key_state_test_auth_control_file return values, these specify the
 * current status of a deferred authentication */
enum auth_deferred_result {
    ACF_PENDING,      /**< deferred auth still pending */
    ACF_SUCCEEDED,    /**< deferred auth has suceeded */
    ACF_DISABLED,     /**< deferred auth is not used */
    ACF_FAILED        /**< deferred auth has failed */
};

enum dco_key_status {
    DCO_NOT_INSTALLED,
    DCO_INSTALLED_PRIMARY,
    DCO_INSTALLED_SECONDARY
};

/**
 * Security parameter state of one TLS and data channel %key session.
 * @ingroup control_processor
 *
 * This structure represents one security parameter session between
 * OpenVPN peers.  It includes the control channel TLS state and the data
 * channel crypto state.  It also contains the reliability layer
 * structures used for control channel messages.
 *
 * A new \c key_state structure is initialized for each hard or soft
 * reset.
 *
 * @see
 *  - This structure should be initialized using the \c key_state_init()
 *    function.
 *  - This structure should be cleaned up using the \c key_state_free()
 *    function.
 */
struct key_state
{
    int state;
    /** The state of the auth-token sent from the client */
    unsigned int auth_token_state_flags;

    /**
     * Key id for this key_state,  inherited from struct tls_session.
     * @see tls_session::key_id.
     */
    int key_id;

    /**
     * Key id for this key_state, inherited from struct tls_session.
     * @see tls_multi::peer_id.
     */
    uint32_t peer_id;

    struct key_state_ssl ks_ssl; /* contains SSL object and BIOs for the control channel */

    time_t initial;             /* when we created this session */
    time_t established;         /* when our state went S_ACTIVE */
    time_t must_negotiate;      /* key negotiation times out if not finished before this time */
    time_t must_die;            /* this object is destroyed at this time */
    time_t peer_last_packet;    /* Last time we received a packet in this control session */

    int initial_opcode;         /* our initial P_ opcode */
    struct session_id session_id_remote; /* peer's random session ID */
    struct link_socket_actual remote_addr; /* peer's IP addr */

    struct crypto_options crypto_options;/* data channel crypto options */

    struct key_source2 *key_src;       /* source entropy for key expansion */

    struct buffer plaintext_read_buf;
    struct buffer plaintext_write_buf;
    struct buffer ack_write_buf;

    struct reliable *send_reliable; /* holds a copy of outgoing packets until ACK received */
    struct reliable *rec_reliable; /* order incoming ciphertext packets before we pass to TLS */
    struct reliable_ack *rec_ack; /* buffers all packet IDs we want to ACK back to sender */
    struct reliable_ack *lru_acks; /* keeps the most recently acked packages*/

    /** Holds outgoing message for the control channel until ks->state reaches
     * S_ACTIVE */
    struct buffer_list *paybuf;
    counter_type n_bytes;                /* how many bytes sent/recvd since last key exchange */
    counter_type n_packets;              /* how many packets sent/recvd since last key exchange */

    /*
     * If bad username/password, TLS connection will come up but 'authenticated' will be false.
     */
    enum ks_auth_state authenticated;
    time_t auth_deferred_expire;

#ifdef ENABLE_MANAGEMENT
    unsigned int mda_key_id;
    enum auth_deferred_result mda_status;
#endif
    time_t acf_last_mod;

    struct auth_deferred_status plugin_auth;
    struct auth_deferred_status script_auth;

    enum dco_key_status dco_status;
};

/** Control channel wrapping (--tls-auth/--tls-crypt) context */
struct tls_wrap_ctx
{
    enum {
        TLS_WRAP_NONE = 0, /**< No control channel wrapping */
        TLS_WRAP_AUTH,  /**< Control channel authentication */
        TLS_WRAP_CRYPT, /**< Control channel encryption and authentication */
    } mode;                     /**< Control channel wrapping mode */
    struct crypto_options opt;  /**< Crypto state */
    struct buffer work;         /**< Work buffer (only for --tls-crypt) */
    struct key_ctx tls_crypt_v2_server_key;  /**< Decrypts client keys */
    const struct buffer *tls_crypt_v2_wkc;   /**< Wrapped client key,
                                              *   sent to server */
    struct buffer tls_crypt_v2_metadata;     /**< Received from client */
    bool cleanup_key_ctx;                    /**< opt.key_ctx_bi is owned by
                                              *   this context */
    /** original key data to be xored in to the key for dynamic tls-crypt.
     *
     * We keep the original key data to ensure that the newly generated key
     * for the dynamic tls-crypt has the same level of quality by using
     * xor with the original key. This gives us the same same entropy/randomness
     * as the original tls-crypt key to ensure the post-quantum use case of
     * tls-crypt still holds true
     * */
    struct key2 original_wrap_keydata;
};

/*
 * Our const options, obtained directly or derived from
 * command line options.
 */
struct tls_options
{
    /* our master TLS context from which all SSL objects derived */
    struct tls_root_ctx ssl_ctx;

    /* data channel cipher, hmac, and key lengths */
    struct key_type key_type;

    /* true if we are a TLS server, client otherwise */
    bool server;

    /* if true, don't xmit until first packet from peer is received */
    bool xmit_hold;

    /* local and remote options strings
     * that must match between client and server */
    const char *local_options;
    const char *remote_options;

    /* from command line */
    bool replay;
    bool single_session;
    bool disable_occ;
    int mode;
    bool pull;
    /**
     * The detail of info we push in peer info
     *
     * 0 - nothing at all, P2MP server only
     * 1 - only the most basic information to negotiate cipher and features
     *     for P2P NCP
     * 2 - normal setting for clients
     * 3 - full information including "sensitive data" like IV_HWADDR
     *     enabled by --push-peer-info
     */
    int push_peer_info_detail;
    int transition_window;
    int handshake_window;
    interval_t packet_timeout;
    int renegotiate_bytes;
    int renegotiate_packets;
    interval_t renegotiate_seconds;

    /* cert verification parms */
    const char *verify_command;
    int verify_x509_type;
    const char *verify_x509_name;
    const char *crl_file;
    bool crl_file_inline;
    int ns_cert_type;
    unsigned remote_cert_ku[MAX_PARMS];
    const char *remote_cert_eku;
    struct verify_hash_list *verify_hash;
    int verify_hash_depth;
    bool verify_hash_no_ca;
    hash_algo_type verify_hash_algo;
#ifdef ENABLE_X509ALTUSERNAME
    char *x509_username_field[MAX_PARMS];
#else
    char *x509_username_field[2];
#endif

    /* struct crypto_option flags */
    unsigned int crypto_flags;

    int replay_window;                 /* --replay-window parm */
    int replay_time;                   /* --replay-window parm */
    bool tcp_mode;

    const char *config_ciphername;
    const char *config_ncp_ciphers;

    bool tls_crypt_v2;
    const char *tls_crypt_v2_verify_script;

    /** TLS handshake wrapping state */
    struct tls_wrap_ctx tls_wrap;

    struct frame frame;

    /* used for username/password authentication */
    const char *auth_user_pass_verify_script;
    const char *client_crresponse_script;
    bool auth_user_pass_verify_script_via_file;
    const char *tmp_dir;
    const char *export_peer_cert_dir;
    const char *auth_user_pass_file;
    bool auth_user_pass_file_inline;

    bool auth_token_generate;   /**< Generate auth-tokens on successful
                                 * user/pass auth,seet via
                                 * options->auth_token_generate. */
    bool auth_token_call_auth; /**< always call normal authentication */
    unsigned int auth_token_lifetime;
    unsigned int auth_token_renewal;

    struct key_ctx auth_token_key;

    /* use the client-config-dir as a positive authenticator */
    const char *client_config_dir_exclusive;

    /* instance-wide environment variable set */
    struct env_set *es;
    openvpn_net_ctx_t *net_ctx;
    const struct plugin_list *plugins;

    /* compression parms */
#ifdef USE_COMP
    struct compress_options comp_options;
#endif

    /* configuration file SSL-related boolean and low-permutation options */
#define SSLF_CLIENT_CERT_NOT_REQUIRED (1<<0)
#define SSLF_CLIENT_CERT_OPTIONAL     (1<<1)
#define SSLF_USERNAME_AS_COMMON_NAME  (1<<2)
#define SSLF_AUTH_USER_PASS_OPTIONAL  (1<<3)
#define SSLF_OPT_VERIFY               (1<<4)
#define SSLF_CRL_VERIFY_DIR           (1<<5)
#define SSLF_TLS_VERSION_MIN_SHIFT    6
#define SSLF_TLS_VERSION_MIN_MASK     0xF  /* (uses bit positions 6 to 9) */
#define SSLF_TLS_VERSION_MAX_SHIFT    10
#define SSLF_TLS_VERSION_MAX_MASK     0xF  /* (uses bit positions 10 to 13) */
#define SSLF_TLS_DEBUG_ENABLED        (1<<14)
    unsigned int ssl_flags;

#ifdef ENABLE_MANAGEMENT
    struct man_def_auth_context *mda_context;
#endif

    const struct x509_track *x509_track;

#ifdef ENABLE_MANAGEMENT
    const struct static_challenge_info *sci;
#endif

    /* --gremlin bits */
    int gremlin;

    /* Keying Material Exporter [RFC 5705] parameters */
    const char *ekm_label;
    size_t ekm_label_size;
    size_t ekm_size;

    bool dco_enabled; /**< Whether keys have to be installed in DCO or not */
};

/** @addtogroup control_processor
 *  @{ */
/** @name Index of key_state objects within a tls_session structure
 *
 *  This is the index of \c tls_session.key
 *
 *  @{ */
#define KS_PRIMARY    0         /**< Primary %key state index. */
#define KS_LAME_DUCK  1         /**< %Key state index that will retire
                                 *   soon. */
#define KS_SIZE       2         /**< Size of the \c tls_session.key array. */
/** @} name Index of key_state objects within a tls_session structure */
/** @} addtogroup control_processor */

/**
 * Security parameter state of a single session within a VPN tunnel.
 * @ingroup control_processor
 *
 * This structure represents an OpenVPN peer-to-peer control channel
 * session.
 *
 * A \c tls_session remains over soft resets, but a new instance is
 * initialized for each hard reset.
 *
 * @see
 *  - This structure should be initialized using the \c tls_session_init()
 *    function.
 *  - This structure should be cleaned up using the \c tls_session_free()
 *    function.
 */
struct tls_session
{
    /* const options and config info */
    struct tls_options *opt;

    /* during hard reset used to control burst retransmit */
    bool burst;

    /* authenticate control packets */
    struct tls_wrap_ctx tls_wrap;

    /* Specific tls-crypt for renegotiations, if this is valid,
     * tls_wrap_reneg.mode is TLS_WRAP_CRYPT, otherwise ignore it */
    struct tls_wrap_ctx tls_wrap_reneg;

    int initial_opcode;         /* our initial P_ opcode */
    struct session_id session_id; /* our random session ID */

    /**
     * The current active key id, used to keep track of renegotiations.
     * key_id increments with each soft reset to KEY_ID_MASK then recycles back
     * to 1.  This way you know that if key_id is 0, it is the first key.
     */
    int key_id;

    int limit_next;             /* used for traffic shaping on the control channel */

    int verify_maxlevel;

    char *common_name;

    struct cert_hash_set *cert_hash_set;

    bool verified;              /* true if peer certificate was verified against CA */

    /* not-yet-authenticated incoming client */
    struct link_socket_actual untrusted_addr;

    struct key_state key[KS_SIZE];
};

/** @addtogroup control_processor
 *  @{ */
/** @name Index of tls_session objects within a tls_multi structure
 *
 *  This is the index of \c tls_multi.session
 *
 *  Normally three tls_session objects are maintained by an active openvpn
 *  session.  The first is the current, TLS authenticated session, the
 *  second is used to process connection requests from a new client that
 *  would usurp the current session if successfully authenticated, and the
 *  third is used as a repository for a "lame-duck" %key in the event that
 *  the primary session resets due to error while the lame-duck %key still
 *  has time left before its expiration.  Lame duck keys are used to
 *  maintain the continuity of the data channel connection while a new %key
 *  is being negotiated.
 *
 *  @{ */
#define TM_ACTIVE    0          /**< Active \c tls_session. */
#define TM_INITIAL   1          /**< As yet un-trusted \c tls_session
                                 *   being negotiated. */
#define TM_LAME_DUCK 2          /**< Old \c tls_session. */
#define TM_SIZE      3          /**< Size of the \c tls_multi.session
                                 *   array. */
/** @} name Index of tls_session objects within a tls_multi structure */
/** @} addtogroup control_processor */


/*
 * The number of keys we will scan on encrypt or decrypt.  The first
 * is the "active" key.  The second is the lame_duck or retiring key
 * associated with the active key's session ID.  The third is a detached
 * lame duck session that only occurs in situations where a key renegotiate
 * failed on the active key, but a lame duck key was still valid.  By
 * preserving the lame duck session, we can be assured of having a data
 * channel key available even when network conditions are so bad that
 * we can't negotiate a new key within the time allotted.
 */
#define KEY_SCAN_SIZE 3


/* multi state (originally client authentication state (=CAS))
 * CAS_NOT_CONNECTED must be 0 since non multi code paths still check
 * this variable but do not explicitly initialise it and depend
 * on zero initialisation */

/* CAS_NOT_CONNECTED is the initial state for every context. When the *first*
 * tls_session reaches S_ACTIVE, this state machine moves to CAS_PENDING (server)
 * or CAS_CONNECT_DONE (client/p2p) as clients skip the stages associated with
 * connect scripts/plugins */
enum multi_status {
    CAS_NOT_CONNECTED,
    CAS_WAITING_AUTH,               /**< Initial TLS connection established but deferred auth is not yet finished */
    CAS_PENDING,                    /**< Options import (Connect script/plugin, ccd,...) */
    CAS_PENDING_DEFERRED,           /**< Waiting on an async option import handler */
    CAS_PENDING_DEFERRED_PARTIAL,   /**< at least handler succeeded but another is still pending */
    CAS_FAILED,                     /**< Option import failed or explicitly denied the client */
    CAS_WAITING_OPTIONS_IMPORT,     /**< client with pull or p2p waiting for first time options import */
    CAS_RECONNECT_PENDING,          /**< session has already successful established (CAS_CONNECT_DONE)
                                     * but has a reconnect and needs to redo some initialisation, this state is
                                     * similar CAS_WAITING_OPTIONS_IMPORT but skips a few things. The normal connection
                                     * skips this step. */
    CAS_CONNECT_DONE,
};


/**
 * Security parameter state for a single VPN tunnel.
 * @ingroup control_processor
 *
 * An active VPN tunnel running with TLS enabled has one \c tls_multi
 * object, in which it stores all control channel and data channel
 * security parameter state.  This structure can contain multiple,
 * possibly simultaneously active, \c tls_context objects to allow for
 * interruption-less transitions during session renegotiations.  Each \c
 * tls_context represents one control channel session, which can span
 * multiple data channel security parameter sessions stored in \c
 * key_state structures.
 */
struct tls_multi
{
    /* used to coordinate access between main thread and TLS thread */
    /*MUTEX_PTR_DEFINE (mutex);*/

    /* const options and config info */
    struct tls_options opt;

    /*
     * used by tls_pre_encrypt to communicate the encrypt key
     * to tls_post_encrypt()
     */
    struct key_state *save_ks;  /* temporary pointer used between pre/post routines */

    /*
     * Used to return outgoing address from
     * tls_multi_process.
     */
    struct link_socket_actual to_link_addr;

    int n_sessions;             /**< Number of sessions negotiated thus
                                 *   far. */
    enum multi_status multi_state;

    /*
     * Number of errors.
     */
    int n_hard_errors; /* errors due to TLS negotiation failure */
    int n_soft_errors; /* errors due to unrecognized or failed-to-authenticate incoming packets */

    /*
     * Our locked common name, username, and cert hashes (cannot change during the life of this tls_multi object)
     */
    char *locked_cn;
    char *locked_username;
    struct cert_hash_set *locked_cert_hash_set;

    /** Time of last when we updated the cached state of
     * tls_authentication_status deferred files */
    time_t tas_cache_last_update;

    /** The number of times we updated the cache */
    unsigned int tas_cache_num_updates;

    /*
     * An error message to send to client on AUTH_FAILED
     */
    char *client_reason;

    /*
     * A multi-line string of general-purpose info received from peer
     * over control channel.
     */
    char *peer_info;
    char *auth_token;    /**< If server sends a generated auth-token,
                          *   this is the token to use for future
                          *   user/pass authentications in this session.
                          */
    char *auth_token_initial;
    /**< The first auth-token we sent to a client. We use this to remember
     * the session ID and initial timestamp when generating new auth-token.
     */
#define  AUTH_TOKEN_HMAC_OK              (1<<0)
    /**< Auth-token sent from client has valid hmac */
#define  AUTH_TOKEN_EXPIRED              (1<<1)
    /**< Auth-token sent from client has expired */
#define  AUTH_TOKEN_VALID_EMPTYUSER      (1<<2)
    /**<
     * Auth-token is only valid for an empty username
     * and not the username actually supplied from the client
     *
     * OpenVPN 3 clients sometimes wipes or replaces the username with a
     * username hint from their config.
     */

    /* For P_DATA_V2 */
    uint32_t peer_id;
    bool use_peer_id;

    char *remote_ciphername;    /**< cipher specified in peer's config file */
    bool remote_usescomp;       /**< remote announced comp-lzo in OCC string */

    /*
     * Our session objects.
     */
    struct tls_session session[TM_SIZE];
    /**< Array of \c tls_session objects
     *   representing control channel
     *   sessions with the remote peer. */

    /* Only used when DCO is used to remember how many keys we installed
     * for this session */
    int dco_keys_installed;
    /**
     * This is the handle that DCO uses to identify this session with the
     * kernel.
     *
     * We keep this separate as the normal peer_id can change during
     * p2p NCP and we need to track the id that is really used.
     */
    int dco_peer_id;

    dco_context_t *dco;
};

/**  gets an item  of \c key_state objects in the
 *   order they should be scanned by data
 *   channel modules. */
static inline struct key_state *
get_key_scan(struct tls_multi *multi, int index)
{
    switch (index)
    {
        case 0:
            return &multi->session[TM_ACTIVE].key[KS_PRIMARY];

        case 1:
            return &multi->session[TM_ACTIVE].key[KS_LAME_DUCK];

        case 2:
            return &multi->session[TM_LAME_DUCK].key[KS_LAME_DUCK];

        default:
            ASSERT(false);
            return NULL; /* NOTREACHED */
    }
}

/**  gets an item  of \c key_state objects in the
 *   order they should be scanned by data
 *   channel modules. */
static inline const struct key_state *
get_primary_key(const struct tls_multi *multi)
{
    return &multi->session[TM_ACTIVE].key[KS_PRIMARY];
}

#endif /* SSL_COMMON_H_ */
