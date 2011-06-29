/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010 Fox Crypto B.V. <openvpn@fox-it.com>
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

/**
 * @file Control Channel SSL/Data channel negotiation module
 */

#ifndef OPENVPN_SSL_H
#define OPENVPN_SSL_H

#if defined(USE_CRYPTO) && defined(USE_SSL)

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

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
#include "ssl_verify.h"
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

/* indicates key_method >= 2 */
#define P_CONTROL_HARD_RESET_CLIENT_V2 7     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V2 8     /* initial key from server, forget previous state */

/* define the range of legal opcodes */
#define P_FIRST_OPCODE                 1
#define P_LAST_OPCODE                  8

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
 *   -# \c S_ACTIVE, normal operation during remaining handshake window.
 *   -# \c S_NORMAL_OP, normal operation.
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
                                 *   handshake window. */
/* ready to exchange data channel packets */
#define S_NORMAL_OP       7     /**< Normal operational \c key_state
                                 *   state. */
/** @} name Control channel negotiation states */
/** @} addtogroup control_processor */


#define DECRYPT_KEY_ENABLED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))
                                /**< Check whether the \a ks \c key_state
                                 *   is ready to receive data channel
                                 *   packets.
                                 *   @ingroup data_crypto
                                 *
                                 *   If true, it is safe to assume that
                                 *   this session has been authenticated
                                 *   by TLS.
                                 *
                                 *   @note This macro only works if
                                 *       S_SENT_KEY + 1 == S_GOT_KEY. */

/* Should we aggregate TLS
 * acknowledgements, and tack them onto
 * control packets? */
#define TLS_AGGREGATE_ACK

/*
 * If TLS_AGGREGATE_ACK, set the
 * max number of acknowledgments that
 * can "hitch a ride" on an outgoing
 * non-P_ACK_V1 control packet.
 */
#define CONTROL_SEND_ACK_MAX 4

/*
 * Define number of buffers for send and receive in the reliability layer.
 */
#define TLS_RELIABLE_N_SEND_BUFFERS  4 /* also window size for reliablity layer */
#define TLS_RELIABLE_N_REC_BUFFERS   8

/*
 * Various timeouts
 */
 
#define TLS_MULTI_REFRESH 15    /* call tls_multi_process once every n seconds */
#define TLS_MULTI_HORIZON 2     /* call tls_multi_process frequently for n seconds after
				   every packet sent/received action */

/* The SSL/TLS worker thread will wait at most this many seconds for the interprocess
   communication pipe to the main thread to be ready to accept writes. */
#define TLS_MULTI_THREAD_SEND_TIMEOUT 5

/* Interval that tls_multi_process should call tls_authentication_status */
#define TLS_MULTI_AUTH_STATUS_INTERVAL 10

/*
 * Buffer sizes (also see mtu.h).
 */

/* Maximum length of the username in cert */
#define TLS_USERNAME_LEN 64

/* Legal characters in an X509 or common name */
#define X509_NAME_CHAR_CLASS   (CC_ALNUM|CC_UNDERBAR|CC_DASH|CC_DOT|CC_AT|CC_COLON|CC_SLASH|CC_EQUAL)
#define COMMON_NAME_CHAR_CLASS (CC_ALNUM|CC_UNDERBAR|CC_DASH|CC_DOT|CC_AT|CC_SLASH)

/* Maximum length of OCC options string passed as part of auth handshake */
#define TLS_OPTIONS_LEN 512

/* Default field in X509 to be username */
#define X509_USERNAME_FIELD_DEFAULT "CN"

/*
 * Range of key exchange methods
 */
#define KEY_METHOD_MIN 1
#define KEY_METHOD_MAX 2

/* key method taken from lower 4 bits */
#define KEY_METHOD_MASK 0x0F

/*
 * Measure success rate of TLS handshakes, for debugging only
 */
/* #define MEASURE_TLS_HANDSHAKE_STATS */

/*
 * Keep track of certificate hashes at various depths
 */

/* Maximum certificate depth we will allow */
#define MAX_CERT_DEPTH 16

struct cert_hash {
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
};

struct cert_hash_set {
  struct cert_hash *ch[MAX_CERT_DEPTH];
};
/*
 * Prepare the SSL library for use
 */
void init_ssl_lib (void);

/*
 * Free any internal state that the SSL library might have
 */
void free_ssl_lib (void);

/**
 * Container for one half of random material to be used in %key method 2
 * \ref key_generation "data channel key generation".
 * @ingroup control_processor
 */
struct key_source {
  uint8_t pre_master[48];       /**< Random used for master secret
                                 *   generation, provided only by client
                                 *   OpenVPN peer. */
  uint8_t random1[32];          /**< Seed used for master secret
                                 *   generation, provided by both client
                                 *   and server. */
  uint8_t random2[32];          /**< Seed used for key expansion, provided
                                 *   by both client and server. */
};


/**
 * Container for both halves of random material to be used in %key method
 * 2 \ref key_generation "data channel key generation".
 * @ingroup control_processor
 */
struct key_source2 {
  struct key_source client;     /**< Random provided by client. */
  struct key_source server;     /**< Random provided by server. */
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
  int key_id;			/* inherited from struct tls_session below */

  SSL *ssl;			/* SSL object -- new obj created for each new key */
  BIO *ssl_bio;			/* read/write plaintext from here */
  BIO *ct_in;			/* write ciphertext to here */
  BIO *ct_out;			/* read ciphertext from here */

  time_t established;		/* when our state went S_ACTIVE */
  time_t must_negotiate;	/* key negotiation times out if not finished before this time */
  time_t must_die;		/* this object is destroyed at this time */

  int initial_opcode;		/* our initial P_ opcode */
  struct session_id session_id_remote;   /* peer's random session ID */
  struct link_socket_actual remote_addr; /* peer's IP addr */
  struct packet_id packet_id;	       /* for data channel, to prevent replay attacks */

  struct key_ctx_bi key;	       /* data channel keys for encrypt/decrypt/hmac */

  struct key_source2 *key_src;         /* source entropy for key expansion */

  struct buffer plaintext_read_buf;
  struct buffer plaintext_write_buf;
  struct buffer ack_write_buf;

  struct reliable *send_reliable; /* holds a copy of outgoing packets until ACK received */
  struct reliable *rec_reliable;  /* order incoming ciphertext packets before we pass to TLS */
  struct reliable_ack *rec_ack;	  /* buffers all packet IDs we want to ACK back to sender */

  struct buffer_list *paybuf;

  counter_type n_bytes;		 /* how many bytes sent/recvd since last key exchange */
  counter_type n_packets;	 /* how many packets sent/recvd since last key exchange */

  /*
   * If bad username/password, TLS connection will come up but 'authenticated' will be false.
   */
  bool authenticated;
  time_t auth_deferred_expire;

#ifdef ENABLE_DEF_AUTH
  /* If auth_deferred is true, authentication is being deferred */
  bool auth_deferred;
#ifdef MANAGEMENT_DEF_AUTH
  unsigned int mda_key_id;
  unsigned int mda_status;
#endif
#ifdef PLUGIN_DEF_AUTH
  unsigned int auth_control_status;
  time_t acf_last_mod;
  char *auth_control_file;
#endif
#endif
};

#ifdef ENABLE_X509_TRACK

struct x509_track
{
  const struct x509_track *next;
  const char *name;
# define XT_FULL_CHAIN (1<<0)
  unsigned int flags;
  int nid;
};

void x509_track_add (const struct x509_track **ll_head, const char *name, int msglevel, struct gc_arena *gc);

#endif

/*
 * Our const options, obtained directly or derived from
 * command line options.
 */
struct tls_options
{
  /* our master SSL_CTX from which all SSL objects derived */
  SSL_CTX *ssl_ctx;

  /* data channel cipher, hmac, and key lengths */
  struct key_type key_type;

  /* true if we are a TLS server, client otherwise */
  bool server;

  /* if true, don't xmit until first packet from peer is received */
  bool xmit_hold;

#ifdef ENABLE_OCC
  /* local and remote options strings
     that must match between client and server */
  const char *local_options;
  const char *remote_options;
#endif

  /* from command line */
  int key_method;
  bool replay;
  bool single_session;
#ifdef ENABLE_OCC
  bool disable_occ;
#endif
#ifdef ENABLE_PUSH_PEER_INFO
  bool push_peer_info;
#endif
  int transition_window;
  int handshake_window;
  interval_t packet_timeout;
  int renegotiate_bytes;
  int renegotiate_packets;
  interval_t renegotiate_seconds;

  /* cert verification parms */
  const char *verify_command;
  const char *verify_export_cert;
  const char *verify_x509name;
  const char *crl_file;
  int ns_cert_type;
  unsigned remote_cert_ku[MAX_PARMS];
  const char *remote_cert_eku;
  uint8_t *verify_hash;

  /* allow openvpn config info to be
     passed over control channel */
  bool pass_config_info;

  /* struct crypto_option flags */
  unsigned int crypto_flags_and;
  unsigned int crypto_flags_or;

  int replay_window;                   /* --replay-window parm */
  int replay_time;                     /* --replay-window parm */
  bool tcp_mode;

  /* packet authentication for TLS handshake */
  struct crypto_options tls_auth;
  struct key_ctx_bi tls_auth_key;

  /* frame parameters for TLS control channel */
  struct frame frame;

  /* used for username/password authentication */
  const char *auth_user_pass_verify_script;
  bool auth_user_pass_verify_script_via_file;
  const char *tmp_dir;

  /* use the client-config-dir as a positive authenticator */
  const char *client_config_dir_exclusive;

  /* instance-wide environment variable set */
  struct env_set *es;
  const struct plugin_list *plugins;

  /* configuration file boolean options */
# define SSLF_CLIENT_CERT_NOT_REQUIRED (1<<0)
# define SSLF_USERNAME_AS_COMMON_NAME  (1<<1)
# define SSLF_AUTH_USER_PASS_OPTIONAL  (1<<2)
# define SSLF_NO_NAME_REMAPPING        (1<<3)
# define SSLF_OPT_VERIFY               (1<<4)
# define SSLF_CRL_VERIFY_DIR           (1<<5)
  unsigned int ssl_flags;

#ifdef MANAGEMENT_DEF_AUTH
  struct man_def_auth_context *mda_context;
#endif

#ifdef ENABLE_X509_TRACK
  const struct x509_track *x509_track;
#endif

#ifdef ENABLE_CLIENT_CR
  const struct static_challenge_info *sci;
#endif

  /* --gremlin bits */
  int gremlin;
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
  const struct tls_options *opt;

  /* during hard reset used to control burst retransmit */
  bool burst;

  /* authenticate control packets */
  struct crypto_options tls_auth;
  struct packet_id tls_auth_pid;

  int initial_opcode;		/* our initial P_ opcode */
  struct session_id session_id;	/* our random session ID */
  int key_id;			/* increments with each soft reset (for key renegotiation) */

  int limit_next;               /* used for traffic shaping on the control channel */

  int verify_maxlevel;

  char *common_name;

  struct cert_hash_set *cert_hash_set;

#ifdef ENABLE_PF
  uint32_t common_name_hashval;
#endif

  bool verified;                /* true if peer certificate was verified against CA */

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
#define TM_UNTRUSTED 1          /**< As yet un-trusted \c tls_session
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
  /* const options and config info */
  struct tls_options opt;

  struct key_state* key_scan[KEY_SCAN_SIZE];
                                /**< List of \c key_state objects in the
                                 *   order they should be scanned by data
                                 *   channel modules. */

  /*
   * used by tls_pre_encrypt to communicate the encrypt key
   * to tls_post_encrypt()
   */
  struct key_state *save_ks;	/* temporary pointer used between pre/post routines */

  /*
   * Used to return outgoing address from
   * tls_multi_process.
   */
  struct link_socket_actual to_link_addr;

  int n_sessions;               /**< Number of sessions negotiated thus
                                 *   far. */

  /*
   * Number of errors.
   */
  int n_hard_errors;   /* errors due to TLS negotiation failure */
  int n_soft_errors;   /* errors due to unrecognized or failed-to-authenticate incoming packets */

  /*
   * Our locked common name, username, and cert hashes (cannot change during the life of this tls_multi object)
   */
  char *locked_cn;
  char *locked_username;
  struct cert_hash_set *locked_cert_hash_set;

#ifdef ENABLE_DEF_AUTH
  /*
   * An error message to send to client on AUTH_FAILED
   */
  char *client_reason;

  /*
   * A multi-line string of general-purpose info received from peer
   * over control channel.
   */
  char *peer_info;

  /* Time of last call to tls_authentication_status */
  time_t tas_last;
#endif

  /*
   * Our session objects.
   */
  struct tls_session session[TM_SIZE];
                                /**< Array of \c tls_session objects
                                 *   representing control channel
                                 *   sessions with the remote peer. */
};

/*
 * Used in --mode server mode to check tls-auth signature on initial
 * packets received from new clients.
 */
struct tls_auth_standalone
{
  struct key_ctx_bi tls_auth_key;
  struct crypto_options tls_auth_options;
  struct frame frame;
};

void init_ssl_lib (void);
void free_ssl_lib (void);

/**
 * Build master SSL context object that serves for the whole of OpenVPN
 * instantiation
 */
void init_ssl (const struct options *options, struct tls_root_ctx *ctx);

struct tls_multi *tls_multi_init (struct tls_options *tls_options);

struct tls_auth_standalone *tls_auth_standalone_init (struct tls_options *tls_options,
						      struct gc_arena *gc);

void tls_auth_standalone_finalize (struct tls_auth_standalone *tas,
				   const struct frame *frame);

void tls_multi_init_finalize(struct tls_multi *multi,
			     const struct frame *frame);

void tls_multi_init_set_options(struct tls_multi* multi,
				const char *local,
				const char *remote);

#define TLSMP_INACTIVE 0
#define TLSMP_ACTIVE   1
#define TLSMP_KILL     2
int tls_multi_process (struct tls_multi *multi,
		       struct buffer *to_link,
		       struct link_socket_actual **to_link_addr,
		       struct link_socket_info *to_link_socket_info,
		       interval_t *wakeup);

void tls_multi_free (struct tls_multi *multi, bool clear);


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
 * @param opt - A crypto options structure that will be loaded with the
 *     appropriate security parameters to handle the packet if it is a
 *     data channel packet.
 *
 * @return
 * @li True if the packet is a control channel packet that has been
 *     processed successfully.
 * @li False if the packet is a data channel packet, or if an error
 *     occurred during processing of a control channel packet.
 */
bool tls_pre_decrypt (struct tls_multi *multi,
		      const struct link_socket_actual *from,
		      struct buffer *buf,
		      struct crypto_options *opt);


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
bool tls_pre_decrypt_lite (const struct tls_auth_standalone *tas,
			   const struct link_socket_actual *from,
			   const struct buffer *buf);


/**
 * Choose the appropriate security parameters with which to process an
 * outgoing packet.
 * @ingroup data_crypto
 *
 * If no appropriate security parameters can be found, or if some other
 * error occurs, then the buffer is set to empty.
 *
 * @param multi - The TLS state for this packet's destination VPN tunnel.
 * @param buf - The buffer containing the outgoing packet.
 * @param opt - The crypto options structure into which the appropriate
 *     security parameters should be loaded.
 */
void tls_pre_encrypt (struct tls_multi *multi,
		      struct buffer *buf, struct crypto_options *opt);


/**
 * Prepend the one-byte OpenVPN header to the packet, and perform some
 * accounting for the key state used.
 * @ingroup data_crypto
 *
 * @param multi - The TLS state for this packet's destination VPN tunnel.
 * @param buf - The buffer containing the outgoing packet.
 */
void tls_post_encrypt (struct tls_multi *multi, struct buffer *buf);

/** @} name Functions for managing security parameter state for data channel packets */

void pem_password_setup (const char *auth_file);
int pem_password_callback (char *buf, int size, int rwflag, void *u);
void auth_user_pass_setup (const char *auth_file, const struct static_challenge_info *sc_info);
void ssl_set_auth_nocache (void);
void ssl_set_auth_token (const char *token);
void ssl_purge_auth (const bool auth_user_pass_only);


#ifdef ENABLE_CLIENT_CR
/*
 * ssl_get_auth_challenge will parse the server-pushed auth-failed
 * reason string and return a dynamically allocated
 * auth_challenge_info struct.
 */
void ssl_purge_auth_challenge (void);
void ssl_put_auth_challenge (const char *cr_str);
#endif

void tls_set_verify_command (const char *cmd);
void tls_set_crl_verify (const char *crl);
void tls_set_verify_x509name (const char *x509name);

void tls_adjust_frame_parameters(struct frame *frame);

bool tls_send_payload (struct tls_multi *multi,
		       const uint8_t *data,
		       int size);

bool tls_rec_payload (struct tls_multi *multi,
		      struct buffer *buf);

const char *tls_common_name (const struct tls_multi* multi, const bool null);
const char *tls_username(const struct tls_multi *multi, const bool null);
void tls_set_common_name (struct tls_multi *multi, const char *common_name);
void tls_lock_common_name (struct tls_multi *multi);
void tls_lock_cert_hash_set (struct tls_multi *multi);

#define TLS_AUTHENTICATION_SUCCEEDED  0
#define TLS_AUTHENTICATION_FAILED     1
#define TLS_AUTHENTICATION_DEFERRED   2
#define TLS_AUTHENTICATION_UNDEFINED  3
int tls_authentication_status (struct tls_multi *multi, const int latency);
void tls_deauthenticate (struct tls_multi *multi);

#ifdef MANAGEMENT_DEF_AUTH
bool tls_authenticate_key (struct tls_multi *multi, const unsigned int mda_key_id, const bool auth, const char *client_reason);

static inline char *
tls_get_peer_info(const struct tls_multi *multi)
{
  return multi->peer_info;
}
#endif

/*
 * inline functions
 */

static inline bool
tls_initial_packet_received (const struct tls_multi *multi)
{
  return multi->n_sessions > 0;
}

static inline bool
tls_test_auth_deferred_interval (const struct tls_multi *multi)
{
  if (multi)
    {
      const struct key_state *ks = &multi->session[TM_ACTIVE].key[KS_PRIMARY];
      return now < ks->auth_deferred_expire;
    }
  return false;
}

static inline int
tls_test_payload_len (const struct tls_multi *multi)
{
  if (multi)
    {
      const struct key_state *ks = &multi->session[TM_ACTIVE].key[KS_PRIMARY];
      if (ks->state >= S_ACTIVE)
	return BLEN (&ks->plaintext_read_buf);
    }
  return 0;
}

static inline void
tls_set_single_session (struct tls_multi *multi)
{
  if (multi)
    multi->opt.single_session = true;
}

static inline const char *
tls_client_reason (struct tls_multi *multi)
{
#ifdef ENABLE_DEF_AUTH
  return multi->client_reason;
#else
  return NULL;
#endif
}

#ifdef ENABLE_PF

static inline bool
tls_common_name_hash (const struct tls_multi *multi, const char **cn, uint32_t *cn_hash)
{
  if (multi)
    {
      const struct tls_session *s = &multi->session[TM_ACTIVE];
      if (s->common_name && s->common_name[0] != '\0')
	{
	  *cn = s->common_name;
	  *cn_hash = s->common_name_hashval;
	  return true;
	}
    }
  return false;
}

#endif

/*
 * protocol_dump() flags
 */
#define PD_TLS_AUTH_HMAC_SIZE_MASK 0xFF
#define PD_SHOW_DATA               (1<<8)
#define PD_TLS                     (1<<9)
#define PD_VERBOSE                 (1<<10)

const char *protocol_dump (struct buffer *buffer,
			   unsigned int flags,
			   struct gc_arena *gc);

/*
 * debugging code
 */

#ifdef MEASURE_TLS_HANDSHAKE_STATS
void show_tls_performance_stats(void);
#endif

/*#define EXTRACT_X509_FIELD_TEST*/
void extract_x509_field_test (void);

#endif /* USE_CRYPTO && USE_SSL */

#endif
