/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

/*
 * OpenVPN Protocol, taken from ssl.h in OpenVPN source code.
 *
 * TCP/UDP Packet:  This represents the top-level encapsulation.
 *
 * TCP/UDP packet format:
 *
 *   Packet length (16 bits, unsigned) -- TCP only, always sent as
 *       plaintext.  Since TCP is a stream protocol, the packet
 *       length words define the packetization of the stream.
 *
 *   Packet opcode/key_id (8 bits) -- TLS only, not used in
 *       pre-shared secret mode.
 *            packet message type, a P_* constant (high 5 bits)
 *            key_id (low 3 bits, see key_id in struct tls_session
 *              below for comment).  The key_id refers to an
 *              already negotiated TLS session.  OpenVPN seamlessly
 *              renegotiates the TLS session by using a new key_id
 *              for the new session.  Overlap (controlled by
 *              user definable parameters) between old and new TLS
 *              sessions is allowed, providing a seamless transition
 *              during tunnel operation.
 *
 *   Payload (n bytes), which may be a P_CONTROL, P_ACK, or P_DATA
 *       message.
 *
 * Message types:
 *
 *  P_CONTROL_HARD_RESET_CLIENT_V1 -- Key method 1, initial key from
 *    client, forget previous state.
 *
 *  P_CONTROL_HARD_RESET_SERVER_V1 -- Key method 2, initial key
 *    from server, forget previous state.
 *
 *  P_CONTROL_SOFT_RESET_V1 -- New key, with a graceful transition
 *    from old to new key in the sense that a transition window
 *    exists where both the old or new key_id can be used.  OpenVPN
 *    uses two different forms of key_id.  The first form is 64 bits
 *    and is used for all P_CONTROL messages.  P_DATA messages on the
 *    other hand use a shortened key_id of 3 bits for efficiency
 *    reasons since the vast majority of OpenVPN packets in an
 *    active tunnel will be P_DATA messages.  The 64 bit form
 *    is referred to as a session_id, while the 3 bit form is
 *    referred to as a key_id.
 *
 *  P_CONTROL_V1 -- Control channel packet (usually TLS ciphertext).
 *
 *  P_ACK_V1 -- Acknowledgement for P_CONTROL packets received.
 *
 *  P_DATA_V1 -- Data channel packet containing actual tunnel data
 *    ciphertext.
 *
 *  P_CONTROL_HARD_RESET_CLIENT_V2 -- Key method 2, initial key from
 *   client, forget previous state.
 *
 *  P_CONTROL_HARD_RESET_SERVER_V2 -- Key method 2, initial key from
 *   server, forget previous state.
 *
 * P_CONTROL* and P_ACK Payload:  The P_CONTROL message type
 * indicates a TLS ciphertext packet which has been encapsulated
 * inside of a reliability layer.  The reliability layer is
 * implemented as a straightforward ACK and retransmit model.
 *
 * P_CONTROL message format:
 *
 *   local session_id (random 64 bit value to identify TLS session).
 *   HMAC signature of entire encapsulation header for integrity
 *       check if --tls-auth is specified (usually 16 or 20 bytes).
 *   packet-id for replay protection (4 or 8 bytes, includes
 *       sequence number and optional time_t timestamp).
 *   P_ACK packet_id array length (1 byte).
 *   P_ACK packet-id array (if length > 0).
 *   P_ACK remote session_id (if length > 0).
 *   message packet-id (4 bytes).
 *   TLS payload ciphertext (n bytes) (only for P_CONTROL).
 *
 * Once the TLS session has been initialized and authenticated,
 * the TLS channel is used to exchange random key material for
 * bidirectional cipher and HMAC keys which will be
 * used to secure actual tunnel packets.  OpenVPN currently
 * implements two key methods.  Key method 1 directly
 * derives keys using random bits obtained from the RAND_bytes
 * OpenSSL function.  Key method 2 mixes random key material
 * from both sides of the connection using the TLS PRF mixing
 * function.  Key method 2 is the preferred method and is the default
 * for OpenVPN 2.0.
 * 
 * TLS plaintext content:
 *
 * TLS plaintext packet (if key_method == 1):
 *
 *   Cipher key length in bytes (1 byte).
 *   Cipher key (n bytes).
 *   HMAC key length in bytes (1 byte).
 *   HMAC key (n bytes).
 *   Options string (n bytes, null terminated, client/server options
 *       string should match).
 *
 * TLS plaintext packet (if key_method == 2):
 *
 *   Literal 0 (4 bytes).
 *   key_method type (1 byte).
 *   key_source structure (pre_master only defined for client ->
 *       server).
 *   options_string_length, including null (2 bytes).
 *   Options string (n bytes, null terminated, client/server options
 *       string must match).
 *   [The username/password data below is optional, record can end
 *       at this point.]
 *   username_string_length, including null (2 bytes).
 *   Username string (n bytes, null terminated).
 *   password_string_length, including null (2 bytes).
 *   Password string (n bytes, null terminated).
 *
 * The P_DATA payload represents encrypted, encapsulated tunnel
 * packets which tend to be either IP packets or Ethernet frames.
 * This is essentially the "payload" of the VPN.
 *
 * P_DATA message content:
 *   HMAC of ciphertext IV + ciphertext (if not disabled by
 *       --auth none).
 *   Ciphertext IV (size is cipher-dependent, if not disabled by
 *       --no-iv).
 *   Tunnel packet ciphertext.
 *
 * P_DATA plaintext
 *   packet_id (4 or 8 bytes, if not disabled by --no-replay).
 *       In SSL/TLS mode, 4 bytes are used because the implementation
 *       can force a TLS renegotation before 2^32 packets are sent.
 *       In pre-shared key mode, 8 bytes are used (sequence number
 *       and time_t value) to allow long-term key usage without
 *       packet_id collisions.
 *   User plaintext (n bytes).
 *
 * Notes:
 *   (1) ACK messages can be encoded in either the dedicated
 *       P_ACK record or they can be prepended to a P_CONTROL message.
 *   (2) P_DATA and P_CONTROL/P_ACK use independent packet-id
 *       sequences because P_DATA is an unreliable channel while
 *       P_CONTROL/P_ACK is a reliable channel.  Each use their
 *       own independent HMAC keys.
 *   (3) Note that when --tls-auth is used, all message types are
 *       protected with an HMAC signature, even the initial packets
 *       of the TLS handshake.  This makes it easy for OpenVPN to
 *       throw away bogus packets quickly, without wasting resources
 *       on attempting a TLS handshake which will ultimately fail.
 */

/* Used in the TLS PRF function */
#define KEY_EXPANSION_ID "OpenVPN"

/* passwords */
#define UP_TYPE_AUTH        "Auth"
#define UP_TYPE_PRIVATE_KEY "Private Key"

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

/* key negotiation states */
#define S_ERROR          -1
#define S_UNDEF           0
#define S_INITIAL         1	/* tls_init() was called */
#define S_PRE_START       2	/* waiting for initial reset & acknowledgement */
#define S_START           3	/* ready to exchange keys */
#define S_SENT_KEY        4	/* client does S_SENT_KEY -> S_GOT_KEY */
#define S_GOT_KEY         5	/* server does S_GOT_KEY -> S_SENT_KEY */
#define S_ACTIVE          6	/* ready to exchange data channel packets */
#define S_NORMAL_OP       7	/* normal operations */

/*
 * Are we ready to receive data channel packets?
 *
 * Also, if true, we can safely assume session has been
 * authenticated by TLS.
 *
 * NOTE: Assumes S_SENT_KEY + 1 == S_GOT_KEY.
 */
#define DECRYPT_KEY_ENABLED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))

/* Should we aggregate TLS acknowledgements, and tack them onto control packets? */
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
 * Key material, used as source for PRF-based
 * key expansion.
 */

struct key_source {
  uint8_t pre_master[48]; /* client generated */
  uint8_t random1[32];    /* generated by both client and server */
  uint8_t random2[32];    /* generated by both client and server */
};

struct key_source2 {
  struct key_source client;
  struct key_source server;
};

/*
 * Represents a single instantiation of a TLS negotiation and
 * data channel key exchange.  4 keys are kept: encrypt hmac,
 * decrypt hmac, encrypt cipher, and decrypt cipher.  The TLS
 * control channel is used to exchange these keys.
 * Each hard or soft reset will build
 * a fresh key_state.  Normally an openvpn session will contain two
 * key_state objects, one for the current TLS connection, and other
 * for the retiring or "lame duck" key.  The lame duck key_state is
 * used to maintain transmission continuity on the data-channel while
 * a key renegotiation is taking place.
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

  /* allow openvpn config info to be
     passed over control channel */
  bool pass_config_info;

  /* struct crypto_option flags */
  unsigned int crypto_flags_and;
  unsigned int crypto_flags_or;

  int replay_window;                   /* --replay-window parm */
  int replay_time;                     /* --replay-window parm */

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
  unsigned int ssl_flags;

#ifdef MANAGEMENT_DEF_AUTH
  struct man_def_auth_context *mda_context;
#endif

  /* --gremlin bits */
  int gremlin;
};

/* index into tls_session.key */
#define KS_PRIMARY    0		/* the primary key */
#define KS_LAME_DUCK  1		/* the key that's going to retire soon */
#define KS_SIZE       2

/*
 * A tls_session lives through multiple key_state life-cycles.  Soft resets
 * will reuse a tls_session object, but hard resets or errors will require
 * that a fresh object be built.  Normally three tls_session objects are maintained
 * by an active openvpn session.  The first is the current, TLS authenticated
 * session, the second is used to process connection requests from a new
 * client that would usurp the current session if successfully authenticated,
 * and the third is used as a repository for a "lame-duck" key in the event
 * that the primary session resets due to error while the lame-duck key still
 * has time left before its expiration.  Lame duck keys are used to maintain
 * the continuity of the data channel connection while a new key is being
 * negotiated.
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

/* index into tls_multi.session */
#define TM_ACTIVE    0
#define TM_UNTRUSTED 1
#define TM_LAME_DUCK 2
#define TM_SIZE      3

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

/*
 * An openvpn session running with TLS enabled has one tls_multi object.
 */
struct tls_multi
{
  /* const options and config info */
  struct tls_options opt;

  /*
   * A list of key_state objects in the order they should be
   * scanned by data channel encrypt and decrypt routines.
   */
  struct key_state* key_scan[KEY_SCAN_SIZE];

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

  /*
   * Number of sessions negotiated thus far.
   */
  int n_sessions;

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

/* Build master SSL_CTX object that serves for the whole of openvpn instantiation */
SSL_CTX *init_ssl (const struct options *options);

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

bool tls_pre_decrypt (struct tls_multi *multi,
		      const struct link_socket_actual *from,
		      struct buffer *buf,
		      struct crypto_options *opt);

bool tls_pre_decrypt_lite (const struct tls_auth_standalone *tas,
			   const struct link_socket_actual *from,
			   const struct buffer *buf);

void tls_pre_encrypt (struct tls_multi *multi,
		      struct buffer *buf, struct crypto_options *opt);

void tls_post_encrypt (struct tls_multi *multi, struct buffer *buf);

void show_available_tls_ciphers (void);
void get_highest_preference_tls_cipher (char *buf, int size);

void pem_password_setup (const char *auth_file);
int pem_password_callback (char *buf, int size, int rwflag, void *u);
void auth_user_pass_setup (const char *auth_file);
void ssl_set_auth_nocache (void);
void ssl_purge_auth (void);


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
