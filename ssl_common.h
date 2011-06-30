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

  struct key_state_ssl ks_ssl;	/* contains SSL object and BIOs for the control channel */

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

  counter_type n_bytes;			 /* how many bytes sent/recvd since last key exchange */
  counter_type n_packets;		 /* how many packets sent/recvd since last key exchange */

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
  /* our master TLS context from which all SSL objects derived */
  struct tls_root_ctx ssl_ctx;

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

#endif /* SSL_COMMON_H_ */
