/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  Additions for eurephia plugin done by:
 *         David Sommerseth <dazo@users.sourceforge.net> Copyright (C) 2008-2009
 *
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

/*
 * The routines in this file deal with dynamically negotiating
 * the data channel HMAC and cipher keys through a TLS session.
 *
 * Both the TLS session and the data channel are multiplexed
 * over the same TCP/UDP port.
 */

#include "syshead.h"

#if defined(USE_CRYPTO) && defined(USE_SSL)

#include "ssl.h"
#include "error.h"
#include "common.h"
#include "integer.h"
#include "socket.h"
#include "misc.h"
#include "fdmisc.h"
#include "interval.h"
#include "perf.h"
#include "status.h"
#include "gremlin.h"
#include "pkcs11.h"
#include "list.h"

#ifdef WIN32
#include "cryptoapi.h"
#endif

#include "memdbg.h"

#ifndef ENABLE_OCC
static const char ssl_default_options_string[] = "V0 UNDEF";
#endif

static inline const char *
local_options_string (const struct tls_session *session)
{
#ifdef ENABLE_OCC
  return session->opt->local_options;
#else
  return ssl_default_options_string;
#endif
}

#ifdef MEASURE_TLS_HANDSHAKE_STATS

static int tls_handshake_success; /* GLOBAL */
static int tls_handshake_error;   /* GLOBAL */
static int tls_packets_generated; /* GLOBAL */
static int tls_packets_sent;      /* GLOBAL */

#define INCR_SENT       ++tls_packets_sent
#define INCR_GENERATED  ++tls_packets_generated
#define INCR_SUCCESS    ++tls_handshake_success
#define INCR_ERROR      ++tls_handshake_error

void
show_tls_performance_stats(void)
{
  msg (D_TLS_DEBUG_LOW, "TLS Handshakes, success=%f%% (good=%d, bad=%d), retransmits=%f%%",
       (double) tls_handshake_success / (tls_handshake_success + tls_handshake_error) * 100.0,
       tls_handshake_success, tls_handshake_error,
       (double) (tls_packets_sent - tls_packets_generated) / tls_packets_generated * 100.0);
}
#else

#define INCR_SENT
#define INCR_GENERATED
#define INCR_SUCCESS
#define INCR_ERROR

#endif

#ifdef BIO_DEBUG

#warning BIO_DEBUG defined

static FILE *biofp;                            /* GLOBAL */
static bool biofp_toggle;                      /* GLOBAL */
static time_t biofp_last_open;                 /* GLOBAL */
static const int biofp_reopen_interval = 600;  /* GLOBAL */

static void
close_biofp()
{
  if (biofp)
    {
      ASSERT (!fclose (biofp));
      biofp = NULL;
    }
}

static void
open_biofp()
{
  const time_t current = time (NULL);
  const pid_t pid = getpid ();

  if (biofp_last_open + biofp_reopen_interval < current)
    close_biofp();
  if (!biofp)
    {
      char fn[256];
      openvpn_snprintf(fn, sizeof(fn), "bio/%d-%d.log", pid, biofp_toggle);
      biofp = fopen (fn, "w");
      ASSERT (biofp);
      biofp_last_open = time (NULL);
      biofp_toggle ^= 1;
    }
}

static void
bio_debug_data (const char *mode, BIO *bio, const uint8_t *buf, int len, const char *desc)
{
  struct gc_arena gc = gc_new ();
  if (len > 0)
    {
      open_biofp();
      fprintf(biofp, "BIO_%s %s time=" time_format " bio=" ptr_format " len=%d data=%s\n",
	      mode, desc, time (NULL), (ptr_type)bio, len, format_hex (buf, len, 0, &gc));
      fflush (biofp);
    }
  gc_free (&gc);
}

static void
bio_debug_oc (const char *mode, BIO *bio)
{
  open_biofp();
  fprintf(biofp, "BIO %s time=" time_format " bio=" ptr_format "\n",
	  mode, time (NULL), (ptr_type)bio);
  fflush (biofp);
}

#endif

/*
 * Max number of bytes we will add
 * for data structures common to both
 * data and control channel packets.
 * (opcode only). 
 */
void
tls_adjust_frame_parameters(struct frame *frame)
{
  frame_add_to_extra_frame (frame, 1); /* space for opcode */
}

/*
 * Max number of bytes we will add
 * to control channel packet. 
 */
static void
tls_init_control_channel_frame_parameters(const struct frame *data_channel_frame,
					  struct frame *frame)
{
  /*
   * frame->extra_frame is already initialized with tls_auth buffer requirements,
   * if --tls-auth is enabled.
   */

  /* inherit link MTU and extra_link from data channel */
  frame->link_mtu = data_channel_frame->link_mtu;
  frame->extra_link = data_channel_frame->extra_link;

  /* set extra_frame */
  tls_adjust_frame_parameters (frame);
  reliable_ack_adjust_frame_parameters (frame, CONTROL_SEND_ACK_MAX);
  frame_add_to_extra_frame (frame, SID_SIZE + sizeof (packet_id_type));

  /* set dynamic link MTU to minimum value */
  frame_set_mtu_dynamic (frame, 0, SET_MTU_TUN);
}

/*
 * Allocate space in SSL objects
 * in which to store a struct tls_session
 * pointer back to parent.
 */

static int mydata_index; /* GLOBAL */

static void
ssl_set_mydata_index ()
{
  mydata_index = SSL_get_ex_new_index (0, "struct session *", NULL, NULL, NULL);
  ASSERT (mydata_index >= 0);
}

void
init_ssl_lib ()
{
  SSL_library_init ();
  SSL_load_error_strings ();
  OpenSSL_add_all_algorithms ();

  init_crypto_lib();

  /*
   * If you build the OpenSSL library and OpenVPN with
   * CRYPTO_MDEBUG, you will get a listing of OpenSSL
   * memory leaks on program termination.
   */
#ifdef CRYPTO_MDEBUG
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif

  ssl_set_mydata_index ();
}

void
free_ssl_lib ()
{
#ifdef CRYPTO_MDEBUG
  FILE* fp = fopen ("sdlog", "w");
  ASSERT (fp);
  CRYPTO_mem_leaks_fp (fp);
  fclose (fp);
#endif

  uninit_crypto_lib ();
  EVP_cleanup ();
  ERR_free_strings ();
}

/*
 * OpenSSL library calls pem_password_callback if the
 * private key is protected by a password.
 */

static struct user_pass passbuf; /* GLOBAL */

void
pem_password_setup (const char *auth_file)
{
  if (!strlen (passbuf.password))
    get_user_pass (&passbuf, auth_file, UP_TYPE_PRIVATE_KEY, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_SENSITIVE|GET_USER_PASS_PASSWORD_ONLY);
}

int
pem_password_callback (char *buf, int size, int rwflag, void *u)
{
  if (buf)
    {
      /* prompt for password even if --askpass wasn't specified */
      pem_password_setup (NULL);
      strncpynt (buf, passbuf.password, size);
      purge_user_pass (&passbuf, false);

      return strlen (buf);
    }
  return 0;
}

/*
 * Auth username/password handling
 */

static bool auth_user_pass_enabled;     /* GLOBAL */
static struct user_pass auth_user_pass; /* GLOBAL */

#ifdef ENABLE_CLIENT_CR
static char *auth_challenge; /* GLOBAL */
#endif

void
auth_user_pass_setup (const char *auth_file)
{
  auth_user_pass_enabled = true;
  if (!auth_user_pass.defined)
    {
#if AUTO_USERID
      get_user_pass_auto_userid (&auth_user_pass, auth_file);
#elif defined(ENABLE_CLIENT_CR)
      get_user_pass_cr (&auth_user_pass, auth_file, UP_TYPE_AUTH, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_SENSITIVE, auth_challenge);
#else
      get_user_pass (&auth_user_pass, auth_file, UP_TYPE_AUTH, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_SENSITIVE);
#endif
    }
}

/*
 * Disable password caching
 */
void
ssl_set_auth_nocache (void)
{
  passbuf.nocache = true;
  auth_user_pass.nocache = true;
}

/*
 * Forget private key password AND auth-user-pass username/password.
 */
void
ssl_purge_auth (void)
{
#ifdef USE_PKCS11
  pkcs11_logout ();
#endif
  purge_user_pass (&passbuf, true);
  purge_user_pass (&auth_user_pass, true);
#ifdef ENABLE_CLIENT_CR
  ssl_purge_auth_challenge();
#endif
}

#ifdef ENABLE_CLIENT_CR

void
ssl_purge_auth_challenge (void)
{
  free (auth_challenge);
  auth_challenge = NULL;
}

void
ssl_put_auth_challenge (const char *cr_str)
{
  ssl_purge_auth_challenge();
  auth_challenge = string_alloc(cr_str, NULL);
}

#endif

/*
 * OpenSSL callback to get a temporary RSA key, mostly
 * used for export ciphers.
 */
static RSA *
tmp_rsa_cb (SSL * s, int is_export, int keylength)
{
  static RSA *rsa_tmp = NULL;
  if (rsa_tmp == NULL)
    {
      msg (D_HANDSHAKE, "Generating temp (%d bit) RSA key", keylength);
      rsa_tmp = RSA_generate_key (keylength, RSA_F4, NULL, NULL);
    }
  return (rsa_tmp);
}

/*
 * Cert hash functions
 */
static void
cert_hash_remember (struct tls_session *session, const int error_depth, const unsigned char *sha1_hash)
{
  if (error_depth >= 0 && error_depth < MAX_CERT_DEPTH)
    {
      if (!session->cert_hash_set)
	ALLOC_OBJ_CLEAR (session->cert_hash_set, struct cert_hash_set);
      if (!session->cert_hash_set->ch[error_depth])
	ALLOC_OBJ (session->cert_hash_set->ch[error_depth], struct cert_hash);
      {
	struct cert_hash *ch = session->cert_hash_set->ch[error_depth];
	memcpy (ch->sha1_hash, sha1_hash, SHA_DIGEST_LENGTH);
      }
    }
}

#if 0
static void
cert_hash_print (const struct cert_hash_set *chs, int msglevel)
{
  struct gc_arena gc = gc_new ();
  msg (msglevel, "CERT_HASH");
  if (chs)
    {
      int i;
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	{
	  const struct cert_hash *ch = chs->ch[i];
	  if (ch)
	    msg (msglevel, "%d:%s", i, format_hex(ch->sha1_hash, SHA_DIGEST_LENGTH, 0, &gc));
	}
    }
  gc_free (&gc);
}
#endif

static void
cert_hash_free (struct cert_hash_set *chs)
{
  if (chs)
    {
      int i;
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	free (chs->ch[i]);
      free (chs);
    }
}

static bool
cert_hash_compare (const struct cert_hash_set *chs1, const struct cert_hash_set *chs2)
{
  if (chs1 && chs2)
    {
      int i;
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	{
	  const struct cert_hash *ch1 = chs1->ch[i];
	  const struct cert_hash *ch2 = chs2->ch[i];

	  if (!ch1 && !ch2)
	    continue;
	  else if (ch1 && ch2 && !memcmp (ch1->sha1_hash, ch2->sha1_hash, SHA_DIGEST_LENGTH))
	    continue;
	  else
	    return false;
	}
      return true;
    }
  else if (!chs1 && !chs2)
    return true;
  else
    return false;
}

static struct cert_hash_set *
cert_hash_copy (const struct cert_hash_set *chs)
{
  struct cert_hash_set *dest = NULL;
  if (chs)
    {
      int i;
      ALLOC_OBJ_CLEAR (dest, struct cert_hash_set);
      for (i = 0; i < MAX_CERT_DEPTH; ++i)
	{
	  const struct cert_hash *ch = chs->ch[i];
	  if (ch)
	    {
	      ALLOC_OBJ (dest->ch[i], struct cert_hash);
	      memcpy (dest->ch[i]->sha1_hash, ch->sha1_hash, SHA_DIGEST_LENGTH);
	    }
	}
    }
  return dest;
}

/*
 * Extract a field from an X509 subject name.
 *
 * Example:
 *
 * /C=US/ST=CO/L=Denver/O=ORG/CN=First-CN/CN=Test-CA/Email=jim@yonan.net
 *
 * The common name is 'Test-CA'
 *
 * Return true on success, false on error (insufficient buffer size in 'out'
 * to contain result is grounds for error).
 */
static bool
extract_x509_field_ssl (X509_NAME *x509, const char *field_name, char *out, int size)
{
  int lastpos = -1;
  int tmp = -1;
  X509_NAME_ENTRY *x509ne = 0;
  ASN1_STRING *asn1 = 0;
  unsigned char *buf = (unsigned char *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
  int nid = OBJ_txt2nid((char *)field_name);

  ASSERT (size > 0);
  *out = '\0';
  do {
    lastpos = tmp;
    tmp = X509_NAME_get_index_by_NID(x509, nid, lastpos);
  } while (tmp > -1);

  /* Nothing found */
  if (lastpos == -1)
    return false;

  x509ne = X509_NAME_get_entry(x509, lastpos);
  if (!x509ne)
    return false;

  asn1 = X509_NAME_ENTRY_get_data(x509ne);
  if (!asn1)
    return false;
  tmp = ASN1_STRING_to_UTF8(&buf, asn1);
  if (tmp <= 0)
    return false;

  strncpynt(out, (char *)buf, size);

  {
    const bool ret = (strlen ((char *)buf) < size);
    OPENSSL_free (buf);
    return ret;
  }
}

/*
 * Save X509 fields to environment, using the naming convention:
 *
 *  X509_{cert_depth}_{name}={value}
 */
static void
setenv_x509 (struct env_set *es, const int error_depth, X509_NAME *x509)
{
  int i, n;
  int fn_nid;
  ASN1_OBJECT *fn;
  ASN1_STRING *val;
  X509_NAME_ENTRY *ent;
  const char *objbuf;
  unsigned char *buf;
  char *name_expand;
  size_t name_expand_size;

  n = X509_NAME_entry_count (x509);
  for (i = 0; i < n; ++i)
    {
      ent = X509_NAME_get_entry (x509, i);
      if (!ent)
	continue;
      fn = X509_NAME_ENTRY_get_object (ent);
      if (!fn)
	continue;
      val = X509_NAME_ENTRY_get_data (ent);
      if (!val)
	continue;
      fn_nid = OBJ_obj2nid (fn);
      if (fn_nid == NID_undef)
	continue;
      objbuf = OBJ_nid2sn (fn_nid);
      if (!objbuf)
	continue;
      buf = (unsigned char *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
      if (ASN1_STRING_to_UTF8 (&buf, val) <= 0)
	continue;
      name_expand_size = 64 + strlen (objbuf);
      name_expand = (char *) malloc (name_expand_size);
      check_malloc_return (name_expand);
      openvpn_snprintf (name_expand, name_expand_size, "X509_%d_%s", error_depth, objbuf);
      string_mod (name_expand, CC_PRINT, CC_CRLF, '_');
      string_mod ((char*)buf, CC_PRINT, CC_CRLF, '_');
      setenv_str (es, name_expand, (char*)buf);
      free (name_expand);
      OPENSSL_free (buf);
    }
}

static void
setenv_untrusted (struct tls_session *session)
{
  setenv_link_socket_actual (session->opt->es, "untrusted", &session->untrusted_addr, SA_IP_PORT);
}

static void
set_common_name (struct tls_session *session, const char *common_name)
{
  if (session->common_name)
    {
      free (session->common_name);
      session->common_name = NULL;
#ifdef ENABLE_PF
      session->common_name_hashval = 0;
#endif
    }
  if (common_name)
    {
      session->common_name = string_alloc (common_name, NULL);
#ifdef ENABLE_PF
      {
	const uint32_t len = (uint32_t) strlen (common_name);
	if (len)
	  session->common_name_hashval = hash_func ((const uint8_t*)common_name, len+1, 0);
	else
	  session->common_name_hashval = 0;
      }
#endif
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x00907000L

bool verify_cert_eku (X509 *x509, const char * const expected_oid) {

	EXTENDED_KEY_USAGE *eku = NULL;
	bool fFound = false;

	if ((eku = (EXTENDED_KEY_USAGE *)X509_get_ext_d2i (x509, NID_ext_key_usage, NULL, NULL)) == NULL) {
		msg (D_HANDSHAKE, "Certificate does not have extended key usage extension");
	}
	else {
		int i;

		msg (D_HANDSHAKE, "Validating certificate extended key usage");
		for(i = 0; !fFound && i < sk_ASN1_OBJECT_num (eku); i++) {
			ASN1_OBJECT *oid = sk_ASN1_OBJECT_value (eku, i);
			char szOid[1024];

			if (!fFound && OBJ_obj2txt (szOid, sizeof (szOid), oid, 0) != -1) {
				msg (D_HANDSHAKE, "++ Certificate has EKU (str) %s, expects %s", szOid, expected_oid);
				if (!strcmp (expected_oid, szOid)) {
					fFound = true;
				}
			}
			if (!fFound && OBJ_obj2txt (szOid, sizeof (szOid), oid, 1) != -1) {
				msg (D_HANDSHAKE, "++ Certificate has EKU (oid) %s, expects %s", szOid, expected_oid);
				if (!strcmp (expected_oid, szOid)) {
					fFound = true;
				}
			}
		}
	}

	if (eku != NULL) {
		sk_ASN1_OBJECT_pop_free (eku, ASN1_OBJECT_free);
	}

	return fFound;
}

bool verify_cert_ku (X509 *x509, const unsigned * const expected_ku, int expected_len) {

	ASN1_BIT_STRING *ku = NULL;
	bool fFound = false;

	if ((ku = (ASN1_BIT_STRING *)X509_get_ext_d2i (x509, NID_key_usage, NULL, NULL)) == NULL) {
		msg (D_HANDSHAKE, "Certificate does not have key usage extension");
	}
	else {
		unsigned nku = 0;
		int i;
		for (i=0;i<8;i++) {
			if (ASN1_BIT_STRING_get_bit (ku, i)) {
				nku |= 1<<(7-i);
			}
		}

		/*
		 * Fixup if no LSB bits
		 */
		if ((nku & 0xff) == 0) {
			nku >>= 8;
		}

		msg (D_HANDSHAKE, "Validating certificate key usage");
		for (i=0;!fFound && i<expected_len;i++) {
			if (expected_ku[i] != 0) {
				msg (D_HANDSHAKE, "++ Certificate has key usage  %04x, expects %04x", nku, expected_ku[i]);

				if (nku == expected_ku[i]) {
					fFound = true;
				}
			}
		}
	}

	if (ku != NULL) {
		ASN1_BIT_STRING_free (ku);
	}

	return fFound;
}

#endif	/* OPENSSL_VERSION_NUMBER */

/*
 * nsCertType checking
 */

#define verify_nsCertType(x, usage) (((x)->ex_flags & EXFLAG_NSCERT) && ((x)->ex_nscert & (usage)))

static const char *
print_nsCertType (int type)
{
  switch (type)
    {
    case NS_SSL_SERVER:
      return "SERVER";
    case NS_SSL_CLIENT:
      return "CLIENT";
    default:
      return "?";
    }
}

static void
string_mod_sslname (char *str, const unsigned int restrictive_flags, const unsigned int ssl_flags)
{
  if (ssl_flags & SSLF_NO_NAME_REMAPPING)
    string_mod (str, CC_PRINT, CC_CRLF, '_');
  else
    string_mod (str, restrictive_flags, 0, '_');
}

/* Get peer cert and store it in pem format in a temporary file
 * in tmp_dir
 */

const char *
get_peer_cert(X509_STORE_CTX *ctx, const char *tmp_dir, struct gc_arena *gc)
{
  X509 *peercert;
  FILE *peercert_file;
  const char *peercert_filename="";

  if(!tmp_dir)
      return NULL;

  /* get peer cert */
  peercert = X509_STORE_CTX_get_current_cert(ctx);
  if(!peercert)
    {
      msg (M_ERR, "Unable to get peer certificate from current context");
      return NULL;
    }

  /* create tmp file to store peer cert */
  peercert_filename = create_temp_file (tmp_dir, "pcf", gc);

  /* write peer-cert in tmp-file */
  peercert_file = fopen(peercert_filename, "w+");
  if(!peercert_file)
    {
      msg (M_ERR, "Failed to open temporary file : %s", peercert_filename);
      return NULL;
    }
  if(PEM_write_X509(peercert_file,peercert)<0)
    {
      msg (M_ERR, "Failed to write peer certificate in PEM format");
      fclose(peercert_file);
      return NULL;
    }

  fclose(peercert_file);
  return peercert_filename;
}

char * x509_username_field; /* GLOBAL */

/*
 * Our verify callback function -- check
 * that an incoming peer certificate is good.
 */

static int
verify_callback (int preverify_ok, X509_STORE_CTX * ctx)
{
  char *subject = NULL;
  char envname[64];
  char common_name[TLS_USERNAME_LEN];
  SSL *ssl;
  struct tls_session *session;
  const struct tls_options *opt;
  const int max_depth = MAX_CERT_DEPTH;
  struct argv argv = argv_new ();

  /* get the tls_session pointer */
  ssl = X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  ASSERT (ssl);
  session = (struct tls_session *) SSL_get_ex_data (ssl, mydata_index);
  ASSERT (session);
  opt = session->opt;
  ASSERT (opt);

  session->verified = false;

  /* get the X509 name */
  subject = X509_NAME_oneline (X509_get_subject_name (ctx->current_cert), NULL, 0);
  if (!subject)
    {
      msg (D_TLS_ERRORS, "VERIFY ERROR: depth=%d, could not extract X509 subject string from certificate", ctx->error_depth);
      goto err;
    }

  /* Save X509 fields in environment */
  setenv_x509 (opt->es, ctx->error_depth, X509_get_subject_name (ctx->current_cert));

  /* enforce character class restrictions in X509 name */
  string_mod_sslname (subject, X509_NAME_CHAR_CLASS, opt->ssl_flags);
  string_replace_leading (subject, '-', '_');

  /* extract the username (default is CN) */
  if (!extract_x509_field_ssl (X509_get_subject_name (ctx->current_cert), x509_username_field, common_name, sizeof(common_name)))
    {
      if (!ctx->error_depth)
        {
          msg (D_TLS_ERRORS, "VERIFY ERROR: could not extract %s from X509 subject string ('%s') -- note that the username length is limited to %d characters",
                 x509_username_field,
                 subject,
                 TLS_USERNAME_LEN);
          goto err;
        }
    }


  string_mod_sslname (common_name, COMMON_NAME_CHAR_CLASS, opt->ssl_flags);

  cert_hash_remember (session, ctx->error_depth, ctx->current_cert->sha1_hash);

#if 0 /* print some debugging info */
  {
    struct gc_arena gc = gc_new ();
    msg (M_INFO, "LOCAL OPT[%d]: %s", ctx->error_depth, opt->local_options);
    msg (M_INFO, "X509[%d]: %s", ctx->error_depth, subject);
    msg (M_INFO, "SHA1[%d]: %s", ctx->error_depth, format_hex(ctx->current_cert->sha1_hash, SHA_DIGEST_LENGTH, 0, &gc));
    gc_free (&gc);
  }
#endif

  /* did peer present cert which was signed our root cert? */
  if (!preverify_ok)
    {
      /* Remote site specified a certificate, but it's not correct */
      msg (D_TLS_ERRORS, "VERIFY ERROR: depth=%d, error=%s: %s",
	   ctx->error_depth, X509_verify_cert_error_string (ctx->error), subject);
      goto err;			/* Reject connection */
    }

  /* warn if cert chain is too deep */
  if (ctx->error_depth >= max_depth)
    {
      msg (D_TLS_ERRORS, "TLS Error: Convoluted certificate chain detected with depth [%d] greater than %d", ctx->error_depth, max_depth);
      goto err;			/* Reject connection */
    }

  /* save common name in session object */
  if (ctx->error_depth == 0)
    set_common_name (session, common_name);

  /* export subject name string as environmental variable */
  session->verify_maxlevel = max_int (session->verify_maxlevel, ctx->error_depth);
  openvpn_snprintf (envname, sizeof(envname), "tls_id_%d", ctx->error_depth);
  setenv_str (opt->es, envname, subject);

#ifdef ENABLE_EUREPHIA
  /* export X509 cert SHA1 fingerprint */
  {
    struct gc_arena gc = gc_new ();
    openvpn_snprintf (envname, sizeof(envname), "tls_digest_%d", ctx->error_depth);
    setenv_str (opt->es, envname,
		format_hex_ex(ctx->current_cert->sha1_hash, SHA_DIGEST_LENGTH, 0, 1, ":", &gc));
    gc_free(&gc);
  }
#endif
#if 0
  /* export common name string as environmental variable */
  openvpn_snprintf (envname, sizeof(envname), "tls_common_name_%d", ctx->error_depth);
  setenv_str (opt->es, envname, common_name);
#endif

  /* export serial number as environmental variable */
  {
    BIO *bio = NULL;
    char serial[100];
    int n1, n2;

    CLEAR (serial);
    if ((bio = BIO_new (BIO_s_mem ())) == NULL)
      {
        msg (M_WARN, "CALLBACK: Cannot create BIO (for tls_serial_%d)", ctx->error_depth);
      }
    else
      {
        /* "prints" the serial number onto the BIO and read it back */
        if ( ! ( ( (n1 = i2a_ASN1_INTEGER(bio, X509_get_serialNumber (ctx->current_cert))) >= 0 ) &&
                 ( (n2 = BIO_read (bio, serial, sizeof (serial)-1)) >= 0 ) &&
                 ( n1 == n2 ) ) )
          {
            msg (M_WARN, "CALLBACK: Error reading/writing BIO (for tls_serial_%d)", ctx->error_depth);
            CLEAR (serial);     /* empty string */
          }

        openvpn_snprintf (envname, sizeof(envname), "tls_serial_%d", ctx->error_depth);
        setenv_str (opt->es, envname, serial);
        BIO_free(bio);
      }
  }

  /* export current untrusted IP */
  setenv_untrusted (session);

  /* verify certificate nsCertType */
  if (opt->ns_cert_type && ctx->error_depth == 0)
    {
      if (verify_nsCertType (ctx->current_cert, opt->ns_cert_type))
	{
	  msg (D_HANDSHAKE, "VERIFY OK: nsCertType=%s",
	       print_nsCertType (opt->ns_cert_type));
	}
      else
	{
	  msg (D_HANDSHAKE, "VERIFY nsCertType ERROR: %s, require nsCertType=%s",
	       subject, print_nsCertType (opt->ns_cert_type));
	  goto err;		/* Reject connection */
	}
    }

#if OPENSSL_VERSION_NUMBER >= 0x00907000L

  /* verify certificate ku */
  if (opt->remote_cert_ku[0] != 0 &&  ctx->error_depth == 0)
    {
      if (verify_cert_ku (ctx->current_cert, opt->remote_cert_ku, MAX_PARMS))
	{
	  msg (D_HANDSHAKE, "VERIFY KU OK");
	}
        else
        {
	  msg (D_HANDSHAKE, "VERIFY KU ERROR");
          goto err;		/* Reject connection */
	}
    }

  /* verify certificate eku */
  if (opt->remote_cert_eku != NULL && ctx->error_depth == 0)
    {
      if (verify_cert_eku (ctx->current_cert, opt->remote_cert_eku))
        {
	  msg (D_HANDSHAKE, "VERIFY EKU OK");
	}
      else
	{
	  msg (D_HANDSHAKE, "VERIFY EKU ERROR");
          goto err;		/* Reject connection */
	}
    }

#endif	/* OPENSSL_VERSION_NUMBER */

  /* verify X509 name or common name against --tls-remote */
  if (opt->verify_x509name && strlen (opt->verify_x509name) > 0 && ctx->error_depth == 0)
    {
      if (strcmp (opt->verify_x509name, subject) == 0
	  || strncmp (opt->verify_x509name, common_name, strlen (opt->verify_x509name)) == 0)
	msg (D_HANDSHAKE, "VERIFY X509NAME OK: %s", subject);
      else
	{
	  msg (D_HANDSHAKE, "VERIFY X509NAME ERROR: %s, must be %s",
	       subject, opt->verify_x509name);
	  goto err;		/* Reject connection */
	}
    }

  /* call --tls-verify plug-in(s) */
  if (plugin_defined (opt->plugins, OPENVPN_PLUGIN_TLS_VERIFY))
    {
      int ret;

      argv_printf (&argv, "%d %s",
		   ctx->error_depth,
		   subject);

      ret = plugin_call (opt->plugins, OPENVPN_PLUGIN_TLS_VERIFY, &argv, NULL, opt->es);

      if (ret == OPENVPN_PLUGIN_FUNC_SUCCESS)
	{
	  msg (D_HANDSHAKE, "VERIFY PLUGIN OK: depth=%d, %s",
	       ctx->error_depth, subject);
	}
      else
	{
	  msg (D_HANDSHAKE, "VERIFY PLUGIN ERROR: depth=%d, %s",
	       ctx->error_depth, subject);
	  goto err;		/* Reject connection */
	}
    }

  /* run --tls-verify script */
  if (opt->verify_command)
    {
      const char *tmp_file = NULL;
      struct gc_arena gc;
      int ret;

      setenv_str (opt->es, "script_type", "tls-verify");

      if (opt->verify_export_cert)
        {
          gc = gc_new();
          if ((tmp_file=get_peer_cert(ctx, opt->verify_export_cert,&gc)))
           {
             setenv_str(opt->es, "peer_cert", tmp_file);
           }
        }

      argv_printf (&argv, "%sc %d %s",
		   opt->verify_command,
		   ctx->error_depth,
		   subject);
      argv_msg_prefix (D_TLS_DEBUG, &argv, "TLS: executing verify command");
      ret = openvpn_run_script (&argv, opt->es, 0, "--tls-verify script");

      if (opt->verify_export_cert)
        {
           if (tmp_file)
              delete_file(tmp_file);
           gc_free(&gc);
        }

      if (ret)
	{
	  msg (D_HANDSHAKE, "VERIFY SCRIPT OK: depth=%d, %s",
	       ctx->error_depth, subject);
	}
      else
	{
	  msg (D_HANDSHAKE, "VERIFY SCRIPT ERROR: depth=%d, %s",
	       ctx->error_depth, subject);
	  goto err;		/* Reject connection */
	}
    }

  /* check peer cert against CRL */
  if (opt->crl_file)
    {
      X509_CRL *crl=NULL;
      X509_REVOKED *revoked;
      BIO *in=NULL;
      int n,i,retval = 0;

      in=BIO_new(BIO_s_file());

      if (in == NULL) {
	msg (M_ERR, "CRL: BIO err");
	goto end;
      }
      if (BIO_read_filename(in, opt->crl_file) <= 0) {
	msg (M_ERR, "CRL: cannot read: %s", opt->crl_file);
	goto end;
      }
      crl=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
      if (crl == NULL) {
	msg (M_ERR, "CRL: cannot read CRL from file %s", opt->crl_file);
	goto end;
      }

      if (X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_issuer_name(ctx->current_cert)) != 0) {
	msg (M_WARN, "CRL: CRL %s is from a different issuer than the issuer of certificate %s", opt->crl_file, subject);
	retval = 1;
	goto end;
      }

      n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));

      for (i = 0; i < n; i++) {
	revoked = (X509_REVOKED *)sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
	if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(ctx->current_cert)) == 0) {
	  msg (D_HANDSHAKE, "CRL CHECK FAILED: %s is REVOKED",subject);
	  goto end;
	}
      }

      retval = 1;
      msg (D_HANDSHAKE, "CRL CHECK OK: %s",subject);

    end:

      BIO_free(in);
      if (crl)
	X509_CRL_free (crl);
      if (!retval)
	goto err;
    }

  msg (D_HANDSHAKE, "VERIFY OK: depth=%d, %s", ctx->error_depth, subject);

  session->verified = true;
  OPENSSL_free (subject);
  argv_reset (&argv);
  return 1;			/* Accept connection */

 err:
  ERR_clear_error ();
  OPENSSL_free (subject);
  argv_reset (&argv);
  return 0;                     /* Reject connection */
}

void
tls_set_common_name (struct tls_multi *multi, const char *common_name)
{
  if (multi)
    set_common_name (&multi->session[TM_ACTIVE], common_name);
}

const char *
tls_common_name (const struct tls_multi *multi, const bool null)
{
  const char *ret = NULL;
  if (multi)
    ret = multi->session[TM_ACTIVE].common_name;
  if (ret && strlen (ret))
    return ret;
  else if (null)
    return NULL;
  else
    return "UNDEF";
}

void
tls_lock_common_name (struct tls_multi *multi)
{
  const char *cn = multi->session[TM_ACTIVE].common_name;
  if (cn && !multi->locked_cn)
    multi->locked_cn = string_alloc (cn, NULL);
}

void
tls_lock_cert_hash_set (struct tls_multi *multi)
{
  const struct cert_hash_set *chs = multi->session[TM_ACTIVE].cert_hash_set;
  if (chs && !multi->locked_cert_hash_set)
    multi->locked_cert_hash_set = cert_hash_copy (chs);
}

static bool
tls_lock_username (struct tls_multi *multi, const char *username)
{
  if (multi->locked_username)
    {
      if (!username || strcmp (username, multi->locked_username))
	{
	  msg (D_TLS_ERRORS, "TLS Auth Error: username attempted to change from '%s' to '%s' -- tunnel disabled",
	       multi->locked_username,
	       np(username));

	  /* disable the tunnel */
	  tls_deauthenticate (multi);
	  return false;
	}
    }
  else
    {
      if (username)
	multi->locked_username = string_alloc (username, NULL);
    }
  return true;
}

#ifdef ENABLE_DEF_AUTH
/* key_state_test_auth_control_file return values,
   NOTE: acf_merge indexing depends on these values */
#define ACF_UNDEFINED 0
#define ACF_SUCCEEDED 1
#define ACF_DISABLED  2
#define ACF_FAILED    3
#endif

#ifdef MANAGEMENT_DEF_AUTH
static void
man_def_auth_set_client_reason (struct tls_multi *multi, const char *client_reason)
{
  if (multi->client_reason)
    {
      free (multi->client_reason);
      multi->client_reason = NULL;
    }
  if (client_reason && strlen (client_reason))
    multi->client_reason = string_alloc (client_reason, NULL);
}

static inline unsigned int
man_def_auth_test (const struct key_state *ks)
{
  if (management_enable_def_auth (management))
    return ks->mda_status;
  else
    return ACF_DISABLED;
}
#endif

#ifdef PLUGIN_DEF_AUTH

/*
 * auth_control_file functions
 */

static void
key_state_rm_auth_control_file (struct key_state *ks)
{
  if (ks && ks->auth_control_file)
    {
      delete_file (ks->auth_control_file);
      free (ks->auth_control_file);
      ks->auth_control_file = NULL;
    }
}

static void
key_state_gen_auth_control_file (struct key_state *ks, const struct tls_options *opt)
{
  struct gc_arena gc = gc_new ();
  const char *acf;

  key_state_rm_auth_control_file (ks);
  acf = create_temp_file (opt->tmp_dir, "acf", &gc);
  if( acf ) {
    ks->auth_control_file = string_alloc (acf, NULL);
    setenv_str (opt->es, "auth_control_file", ks->auth_control_file);
  } /* FIXME: Should have better error handling? */
  gc_free (&gc);					  
}

static unsigned int
key_state_test_auth_control_file (struct key_state *ks)
{
  if (ks && ks->auth_control_file)
    {
      unsigned int ret = ks->auth_control_status;
      if (ret == ACF_UNDEFINED)
	{
	  FILE *fp = fopen (ks->auth_control_file, "r");
	  if (fp)
	    {
	      const int c = fgetc (fp);
	      if (c == '1')
		ret = ACF_SUCCEEDED;
	      else if (c == '0')
		ret = ACF_FAILED;
	      fclose (fp);
	      ks->auth_control_status = ret;
	    }
	}
      return ret;
    }
  return ACF_DISABLED;
}

#endif

/*
 * Return current session authentication state.  Return
 * value is TLS_AUTHENTICATION_x.
 */

int
tls_authentication_status (struct tls_multi *multi, const int latency)
{
  bool deferred = false;
  bool success = false;
  bool active = false;

#ifdef ENABLE_DEF_AUTH
  static const unsigned char acf_merge[] =
    {
      ACF_UNDEFINED, /* s1=ACF_UNDEFINED s2=ACF_UNDEFINED */
      ACF_UNDEFINED, /* s1=ACF_UNDEFINED s2=ACF_SUCCEEDED */
      ACF_UNDEFINED, /* s1=ACF_UNDEFINED s2=ACF_DISABLED */
      ACF_FAILED,    /* s1=ACF_UNDEFINED s2=ACF_FAILED */
      ACF_UNDEFINED, /* s1=ACF_SUCCEEDED s2=ACF_UNDEFINED */
      ACF_SUCCEEDED, /* s1=ACF_SUCCEEDED s2=ACF_SUCCEEDED */
      ACF_SUCCEEDED, /* s1=ACF_SUCCEEDED s2=ACF_DISABLED */
      ACF_FAILED,    /* s1=ACF_SUCCEEDED s2=ACF_FAILED */
      ACF_UNDEFINED, /* s1=ACF_DISABLED  s2=ACF_UNDEFINED */
      ACF_SUCCEEDED, /* s1=ACF_DISABLED  s2=ACF_SUCCEEDED */
      ACF_DISABLED,  /* s1=ACF_DISABLED  s2=ACF_DISABLED */
      ACF_FAILED,    /* s1=ACF_DISABLED  s2=ACF_FAILED */
      ACF_FAILED,    /* s1=ACF_FAILED    s2=ACF_UNDEFINED */
      ACF_FAILED,    /* s1=ACF_FAILED    s2=ACF_SUCCEEDED */
      ACF_FAILED,    /* s1=ACF_FAILED    s2=ACF_DISABLED */
      ACF_FAILED     /* s1=ACF_FAILED    s2=ACF_FAILED */
    };
#endif

  if (multi)
    {
      int i;

#ifdef ENABLE_DEF_AUTH
      if (latency && multi->tas_last && multi->tas_last + latency >= now)
	return TLS_AUTHENTICATION_UNDEFINED;
      multi->tas_last = now;
#endif

      for (i = 0; i < KEY_SCAN_SIZE; ++i)
	{
	  struct key_state *ks = multi->key_scan[i];
	  if (DECRYPT_KEY_ENABLED (multi, ks))
	    {
	      active = true;
	      if (ks->authenticated)
		{
#ifdef ENABLE_DEF_AUTH
		  unsigned int s1 = ACF_DISABLED;
		  unsigned int s2 = ACF_DISABLED;
#ifdef PLUGIN_DEF_AUTH
		  s1 = key_state_test_auth_control_file (ks); 
#endif
#ifdef MANAGEMENT_DEF_AUTH
		  s2 = man_def_auth_test (ks);
#endif
		  ASSERT (s1 < 4 && s2 < 4);
		  switch (acf_merge[(s1<<2) + s2])
		    {
		    case ACF_SUCCEEDED:
		    case ACF_DISABLED:
		      success = true;
		      ks->auth_deferred = false;
		      break;
		    case ACF_UNDEFINED:
		      if (now < ks->auth_deferred_expire)
			deferred = true;
		      break;
		    case ACF_FAILED:
		      ks->authenticated = false;
		      break;
		    default:
		      ASSERT (0);
		    }
#else
		  success = true;
#endif
		}
	    }
	}
    }

#if 0
  dmsg (D_TLS_ERRORS, "TAS: a=%d s=%d d=%d", active, success, deferred);
#endif

  if (success)
    return TLS_AUTHENTICATION_SUCCEEDED;
  else if (!active || deferred)
    return TLS_AUTHENTICATION_DEFERRED;
  else
    return TLS_AUTHENTICATION_FAILED;
}

#ifdef MANAGEMENT_DEF_AUTH
/*
 * For deferred auth, this is where the management interface calls (on server)
 * to indicate auth failure/success.
 */
bool
tls_authenticate_key (struct tls_multi *multi, const unsigned int mda_key_id, const bool auth, const char *client_reason)
{
  bool ret = false;
  if (multi)
    {
      int i;
      man_def_auth_set_client_reason (multi, client_reason);
      for (i = 0; i < KEY_SCAN_SIZE; ++i)
	{
	  struct key_state *ks = multi->key_scan[i];
	  if (ks->mda_key_id == mda_key_id)
	    {
	      ks->mda_status = auth ? ACF_SUCCEEDED : ACF_FAILED;
	      ret = true;
	    }
	}
    }
  return ret;
}
#endif

void
tls_deauthenticate (struct tls_multi *multi)
{
  if (multi)
    {
      int i, j;
      for (i = 0; i < TM_SIZE; ++i)
	for (j = 0; j < KS_SIZE; ++j)
	  multi->session[i].key[j].authenticated = false;
    }
}

/*
 * Print debugging information on SSL/TLS session negotiation.
 */
static void
info_callback (INFO_CALLBACK_SSL_CONST SSL * s, int where, int ret)
{
  if (where & SSL_CB_LOOP)
    {
      dmsg (D_HANDSHAKE_VERBOSE, "SSL state (%s): %s",
	   where & SSL_ST_CONNECT ? "connect" :
	   where & SSL_ST_ACCEPT ? "accept" :
	   "undefined", SSL_state_string_long (s));
    }
  else if (where & SSL_CB_ALERT)
    {
      dmsg (D_HANDSHAKE_VERBOSE, "SSL alert (%s): %s: %s",
	   where & SSL_CB_READ ? "read" : "write",
	   SSL_alert_type_string_long (ret),
	   SSL_alert_desc_string_long (ret));
    }
}

#if ENABLE_INLINE_FILES

static int
use_inline_load_verify_locations (SSL_CTX *ctx, const char *ca_string)
{
  X509_STORE *store = NULL;
  X509* cert = NULL;
  BIO *in = NULL;
  int ret = 0;

  in = BIO_new_mem_buf ((char *)ca_string, -1);
  if (!in)
    goto err;

  for (;;)
    {
      if (!PEM_read_bio_X509 (in, &cert, 0, NULL))
	{
	  ret = 1;
	  break;
	}
      if (!cert)
	break;

      store = SSL_CTX_get_cert_store (ctx);
      if (!store)
	break;

      if (!X509_STORE_add_cert (store, cert))
	break;

      if (cert)
	{
	  X509_free (cert);
	  cert = NULL;
	}
    }

 err:
  if (cert)
    X509_free (cert);
  if (in)
    BIO_free (in);
  return ret;  
}

static int
xname_cmp(const X509_NAME * const *a, const X509_NAME * const *b)
{
  return(X509_NAME_cmp(*a,*b));
}

static STACK_OF(X509_NAME) *
use_inline_load_client_CA_file (SSL_CTX *ctx, const char *ca_string)
{
  BIO *in = NULL;
  X509 *x = NULL;
  X509_NAME *xn = NULL;
  STACK_OF(X509_NAME) *ret = NULL, *sk;

  sk=sk_X509_NAME_new(xname_cmp);

  in = BIO_new_mem_buf ((char *)ca_string, -1);
  if (!in)
    goto err;

  if ((sk == NULL) || (in == NULL))
    goto err;
	
  for (;;)
    {
      if (PEM_read_bio_X509(in,&x,NULL,NULL) == NULL)
	break;
      if (ret == NULL)
	{
	  ret = sk_X509_NAME_new_null();
	  if (ret == NULL)
	    goto err;
	}
      if ((xn=X509_get_subject_name(x)) == NULL) goto err;
      /* check for duplicates */
      xn=X509_NAME_dup(xn);
      if (xn == NULL) goto err;
      if (sk_X509_NAME_find(sk,xn) >= 0)
	X509_NAME_free(xn);
      else
	{
	  sk_X509_NAME_push(sk,xn);
	  sk_X509_NAME_push(ret,xn);
	}
    }

  if (0)
    {
    err:
      if (ret != NULL) sk_X509_NAME_pop_free(ret,X509_NAME_free);
      ret=NULL;
    }
  if (sk != NULL) sk_X509_NAME_free(sk);
  if (in != NULL) BIO_free(in);
  if (x != NULL) X509_free(x);
  if (ret != NULL)
    ERR_clear_error();
  return(ret);
}

static int
use_inline_certificate_file (SSL_CTX *ctx, const char *cert_string)
{
  BIO *in = NULL;
  X509 *x = NULL;
  int ret = 0;

  in = BIO_new_mem_buf ((char *)cert_string, -1);
  if (!in)
    goto end;

  x = PEM_read_bio_X509 (in,
			 NULL,
			 ctx->default_passwd_callback,
			 ctx->default_passwd_callback_userdata);
  if (!x)
    goto end;

  ret = SSL_CTX_use_certificate(ctx, x);

 end:
  if (x)
    X509_free (x);
  if (in)
    BIO_free (in);
  return ret;
}

static int
use_inline_PrivateKey_file (SSL_CTX *ctx, const char *key_string)
{
  BIO *in = NULL;
  EVP_PKEY *pkey = NULL;
  int ret = 0;

  in = BIO_new_mem_buf ((char *)key_string, -1);
  if (!in)
    goto end;

  pkey = PEM_read_bio_PrivateKey (in,
				  NULL,
				  ctx->default_passwd_callback,
				  ctx->default_passwd_callback_userdata);
  if (!pkey)
    goto end;

  ret = SSL_CTX_use_PrivateKey (ctx, pkey);

 end:
  if (pkey)
    EVP_PKEY_free (pkey);
  if (in)
    BIO_free (in);
  return ret;
}

#endif

/*
 * Initialize SSL context.
 * All files are in PEM format.
 */
SSL_CTX *
init_ssl (const struct options *options)
{
  SSL_CTX *ctx = NULL;
  DH *dh;
  BIO *bio;
  bool using_cert_file = false;

  ERR_clear_error ();

  if (options->tls_server)
    {
      ctx = SSL_CTX_new (TLSv1_server_method ());
      if (ctx == NULL)
	msg (M_SSLERR, "SSL_CTX_new TLSv1_server_method");

      SSL_CTX_set_tmp_rsa_callback (ctx, tmp_rsa_cb);

#if ENABLE_INLINE_FILES
      if (!strcmp (options->dh_file, INLINE_FILE_TAG) && options->dh_file_inline)
	{
	  if (!(bio = BIO_new_mem_buf ((char *)options->dh_file_inline, -1)))
	    msg (M_SSLERR, "Cannot open memory BIO for inline DH parameters");
	}
      else
#endif
	{
	  /* Get Diffie Hellman Parameters */
	  if (!(bio = BIO_new_file (options->dh_file, "r")))
	    msg (M_SSLERR, "Cannot open %s for DH parameters", options->dh_file);
	}

      dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
      BIO_free (bio);
      if (!dh)
	msg (M_SSLERR, "Cannot load DH parameters from %s", options->dh_file);
      if (!SSL_CTX_set_tmp_dh (ctx, dh))
	msg (M_SSLERR, "SSL_CTX_set_tmp_dh");
      msg (D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with %d bit key",
	   8 * DH_size (dh));
      DH_free (dh);
    }
  else				/* if client */
    {
      ctx = SSL_CTX_new (TLSv1_client_method ());
      if (ctx == NULL)
	msg (M_SSLERR, "SSL_CTX_new TLSv1_client_method");
    }

  /* Set SSL options */
  SSL_CTX_set_session_cache_mode (ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options (ctx, SSL_OP_SINGLE_DH_USE);

  /* Set callback for getting password from user to decrypt private key */
  SSL_CTX_set_default_passwd_cb (ctx, pem_password_callback);

  if (options->pkcs12_file)
    {
      /* Use PKCS #12 file for key, cert and CA certs */

      FILE *fp;
      EVP_PKEY *pkey;
      X509 *cert;
      STACK_OF(X509) *ca = NULL;
      PKCS12 *p12=NULL;
      int i;
      char password[256];

#if ENABLE_INLINE_FILES
      if (!strcmp (options->pkcs12_file, INLINE_FILE_TAG) && options->pkcs12_file_inline)
	{
	  BIO *b64 = BIO_new (BIO_f_base64());
	  BIO *bio = BIO_new_mem_buf ((void *)options->pkcs12_file_inline, (int)strlen(options->pkcs12_file_inline));
	  ASSERT(b64 && bio);
	  BIO_push (b64, bio);
	  p12 = d2i_PKCS12_bio(b64, NULL);
	  if (!p12)
	    msg (M_SSLERR, "Error reading inline PKCS#12 file");
	  BIO_free (b64);
	  BIO_free (bio);
	}
      else
#endif
	{
	  /* Load the PKCS #12 file */
	  if (!(fp = fopen(options->pkcs12_file, "rb")))
	    msg (M_SSLERR, "Error opening file %s", options->pkcs12_file);
	  p12 = d2i_PKCS12_fp(fp, NULL);
	  fclose (fp);
	  if (!p12)
	    msg (M_SSLERR, "Error reading PKCS#12 file %s", options->pkcs12_file);
	}

      /* Parse the PKCS #12 file */
      if (!PKCS12_parse(p12, "", &pkey, &cert, &ca))
        {
          pem_password_callback (password, sizeof(password) - 1, 0, NULL);
          /* Reparse the PKCS #12 file with password */
          ca = NULL;
          if (!PKCS12_parse(p12, password, &pkey, &cert, &ca))
	    {
#ifdef ENABLE_MANAGEMENT
	      if (management && (ERR_GET_REASON (ERR_peek_error()) == PKCS12_R_MAC_VERIFY_FAILURE))
		management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
	      PKCS12_free(p12);
	      msg (M_INFO, "OpenSSL ERROR code: %d", (ERR_GET_REASON (ERR_peek_error()))); // fixme
	      goto err;
	    }
        }
      PKCS12_free(p12);

      /* Load Certificate */
      if (!SSL_CTX_use_certificate (ctx, cert))
        msg (M_SSLERR, "Cannot use certificate");

      /* Load Private Key */
      if (!SSL_CTX_use_PrivateKey (ctx, pkey))
        msg (M_SSLERR, "Cannot use private key");
      warn_if_group_others_accessible (options->pkcs12_file);

      /* Check Private Key */
      if (!SSL_CTX_check_private_key (ctx))
        msg (M_SSLERR, "Private key does not match the certificate");

      /* Set Certificate Verification chain */
      if (!options->ca_file)
        {
          if (ca && sk_X509_num(ca))
            {
              for (i = 0; i < sk_X509_num(ca); i++)
                {
	          if (!X509_STORE_add_cert(ctx->cert_store,sk_X509_value(ca, i)))
                    msg (M_SSLERR, "Cannot add certificate to certificate chain (X509_STORE_add_cert)");
                  if (!SSL_CTX_add_client_CA(ctx, sk_X509_value(ca, i)))
                    msg (M_SSLERR, "Cannot add certificate to client CA list (SSL_CTX_add_client_CA)");
                }
            }
        }
    }
  else
    {
      /* Use seperate PEM files for key, cert and CA certs */

#ifdef ENABLE_PKCS11
      if (options->pkcs11_providers[0])
        {
         /* Load Certificate and Private Key */
	 if (!SSL_CTX_use_pkcs11 (ctx, options->pkcs11_id_management, options->pkcs11_id))
	   {
	     msg (M_WARN, "Cannot load certificate \"%s\" using PKCS#11 interface", options->pkcs11_id);
	     goto err;
	   }
        }
      else
#endif

#ifdef WIN32
      if (options->cryptoapi_cert)
	{
	  /* Load Certificate and Private Key */
	  if (!SSL_CTX_use_CryptoAPI_certificate (ctx, options->cryptoapi_cert))
	    msg (M_SSLERR, "Cannot load certificate \"%s\" from Microsoft Certificate Store",
		 options->cryptoapi_cert);
	}
      else
#endif
	{
	  /* Load Certificate */
	  if (options->cert_file)
	    {
#if ENABLE_INLINE_FILES
	      if (!strcmp (options->cert_file, INLINE_FILE_TAG) && options->cert_file_inline)
		{
		  if (!use_inline_certificate_file (ctx, options->cert_file_inline))
		    msg (M_SSLERR, "Cannot load inline certificate file");
		}
	      else
#endif
		{
		  if (!SSL_CTX_use_certificate_file (ctx, options->cert_file, SSL_FILETYPE_PEM))
		    msg (M_SSLERR, "Cannot load certificate file %s", options->cert_file);
		  using_cert_file = true;
		}
	    }

	  /* Load Private Key */
	  if (options->priv_key_file)
	    {
	      int status;
	      
#if ENABLE_INLINE_FILES
	      if (!strcmp (options->priv_key_file, INLINE_FILE_TAG) && options->priv_key_file_inline)
		{
		  status = use_inline_PrivateKey_file (ctx, options->priv_key_file_inline);
		}
	      else
#endif
	      {
		status = SSL_CTX_use_PrivateKey_file (ctx, options->priv_key_file, SSL_FILETYPE_PEM);
	      }
	      if (!status)
		{
#ifdef ENABLE_MANAGEMENT
		  if (management && (ERR_GET_REASON (ERR_peek_error()) == EVP_R_BAD_DECRYPT))
		    management_auth_failure (management, UP_TYPE_PRIVATE_KEY, NULL);
#endif
		  msg (M_WARN|M_SSL, "Cannot load private key file %s", options->priv_key_file);
		  goto err;
		}
	      warn_if_group_others_accessible (options->priv_key_file);

	      /* Check Private Key */
	      if (!SSL_CTX_check_private_key (ctx))
		msg (M_SSLERR, "Private key does not match the certificate");
	    }
	}
    }

  if (options->ca_file || options->ca_path)
    {
      int status;

#if ENABLE_INLINE_FILES
      if (options->ca_file && !strcmp (options->ca_file, INLINE_FILE_TAG) && options->ca_file_inline)
	{
	  status = use_inline_load_verify_locations (ctx, options->ca_file_inline);
	}
      else
#endif
	{
	  /* Load CA file for verifying peer supplied certificate */
	  status = SSL_CTX_load_verify_locations (ctx, options->ca_file, options->ca_path);
	}
      
      if (!status)
	msg (M_SSLERR, "Cannot load CA certificate file %s path %s (SSL_CTX_load_verify_locations)", options->ca_file, options->ca_path);

      /* Set a store for certs (CA & CRL) with a lookup on the "capath" hash directory */
      if (options->ca_path) {
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);

        if (store)
	  {
	    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
	    if (!X509_LOOKUP_add_dir(lookup, options->ca_path, X509_FILETYPE_PEM))
	      X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
	    else
	      msg(M_WARN, "WARNING: experimental option --capath %s", options->ca_path);
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#else
	    msg(M_WARN, "WARNING: this version of OpenSSL cannot handle CRL files in capath");
#endif
	  }
	else
          msg(M_SSLERR, "Cannot get certificate store (SSL_CTX_get_cert_store)");
      }

      /* Load names of CAs from file and use it as a client CA list */
      if (options->ca_file) {
        STACK_OF(X509_NAME) *cert_names = NULL;
#if ENABLE_INLINE_FILES
	if (!strcmp (options->ca_file, INLINE_FILE_TAG) && options->ca_file_inline)
	  {
	    cert_names = use_inline_load_client_CA_file (ctx, options->ca_file_inline);
	  }
	else
#endif
	  {
	    cert_names = SSL_load_client_CA_file (options->ca_file);
	  }
        if (!cert_names)
          msg (M_SSLERR, "Cannot load CA certificate file %s (SSL_load_client_CA_file)", options->ca_file);
        SSL_CTX_set_client_CA_list (ctx, cert_names);
      }
    }

  /* Enable the use of certificate chains */
  if (using_cert_file)
    {
      if (!SSL_CTX_use_certificate_chain_file (ctx, options->cert_file))
	msg (M_SSLERR, "Cannot load certificate chain file %s (SSL_use_certificate_chain_file)", options->cert_file);
    }

  /* Require peer certificate verification */
#if P2MP_SERVER
  if (options->ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED)
    {
      msg (M_WARN, "WARNING: POTENTIALLY DANGEROUS OPTION --client-cert-not-required may accept clients which do not present a certificate");
    }
  else
#endif
    {
#ifdef ENABLE_X509ALTUSERNAME
      x509_username_field = (char *) options->x509_username_field;
#else
      x509_username_field = X509_USERNAME_FIELD_DEFAULT;
#endif
      SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                          verify_callback);
    }

  /* Connection information callback */
  SSL_CTX_set_info_callback (ctx, info_callback);

  /* Allowable ciphers */
  if (options->cipher_list)
    {
      if (!SSL_CTX_set_cipher_list (ctx, options->cipher_list))
	msg (M_SSLERR, "Problem with cipher list: %s", options->cipher_list);
    }

  ERR_clear_error ();

  return ctx;

 err:
  ERR_clear_error ();
  if (ctx)
    SSL_CTX_free (ctx);
  return NULL;
}

/*
 * Print a one line summary of SSL/TLS session handshake.
 */
static void
print_details (SSL * c_ssl, const char *prefix)
{
  const SSL_CIPHER *ciph;
  X509 *cert;
  char s1[256];
  char s2[256];

  s1[0] = s2[0] = 0;
  ciph = SSL_get_current_cipher (c_ssl);
  openvpn_snprintf (s1, sizeof (s1), "%s %s, cipher %s %s",
		    prefix,
		    SSL_get_version (c_ssl),
		    SSL_CIPHER_get_version (ciph),
		    SSL_CIPHER_get_name (ciph));
  cert = SSL_get_peer_certificate (c_ssl);
  if (cert != NULL)
    {
      EVP_PKEY *pkey = X509_get_pubkey (cert);
      if (pkey != NULL)
	{
	  if (pkey->type == EVP_PKEY_RSA && pkey->pkey.rsa != NULL
	      && pkey->pkey.rsa->n != NULL)
	    {
	      openvpn_snprintf (s2, sizeof (s2), ", %d bit RSA",
				BN_num_bits (pkey->pkey.rsa->n));
	    }
	  else if (pkey->type == EVP_PKEY_DSA && pkey->pkey.dsa != NULL
		   && pkey->pkey.dsa->p != NULL)
	    {
	      openvpn_snprintf (s2, sizeof (s2), ", %d bit DSA",
				BN_num_bits (pkey->pkey.dsa->p));
	    }
	  EVP_PKEY_free (pkey);
	}
      X509_free (cert);
    }
  /* The SSL API does not allow us to look at temporary RSA/DH keys,
   * otherwise we should print their lengths too */
  msg (D_HANDSHAKE, "%s%s", s1, s2);
}

/*
 * Show the TLS ciphers that are available for us to use
 * in the OpenSSL library.
 */
void
show_available_tls_ciphers ()
{
  SSL_CTX *ctx;
  SSL *ssl;
  const char *cipher_name;
  int priority = 0;

  ctx = SSL_CTX_new (TLSv1_method ());
  if (!ctx)
    msg (M_SSLERR, "Cannot create SSL_CTX object");
  ssl = SSL_new (ctx);
  if (!ssl)
    msg (M_SSLERR, "Cannot create SSL object");

  printf ("Available TLS Ciphers,\n");
  printf ("listed in order of preference:\n\n");
  while ((cipher_name = SSL_get_cipher_list (ssl, priority++)))
    printf ("%s\n", cipher_name);
  printf ("\n");

  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

/*
 * The OpenSSL library has a notion of preference in TLS
 * ciphers.  Higher preference == more secure.
 * Return the highest preference cipher.
 */
void
get_highest_preference_tls_cipher (char *buf, int size)
{
  SSL_CTX *ctx;
  SSL *ssl;
  const char *cipher_name;

  ctx = SSL_CTX_new (TLSv1_method ());
  if (!ctx)
    msg (M_SSLERR, "Cannot create SSL_CTX object");
  ssl = SSL_new (ctx);
  if (!ssl)
    msg (M_SSLERR, "Cannot create SSL object");

  cipher_name = SSL_get_cipher_list (ssl, 0);
  strncpynt (buf, cipher_name, size);

  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

/*
 * Map internal constants to ascii names.
 */
static const char *
state_name (int state)
{
  switch (state)
    {
    case S_UNDEF:
      return "S_UNDEF";
    case S_INITIAL:
      return "S_INITIAL";
    case S_PRE_START:
      return "S_PRE_START";
    case S_START:
      return "S_START";
    case S_SENT_KEY:
      return "S_SENT_KEY";
    case S_GOT_KEY:
      return "S_GOT_KEY";
    case S_ACTIVE:
      return "S_ACTIVE";
    case S_NORMAL_OP:
      return "S_NORMAL_OP";
    case S_ERROR:
      return "S_ERROR";
    default:
      return "S_???";
    }
}

static const char *
packet_opcode_name (int op)
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
    case P_CONTROL_SOFT_RESET_V1:
      return "P_CONTROL_SOFT_RESET_V1";
    case P_CONTROL_V1:
      return "P_CONTROL_V1";
    case P_ACK_V1:
      return "P_ACK_V1";
    case P_DATA_V1:
      return "P_DATA_V1";
    default:
      return "P_???";
    }
}

static const char *
session_index_name (int index)
{
  switch (index)
    {
    case TM_ACTIVE:
      return "TM_ACTIVE";
    case TM_UNTRUSTED:
      return "TM_UNTRUSTED";
    case TM_LAME_DUCK:
      return "TM_LAME_DUCK";
    default:
      return "TM_???";
    }
}

/*
 * For debugging.
 */
static const char *
print_key_id (struct tls_multi *multi, struct gc_arena *gc)
{
  int i;
  struct buffer out = alloc_buf_gc (256, gc);

  for (i = 0; i < KEY_SCAN_SIZE; ++i)
    {
      struct key_state *ks = multi->key_scan[i];
      buf_printf (&out, " [key#%d state=%s id=%d sid=%s]", i,
		  state_name (ks->state), ks->key_id,
		  session_id_print (&ks->session_id_remote, gc));
    }

  return BSTR (&out);
}

/*
 * Given a key_method, return true if op
 * represents the required form of hard_reset.
 *
 * If key_method = 0, return true if any
 * form of hard reset is used.
 */
static bool
is_hard_reset (int op, int key_method)
{
  if (!key_method || key_method == 1)
    if (op == P_CONTROL_HARD_RESET_CLIENT_V1 || op == P_CONTROL_HARD_RESET_SERVER_V1)
      return true;

  if (!key_method || key_method >= 2)
    if (op == P_CONTROL_HARD_RESET_CLIENT_V2 || op == P_CONTROL_HARD_RESET_SERVER_V2)
      return true;

  return false;
}

/*
 * OpenVPN's interface to SSL/TLS authentication,
 * encryption, and decryption is exclusively
 * through "memory BIOs".
 */
static BIO *
getbio (BIO_METHOD * type, const char *desc)
{
  BIO *ret;
  ret = BIO_new (type);
  if (!ret)
    msg (M_SSLERR, "Error creating %s BIO", desc);
  return ret;
}

/*
 * Write to an OpenSSL BIO in non-blocking mode.
 */
static int
bio_write (struct tls_multi* multi, BIO *bio, const uint8_t *data, int size, const char *desc)
{
  int i;
  int ret = 0;
  ASSERT (size >= 0);
  if (size)
    {
      /*
       * Free the L_TLS lock prior to calling BIO routines
       * so that foreground thread can still call
       * tls_pre_decrypt or tls_pre_encrypt,
       * allowing tunnel packet forwarding to continue.
       */
#ifdef BIO_DEBUG
      bio_debug_data ("write", bio, data, size, desc);
#endif
      i = BIO_write (bio, data, size);

      if (i < 0)
	{
	  if (BIO_should_retry (bio))
	    {
	      ;
	    }
	  else
	    {
	      msg (D_TLS_ERRORS | M_SSL, "TLS ERROR: BIO write %s error",
		   desc);
	      ret = -1;
	      ERR_clear_error ();
	    }
	}
      else if (i != size)
	{
	  msg (D_TLS_ERRORS | M_SSL,
	       "TLS ERROR: BIO write %s incomplete %d/%d", desc, i, size);
	  ret = -1;
	  ERR_clear_error ();
	}
      else
	{			/* successful write */
	  dmsg (D_HANDSHAKE_VERBOSE, "BIO write %s %d bytes", desc, i);
	  ret = 1;
	}
    }
  return ret;
}

/*
 * Read from an OpenSSL BIO in non-blocking mode.
 */
static int
bio_read (struct tls_multi* multi, BIO *bio, struct buffer *buf, int maxlen, const char *desc)
{
  int i;
  int ret = 0;
  ASSERT (buf->len >= 0);
  if (buf->len)
    {
      ;
    }
  else
    {
      int len = buf_forward_capacity (buf);
      if (maxlen < len)
	len = maxlen;

      /*
       * BIO_read brackets most of the serious RSA
       * key negotiation number crunching.
       */
      i = BIO_read (bio, BPTR (buf), len);

      VALGRIND_MAKE_READABLE ((void *) &i, sizeof (i));

#ifdef BIO_DEBUG
      bio_debug_data ("read", bio, BPTR (buf), i, desc);
#endif
      if (i < 0)
	{
	  if (BIO_should_retry (bio))
	    {
	      ;
	    }
	  else
	    {
	      msg (D_TLS_ERRORS | M_SSL, "TLS_ERROR: BIO read %s error",
		   desc);
	      buf->len = 0;
	      ret = -1;
	      ERR_clear_error ();
	    }
	}
      else if (!i)
	{
	  buf->len = 0;
	}
      else
	{			/* successful read */
	  dmsg (D_HANDSHAKE_VERBOSE, "BIO read %s %d bytes", desc, i);
	  buf->len = i;
	  ret = 1;
	  VALGRIND_MAKE_READABLE ((void *) BPTR (buf), BLEN (buf));
	}
    }
  return ret;
}

/*
 * Inline functions for reading from and writing
 * to BIOs.
 */

static void
bio_write_post (const int status, struct buffer *buf)
{
  if (status == 1) /* success status return from bio_write? */
    {
      memset (BPTR (buf), 0, BLEN (buf)); /* erase data just written */
      buf->len = 0;
    }
}

static int
key_state_write_plaintext (struct tls_multi *multi, struct key_state *ks, struct buffer *buf)
{
  int ret;
  perf_push (PERF_BIO_WRITE_PLAINTEXT);
  ret = bio_write (multi, ks->ssl_bio, BPTR(buf), BLEN(buf), "tls_write_plaintext");
  bio_write_post (ret, buf);
  perf_pop ();
  return ret;
}

static int
key_state_write_plaintext_const (struct tls_multi *multi, struct key_state *ks, const uint8_t *data, int len)
{
  int ret;
  perf_push (PERF_BIO_WRITE_PLAINTEXT);
  ret = bio_write (multi, ks->ssl_bio, data, len, "tls_write_plaintext_const");
  perf_pop ();
  return ret;
}

static int
key_state_write_ciphertext (struct tls_multi *multi, struct key_state *ks, struct buffer *buf)
{
  int ret;
  perf_push (PERF_BIO_WRITE_CIPHERTEXT);
  ret = bio_write (multi, ks->ct_in, BPTR(buf), BLEN(buf), "tls_write_ciphertext");
  bio_write_post (ret, buf);
  perf_pop ();
  return ret;
}

static int
key_state_read_plaintext (struct tls_multi *multi, struct key_state *ks, struct buffer *buf,
			  int maxlen)
{
  int ret;
  perf_push (PERF_BIO_READ_PLAINTEXT);
  ret = bio_read (multi, ks->ssl_bio, buf, maxlen, "tls_read_plaintext");
  perf_pop ();
  return ret;
}

static int
key_state_read_ciphertext (struct tls_multi *multi, struct key_state *ks, struct buffer *buf,
			   int maxlen)
{
  int ret;
  perf_push (PERF_BIO_READ_CIPHERTEXT);
  ret = bio_read (multi, ks->ct_out, buf, maxlen, "tls_read_ciphertext");
  perf_pop ();
  return ret;
}

/*
 * Initialize a key_state.  Each key_state corresponds to
 * a specific SSL/TLS session.
 */
static void
key_state_init (struct tls_session *session, struct key_state *ks)
{
  update_time ();

  /*
   * Build TLS object that reads/writes ciphertext
   * to/from memory BIOs.
   */
  CLEAR (*ks);

  ks->ssl = SSL_new (session->opt->ssl_ctx);
  if (!ks->ssl)
    msg (M_SSLERR, "SSL_new failed");

  /* put session * in ssl object so we can access it
     from verify callback*/
  SSL_set_ex_data (ks->ssl, mydata_index, session);

  ks->ssl_bio = getbio (BIO_f_ssl (), "ssl_bio");
  ks->ct_in = getbio (BIO_s_mem (), "ct_in");
  ks->ct_out = getbio (BIO_s_mem (), "ct_out");

#ifdef BIO_DEBUG
  bio_debug_oc ("open ssl_bio", ks->ssl_bio);
  bio_debug_oc ("open ct_in", ks->ct_in);
  bio_debug_oc ("open ct_out", ks->ct_out);
#endif

  if (session->opt->server)
    SSL_set_accept_state (ks->ssl);
  else
    SSL_set_connect_state (ks->ssl);

  SSL_set_bio (ks->ssl, ks->ct_in, ks->ct_out);
  BIO_set_ssl (ks->ssl_bio, ks->ssl, BIO_NOCLOSE);

  /* Set control-channel initiation mode */
  ks->initial_opcode = session->initial_opcode;
  session->initial_opcode = P_CONTROL_SOFT_RESET_V1;
  ks->state = S_INITIAL;
  ks->key_id = session->key_id;

  /*
   * key_id increments to KEY_ID_MASK then recycles back to 1.
   * This way you know that if key_id is 0, it is the first key.
   */
  ++session->key_id;
  session->key_id &= P_KEY_ID_MASK;
  if (!session->key_id)
    session->key_id = 1;

  /* allocate key source material object */
  ALLOC_OBJ_CLEAR (ks->key_src, struct key_source2);

  /* allocate reliability objects */
  ALLOC_OBJ_CLEAR (ks->send_reliable, struct reliable);
  ALLOC_OBJ_CLEAR (ks->rec_reliable, struct reliable);
  ALLOC_OBJ_CLEAR (ks->rec_ack, struct reliable_ack);

  /* allocate buffers */
  ks->plaintext_read_buf = alloc_buf (TLS_CHANNEL_BUF_SIZE);
  ks->plaintext_write_buf = alloc_buf (TLS_CHANNEL_BUF_SIZE);
  ks->ack_write_buf = alloc_buf (BUF_SIZE (&session->opt->frame));
  reliable_init (ks->send_reliable, BUF_SIZE (&session->opt->frame),
		 FRAME_HEADROOM (&session->opt->frame), TLS_RELIABLE_N_SEND_BUFFERS,
		 ks->key_id ? false : session->opt->xmit_hold);
  reliable_init (ks->rec_reliable, BUF_SIZE (&session->opt->frame),
		 FRAME_HEADROOM (&session->opt->frame), TLS_RELIABLE_N_REC_BUFFERS,
		 false);
  reliable_set_timeout (ks->send_reliable, session->opt->packet_timeout);

  /* init packet ID tracker */
  packet_id_init (&ks->packet_id,
		  session->opt->replay_window,
		  session->opt->replay_time);

#ifdef MANAGEMENT_DEF_AUTH
  ks->mda_key_id = session->opt->mda_context->mda_key_id_counter++;
#endif
}

static void
key_state_free (struct key_state *ks, bool clear)
{
  ks->state = S_UNDEF;

  if (ks->ssl) {
#ifdef BIO_DEBUG
    bio_debug_oc ("close ssl_bio", ks->ssl_bio);
    bio_debug_oc ("close ct_in", ks->ct_in);
    bio_debug_oc ("close ct_out", ks->ct_out);
#endif
    BIO_free_all(ks->ssl_bio);
    SSL_free (ks->ssl);
  }

  free_key_ctx_bi (&ks->key);
  free_buf (&ks->plaintext_read_buf);
  free_buf (&ks->plaintext_write_buf);
  free_buf (&ks->ack_write_buf);
  buffer_list_free(ks->paybuf);

  if (ks->send_reliable)
    {
      reliable_free (ks->send_reliable);
      free (ks->send_reliable);
    }

  if (ks->rec_reliable)
    {
      reliable_free (ks->rec_reliable);
      free (ks->rec_reliable);
    }

  if (ks->rec_ack)
    free (ks->rec_ack);

  if (ks->key_src)
    free (ks->key_src);

  packet_id_free (&ks->packet_id);

#ifdef PLUGIN_DEF_AUTH
  key_state_rm_auth_control_file (ks);
#endif

  if (clear)
    CLEAR (*ks);
}

/*
 * Must be called if we move a tls_session in memory.
 */
static inline void tls_session_set_self_referential_pointers (struct tls_session* session) {
  session->tls_auth.packet_id = &session->tls_auth_pid;
}

/*
 * Initialize a TLS session.  A TLS session normally has 2 key_state objects,
 * one for the current key, and one for the lame duck (i.e. retiring) key.
 */
static void
tls_session_init (struct tls_multi *multi, struct tls_session *session)
{
  struct gc_arena gc = gc_new ();

  dmsg (D_TLS_DEBUG, "TLS: tls_session_init: entry");

  CLEAR (*session);

  /* Set options data to point to parent's option structure */
  session->opt = &multi->opt;
  
  /* Randomize session # if it is 0 */
  while (!session_id_defined(&session->session_id))
    session_id_random (&session->session_id);

  /* Are we a TLS server or client? */
  ASSERT (session->opt->key_method >= 1);
  if (session->opt->key_method == 1)
    {
      session->initial_opcode = session->opt->server ?
	P_CONTROL_HARD_RESET_SERVER_V1 : P_CONTROL_HARD_RESET_CLIENT_V1;
    }
  else /* session->opt->key_method >= 2 */
    {
      session->initial_opcode = session->opt->server ?
	P_CONTROL_HARD_RESET_SERVER_V2 : P_CONTROL_HARD_RESET_CLIENT_V2;
    }

  /* Initialize control channel authentication parameters */
  session->tls_auth = session->opt->tls_auth;

  /* Set session internal pointers (also called if session object is moved in memory) */
  tls_session_set_self_referential_pointers (session);

  /* initialize packet ID replay window for --tls-auth */
  packet_id_init (session->tls_auth.packet_id,
		  session->opt->replay_window,
		  session->opt->replay_time);

  /* load most recent packet-id to replay protect on --tls-auth */
  packet_id_persist_load_obj (session->tls_auth.pid_persist, session->tls_auth.packet_id);

  key_state_init (session, &session->key[KS_PRIMARY]);

  dmsg (D_TLS_DEBUG, "TLS: tls_session_init: new session object, sid=%s",
       session_id_print (&session->session_id, &gc));

  gc_free (&gc);
}

static void
tls_session_free (struct tls_session *session, bool clear)
{
  int i;

  if (session->tls_auth.packet_id)
    packet_id_free (session->tls_auth.packet_id);

  for (i = 0; i < KS_SIZE; ++i)
    key_state_free (&session->key[i], false);

  if (session->common_name)
    free (session->common_name);

  cert_hash_free (session->cert_hash_set);

  if (clear)
    CLEAR (*session);
}

static void
move_session (struct tls_multi* multi, int dest, int src, bool reinit_src)
{
  msg (D_TLS_DEBUG_LOW, "TLS: move_session: dest=%s src=%s reinit_src=%d",
       session_index_name(dest),
       session_index_name(src),
       reinit_src);
  ASSERT (src != dest);
  ASSERT (src >= 0 && src < TM_SIZE);
  ASSERT (dest >= 0 && dest < TM_SIZE);
  tls_session_free (&multi->session[dest], false);
  multi->session[dest] = multi->session[src];
  tls_session_set_self_referential_pointers (&multi->session[dest]);

  if (reinit_src)
    tls_session_init (multi, &multi->session[src]);
  else
    CLEAR (multi->session[src]);

  dmsg (D_TLS_DEBUG, "TLS: move_session: exit");
}

static void
reset_session (struct tls_multi *multi, struct tls_session *session)
{
  tls_session_free (session, false);
  tls_session_init (multi, session);
}

#if 0
/*
 * Transmit a TLS reset on our untrusted channel.
 */
static void
initiate_untrusted_session (struct tls_multi *multi, struct sockaddr_in *to)
{
  struct tls_session *session = &multi->session[TM_UNTRUSTED];
  struct key_state *ks = &session->key[KS_PRIMARY];

  reset_session (multi, session);
  ks->remote_addr = *to;
  msg (D_TLS_DEBUG_LOW, "TLS: initiate_untrusted_session: addr=%s", print_sockaddr (to));
}
#endif

/*
 * Used to determine in how many seconds we should be
 * called again.
 */
static inline void
compute_earliest_wakeup (interval_t *earliest, interval_t seconds_from_now) {
  if (seconds_from_now < *earliest)
    *earliest = seconds_from_now;
  if (*earliest < 0)
    *earliest = 0;
}

/*
 * Return true if "lame duck" or retiring key has expired and can
 * no longer be used.
 */
static inline bool
lame_duck_must_die (const struct tls_session* session, interval_t *wakeup)
{
  const struct key_state* lame = &session->key[KS_LAME_DUCK];
  if (lame->state >= S_INITIAL)
    {
      const time_t local_now = now;
      ASSERT (lame->must_die); /* a lame duck key must always have an expiration */
      if (local_now < lame->must_die)
	{
	  compute_earliest_wakeup (wakeup, lame->must_die - local_now);
	  return false;
	}
      else
	return true;
    }
  else if (lame->state == S_ERROR)
    return true;
  else
    return false;
}

/*
 * A tls_multi object fully encapsulates OpenVPN's TLS state.
 * See ssl.h for more comments.
 */
struct tls_multi *
tls_multi_init (struct tls_options *tls_options)
{
  struct tls_multi *ret;

  ALLOC_OBJ_CLEAR (ret, struct tls_multi);

  /* get command line derived options */
  ret->opt = *tls_options;

  /* set up pointer to HMAC object for TLS packet authentication */
  ret->opt.tls_auth.key_ctx_bi = &ret->opt.tls_auth_key;

  /* set up list of keys to be scanned by data channel encrypt and decrypt routines */
  ASSERT (SIZE (ret->key_scan) == 3);
  ret->key_scan[0] = &ret->session[TM_ACTIVE].key[KS_PRIMARY];
  ret->key_scan[1] = &ret->session[TM_ACTIVE].key[KS_LAME_DUCK];
  ret->key_scan[2] = &ret->session[TM_LAME_DUCK].key[KS_LAME_DUCK];

  return ret;
}

/*
 * Finalize our computation of frame sizes.
 */
void
tls_multi_init_finalize (struct tls_multi* multi, const struct frame* frame)
{
  tls_init_control_channel_frame_parameters (frame, &multi->opt.frame);
  
  /* initialize the active and untrusted sessions */

  tls_session_init (multi, &multi->session[TM_ACTIVE]);

  if (!multi->opt.single_session)
    tls_session_init (multi, &multi->session[TM_UNTRUSTED]);
}

/*
 * Initialize and finalize a standalone tls-auth verification object.
 */

struct tls_auth_standalone *
tls_auth_standalone_init (struct tls_options *tls_options,
			  struct gc_arena *gc)
{
  struct tls_auth_standalone *tas;

  ALLOC_OBJ_CLEAR_GC (tas, struct tls_auth_standalone, gc);

  /* set up pointer to HMAC object for TLS packet authentication */
  tas->tls_auth_key = tls_options->tls_auth_key;
  tas->tls_auth_options.key_ctx_bi = &tas->tls_auth_key;
  tas->tls_auth_options.flags |= CO_PACKET_ID_LONG_FORM;

  /* get initial frame parms, still need to finalize */
  tas->frame = tls_options->frame;

  return tas;
}

void
tls_auth_standalone_finalize (struct tls_auth_standalone *tas,
			      const struct frame *frame)
{
  tls_init_control_channel_frame_parameters (frame, &tas->frame);
}

/*
 * Set local and remote option compatibility strings.
 * Used to verify compatibility of local and remote option
 * sets.
 */
void
tls_multi_init_set_options (struct tls_multi* multi,
			   const char *local,
			   const char *remote)
{
#ifdef ENABLE_OCC
  /* initialize options string */
  multi->opt.local_options = local;
  multi->opt.remote_options = remote;
#endif
}

void
tls_multi_free (struct tls_multi *multi, bool clear)
{
  int i;

  ASSERT (multi);

#ifdef MANAGEMENT_DEF_AUTH
  man_def_auth_set_client_reason(multi, NULL);  

  free (multi->peer_info);
#endif

  if (multi->locked_cn)
    free (multi->locked_cn);

  if (multi->locked_username)
    free (multi->locked_username);

  cert_hash_free (multi->locked_cert_hash_set);

  for (i = 0; i < TM_SIZE; ++i)
    tls_session_free (&multi->session[i], false);

  if (clear)
    CLEAR (*multi);

  free(multi);
}

/*
 * Move a packet authentication HMAC + related fields to or from the front
 * of the buffer so it can be processed by encrypt/decrypt.
 */

/*
 * Dependent on hmac size, opcode size, and session_id size.
 * Will assert if too small.
 */
#define SWAP_BUF_SIZE 256

static bool
swap_hmac (struct buffer *buf, const struct crypto_options *co, bool incoming)
{
  struct key_ctx *ctx;

  ASSERT (co);

  ctx = (incoming ? &co->key_ctx_bi->decrypt : &co->key_ctx_bi->encrypt);
  ASSERT (ctx->hmac);

  {
    /* hmac + packet_id (8 bytes) */
    const int hmac_size = HMAC_size (ctx->hmac) + packet_id_size (true);

    /* opcode + session_id */
    const int osid_size = 1 + SID_SIZE;

    int e1, e2;
    uint8_t *b = BPTR (buf);
    uint8_t buf1[SWAP_BUF_SIZE];
    uint8_t buf2[SWAP_BUF_SIZE];

    if (incoming)
      {
	e1 = osid_size;
	e2 = hmac_size;
      }
    else
      {
	e1 = hmac_size;
	e2 = osid_size;
      }

    ASSERT (e1 <= SWAP_BUF_SIZE && e2 <= SWAP_BUF_SIZE);

    if (buf->len >= e1 + e2)
      {
	memcpy (buf1, b, e1);
	memcpy (buf2, b + e1, e2);
	memcpy (b, buf2, e2);
	memcpy (b + e2, buf1, e1);
	return true;
      }
    else
      return false;
  }
}

#undef SWAP_BUF_SIZE

/*
 * Write a control channel authentication record.
 */
static void
write_control_auth (struct tls_session *session,
		    struct key_state *ks,
		    struct buffer *buf,
		    struct link_socket_actual **to_link_addr,
		    int opcode,
		    int max_ack,
		    bool prepend_ack)
{
  uint8_t *header;
  struct buffer null = clear_buf ();

  ASSERT (link_socket_actual_defined (&ks->remote_addr));
  ASSERT (reliable_ack_write
	  (ks->rec_ack, buf, &ks->session_id_remote, max_ack, prepend_ack));
  ASSERT (session_id_write_prepend (&session->session_id, buf));
  ASSERT (header = buf_prepend (buf, 1));
  *header = ks->key_id | (opcode << P_OPCODE_SHIFT);
  if (session->tls_auth.key_ctx_bi->encrypt.hmac)
    {
      /* no encryption, only write hmac */
      openvpn_encrypt (buf, null, &session->tls_auth, NULL);
      ASSERT (swap_hmac (buf, &session->tls_auth, false));
    }
  *to_link_addr = &ks->remote_addr;
}

/*
 * Read a control channel authentication record.
 */
static bool
read_control_auth (struct buffer *buf,
		   const struct crypto_options *co,
		   const struct link_socket_actual *from)
{
  struct gc_arena gc = gc_new ();

  if (co->key_ctx_bi->decrypt.hmac)
    {
      struct buffer null = clear_buf ();

      /* move the hmac record to the front of the packet */
      if (!swap_hmac (buf, co, true))
	{
	  msg (D_TLS_ERRORS,
	       "TLS Error: cannot locate HMAC in incoming packet from %s",
	       print_link_socket_actual (from, &gc));
	  gc_free (&gc);
	  return false;
	}

      /* authenticate only (no decrypt) and remove the hmac record
         from the head of the buffer */
      openvpn_decrypt (buf, null, co, NULL);
      if (!buf->len)
	{
	  msg (D_TLS_ERRORS,
	       "TLS Error: incoming packet authentication failed from %s",
	       print_link_socket_actual (from, &gc));
	  gc_free (&gc);
	  return false;
	}

    }

  /* advance buffer pointer past opcode & session_id since our caller
     already read it */
  buf_advance (buf, SID_SIZE + 1);

  gc_free (&gc);
  return true;
}

/*
 * For debugging, print contents of key_source2 structure.
 */

static void
key_source_print (const struct key_source *k,
		  const char *prefix)
{
  struct gc_arena gc = gc_new ();

  VALGRIND_MAKE_READABLE ((void *)k->pre_master, sizeof (k->pre_master));
  VALGRIND_MAKE_READABLE ((void *)k->random1, sizeof (k->random1));
  VALGRIND_MAKE_READABLE ((void *)k->random2, sizeof (k->random2));

  dmsg (D_SHOW_KEY_SOURCE,
       "%s pre_master: %s",
       prefix,
       format_hex (k->pre_master, sizeof (k->pre_master), 0, &gc));
  dmsg (D_SHOW_KEY_SOURCE,
       "%s random1: %s",
       prefix,
       format_hex (k->random1, sizeof (k->random1), 0, &gc));
  dmsg (D_SHOW_KEY_SOURCE,
       "%s random2: %s",
       prefix,
       format_hex (k->random2, sizeof (k->random2), 0, &gc));

  gc_free (&gc);
}

static void
key_source2_print (const struct key_source2 *k)
{
  key_source_print (&k->client, "Client");
  key_source_print (&k->server, "Server");
}

/*
 * Use the TLS PRF function for generating data channel keys.
 * This code is taken from the OpenSSL library.
 *
 * TLS generates keys as such:
 *
 * master_secret[48] = PRF(pre_master_secret[48], "master secret",
 *                         ClientHello.random[32] + ServerHello.random[32])
 *
 * key_block[] = PRF(SecurityParameters.master_secret[48],
 *                 "key expansion",
 *                 SecurityParameters.server_random[32] +
 *                 SecurityParameters.client_random[32]);
 *
 * Notes:
 *
 * (1) key_block contains a full set of 4 keys.
 * (2) The pre-master secret is generated by the client.
 */

static void
tls1_P_hash(const EVP_MD *md,
	    const uint8_t *sec,
	    int sec_len,
	    const uint8_t *seed,
	    int seed_len,
	    uint8_t *out,
	    int olen)
{
  struct gc_arena gc = gc_new ();
  int chunk,n;
  unsigned int j;
  HMAC_CTX ctx;
  HMAC_CTX ctx_tmp;
  uint8_t A1[EVP_MAX_MD_SIZE];
  unsigned int A1_len;

#ifdef ENABLE_DEBUG
  const int olen_orig = olen;
  const uint8_t *out_orig = out;
#endif
	
  dmsg (D_SHOW_KEY_SOURCE, "tls1_P_hash sec: %s", format_hex (sec, sec_len, 0, &gc));
  dmsg (D_SHOW_KEY_SOURCE, "tls1_P_hash seed: %s", format_hex (seed, seed_len, 0, &gc));

  chunk=EVP_MD_size(md);

  HMAC_CTX_init(&ctx);
  HMAC_CTX_init(&ctx_tmp);
  HMAC_Init_ex(&ctx,sec,sec_len,md, NULL);
  HMAC_Init_ex(&ctx_tmp,sec,sec_len,md, NULL);
  HMAC_Update(&ctx,seed,seed_len);
  HMAC_Final(&ctx,A1,&A1_len);

  n=0;
  for (;;)
    {
      HMAC_Init_ex(&ctx,NULL,0,NULL,NULL); /* re-init */
      HMAC_Init_ex(&ctx_tmp,NULL,0,NULL,NULL); /* re-init */
      HMAC_Update(&ctx,A1,A1_len);
      HMAC_Update(&ctx_tmp,A1,A1_len);
      HMAC_Update(&ctx,seed,seed_len);

      if (olen > chunk)
	{
	  HMAC_Final(&ctx,out,&j);
	  out+=j;
	  olen-=j;
	  HMAC_Final(&ctx_tmp,A1,&A1_len); /* calc the next A1 value */
	}
      else	/* last one */
	{
	  HMAC_Final(&ctx,A1,&A1_len);
	  memcpy(out,A1,olen);
	  break;
	}
    }
  HMAC_CTX_cleanup(&ctx);
  HMAC_CTX_cleanup(&ctx_tmp);
  CLEAR (A1);

  dmsg (D_SHOW_KEY_SOURCE, "tls1_P_hash out: %s", format_hex (out_orig, olen_orig, 0, &gc));
  gc_free (&gc);
}

static void
tls1_PRF(uint8_t *label,
	 int label_len,
	 const uint8_t *sec,
	 int slen,
	 uint8_t *out1,
	 int olen)
{
  struct gc_arena gc = gc_new ();
  const EVP_MD *md5 = EVP_md5();
  const EVP_MD *sha1 = EVP_sha1();
  int len,i;
  const uint8_t *S1,*S2;
  uint8_t *out2;

  out2 = (uint8_t *) gc_malloc (olen, false, &gc);

  len=slen/2;
  S1=sec;
  S2= &(sec[len]);
  len+=(slen&1); /* add for odd, make longer */

	
  tls1_P_hash(md5 ,S1,len,label,label_len,out1,olen);
  tls1_P_hash(sha1,S2,len,label,label_len,out2,olen);

  for (i=0; i<olen; i++)
    out1[i]^=out2[i];

  memset (out2, 0, olen);

  dmsg (D_SHOW_KEY_SOURCE, "tls1_PRF out[%d]: %s", olen, format_hex (out1, olen, 0, &gc));

  gc_free (&gc);
}

static void
openvpn_PRF (const uint8_t *secret,
	     int secret_len,
	     const char *label,
	     const uint8_t *client_seed,
	     int client_seed_len,
	     const uint8_t *server_seed,
	     int server_seed_len,
	     const struct session_id *client_sid,
	     const struct session_id *server_sid,
	     uint8_t *output,
	     int output_len)
{
  /* concatenate seed components */

  struct buffer seed = alloc_buf (strlen (label)
				  + client_seed_len
				  + server_seed_len
				  + SID_SIZE * 2);

  ASSERT (buf_write (&seed, label, strlen (label)));
  ASSERT (buf_write (&seed, client_seed, client_seed_len));
  ASSERT (buf_write (&seed, server_seed, server_seed_len));

  if (client_sid)
      ASSERT (buf_write (&seed, client_sid->id, SID_SIZE));
  if (server_sid)
      ASSERT (buf_write (&seed, server_sid->id, SID_SIZE));

  /* compute PRF */
  tls1_PRF (BPTR(&seed), BLEN(&seed), secret, secret_len, output, output_len);

  buf_clear (&seed);
  free_buf (&seed);

  VALGRIND_MAKE_READABLE ((void *)output, output_len);
}

/* 
 * Using source entropy from local and remote hosts, mix into
 * master key.
 */
static bool
generate_key_expansion (struct key_ctx_bi *key,
			const struct key_type *key_type,
			const struct key_source2 *key_src,
			const struct session_id *client_sid,
			const struct session_id *server_sid,
			bool server)
{
  uint8_t master[48];
  struct key2 key2;
  bool ret = false;
  int i;

  CLEAR (master);
  CLEAR (key2);

  /* debugging print of source key material */
  key_source2_print (key_src);

  /* compute master secret */
  openvpn_PRF (key_src->client.pre_master,
	       sizeof(key_src->client.pre_master),
	       KEY_EXPANSION_ID " master secret",
	       key_src->client.random1,
	       sizeof(key_src->client.random1),
	       key_src->server.random1,
	       sizeof(key_src->server.random1),
	       NULL,
	       NULL,
	       master,
	       sizeof(master));
  
  /* compute key expansion */
  openvpn_PRF (master,
	       sizeof(master),
	       KEY_EXPANSION_ID " key expansion",
	       key_src->client.random2,
	       sizeof(key_src->client.random2),
	       key_src->server.random2,
	       sizeof(key_src->server.random2),
	       client_sid,
	       server_sid,
	       (uint8_t*)key2.keys,
	       sizeof(key2.keys));

  key2.n = 2;

  key2_print (&key2, key_type, "Master Encrypt", "Master Decrypt");

  /* check for weak keys */
  for (i = 0; i < 2; ++i)
    {
      fixup_key (&key2.keys[i], key_type);
      if (!check_key (&key2.keys[i], key_type))
	{
	  msg (D_TLS_ERRORS, "TLS Error: Bad dynamic key generated");
	  goto exit;
	}
    }

  /* Initialize OpenSSL key contexts */

  ASSERT (server == true || server == false);

  init_key_ctx (&key->encrypt,
		&key2.keys[(int)server],
		key_type,
		DO_ENCRYPT,
		"Data Channel Encrypt");

  init_key_ctx (&key->decrypt,
		&key2.keys[1-(int)server],
		key_type,
		DO_DECRYPT,
		"Data Channel Decrypt");

  ret = true;

 exit:
  CLEAR (master);
  CLEAR (key2);

  return ret;
}

static bool
random_bytes_to_buf (struct buffer *buf,
		     uint8_t *out,
		     int outlen)
{
  if (!RAND_bytes (out, outlen))
    msg (M_FATAL, "ERROR: Random number generator cannot obtain entropy for key generation [SSL]");
  if (!buf_write (buf, out, outlen))
    return false;
  return true;
}

static bool
key_source2_randomize_write (struct key_source2 *k2,
			     struct buffer *buf,
			     bool server)
{
  struct key_source *k = &k2->client;
  if (server)
    k = &k2->server;

  CLEAR (*k);

  if (!server)
    {
      if (!random_bytes_to_buf (buf, k->pre_master, sizeof (k->pre_master)))
	return false;
    }

  if (!random_bytes_to_buf (buf, k->random1, sizeof (k->random1)))
    return false;
  if (!random_bytes_to_buf (buf, k->random2, sizeof (k->random2)))
    return false;

  return true;
}

static int
key_source2_read (struct key_source2 *k2,
		  struct buffer *buf,
		  bool server)
{
  struct key_source *k = &k2->client;

  if (!server)
    k = &k2->server;

  CLEAR (*k);

  if (server)
    {
      if (!buf_read (buf, k->pre_master, sizeof (k->pre_master)))
	return 0;
    }

  if (!buf_read (buf, k->random1, sizeof (k->random1)))
    return 0;
  if (!buf_read (buf, k->random2, sizeof (k->random2)))
    return 0;

  return 1;
}

static void
flush_payload_buffer (struct tls_multi *multi, struct key_state *ks)
{
  struct buffer *b;
  while ((b = buffer_list_peek (ks->paybuf)))
    {
      key_state_write_plaintext_const (multi, ks, b->data, b->len);
      buffer_list_pop (ks->paybuf);
    }
}

/*
 * Macros for key_state_soft_reset & tls_process
 */
#define ks      (&session->key[KS_PRIMARY])	/* primary key */
#define ks_lame (&session->key[KS_LAME_DUCK])	/* retiring key */

/* true if no in/out acknowledgements pending */
#define FULL_SYNC \
  (reliable_empty(ks->send_reliable) && reliable_ack_empty (ks->rec_ack))

/*
 * Move the active key to the lame duck key and reinitialize the
 * active key.
 */
static void
key_state_soft_reset (struct tls_session *session)
{
  ks->must_die = now + session->opt->transition_window; /* remaining lifetime of old key */
  key_state_free (ks_lame, false);
  *ks_lame = *ks;

  key_state_init (session, ks);
  ks->session_id_remote = ks_lame->session_id_remote;
  ks->remote_addr = ks_lame->remote_addr;
}

/*
 * Read/write strings from/to a struct buffer with a u16 length prefix.
 */

static bool
write_string (struct buffer *buf, const char *str, const int maxlen)
{
  const int len = strlen (str) + 1;
  if (len < 1 || (maxlen >= 0 && len > maxlen))
    return false;
  if (!buf_write_u16 (buf, len))
    return false;
  if (!buf_write (buf, str, len))
    return false;
  return true;
}

static bool
write_empty_string (struct buffer *buf)
{
  if (!buf_write_u16 (buf, 0))
    return false;
  return true;
}

static bool
read_string (struct buffer *buf, char *str, const unsigned int capacity)
{
  const int len = buf_read_u16 (buf);
  if (len < 1 || len > (int)capacity)
    return false;
  if (!buf_read (buf, str, len))
    return false;
  str[len-1] = '\0';
  return true;
}

static char *
read_string_alloc (struct buffer *buf)
{
  const int len = buf_read_u16 (buf);
  char *str;

  if (len < 1)
    return NULL;
  str = (char *) malloc(len);
  check_malloc_return(str);
  if (!buf_read (buf, str, len))
    {
      free (str);
      return NULL;
    }
  str[len-1] = '\0';
  return str;
}

void
read_string_discard (struct buffer *buf)
{
  char *data = read_string_alloc(buf);
  if (data)
    free (data);
}

/*
 * Authenticate a client using username/password.
 * Runs on server.
 *
 * If you want to add new authentication methods,
 * this is the place to start.
 */

static bool
verify_user_pass_script (struct tls_session *session, const struct user_pass *up)
{
  struct gc_arena gc = gc_new ();
  struct argv argv = argv_new ();
  const char *tmp_file = "";
  bool ret = false;

  /* Is username defined? */
  if ((session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL) || strlen (up->username))
    {
      /* Set environmental variables prior to calling script */
      setenv_str (session->opt->es, "script_type", "user-pass-verify");

      if (session->opt->auth_user_pass_verify_script_via_file)
	{
	  struct status_output *so;

	  tmp_file = create_temp_file (session->opt->tmp_dir, "up", &gc);
          if( tmp_file ) {
            so = status_open (tmp_file, 0, -1, NULL, STATUS_OUTPUT_WRITE);
            status_printf (so, "%s", up->username);
            status_printf (so, "%s", up->password);
            if (!status_close (so))
              {
                msg (D_TLS_ERRORS, "TLS Auth Error: could not write username/password to file: %s",
                     tmp_file);
                goto done;
              }
          } else {
            msg (D_TLS_ERRORS, "TLS Auth Error: could not create write "
                 "username/password to temp file");
          }
        }
      else
	{
	  setenv_str (session->opt->es, "username", up->username);
	  setenv_str (session->opt->es, "password", up->password);
	}

      /* setenv incoming cert common name for script */
      setenv_str (session->opt->es, "common_name", session->common_name);

      /* setenv client real IP address */
      setenv_untrusted (session);

      /* format command line */
      argv_printf (&argv, "%sc %s", session->opt->auth_user_pass_verify_script, tmp_file);

      /* call command */
      ret = openvpn_run_script (&argv, session->opt->es, 0,
				"--auth-user-pass-verify");

      if (!session->opt->auth_user_pass_verify_script_via_file)
	setenv_del (session->opt->es, "password");
    }
  else
    {
      msg (D_TLS_ERRORS, "TLS Auth Error: peer provided a blank username");
    }

 done:
  if (tmp_file && strlen (tmp_file) > 0)
    delete_file (tmp_file);

  argv_reset (&argv);
  gc_free (&gc);
  return ret;
}

static int
verify_user_pass_plugin (struct tls_session *session, const struct user_pass *up, const char *raw_username)
{
  int retval = OPENVPN_PLUGIN_FUNC_ERROR;

  /* Is username defined? */
  if ((session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL) || strlen (up->username))
    {
      /* set username/password in private env space */
      setenv_str (session->opt->es, "username", raw_username);
      setenv_str (session->opt->es, "password", up->password);

      /* setenv incoming cert common name for script */
      setenv_str (session->opt->es, "common_name", session->common_name);

      /* setenv client real IP address */
      setenv_untrusted (session);

#ifdef PLUGIN_DEF_AUTH
      /* generate filename for deferred auth control file */
      key_state_gen_auth_control_file (ks, session->opt);
#endif

      /* call command */
      retval = plugin_call (session->opt->plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, NULL, NULL, session->opt->es);

#ifdef PLUGIN_DEF_AUTH
      /* purge auth control filename (and file itself) for non-deferred returns */
      if (retval != OPENVPN_PLUGIN_FUNC_DEFERRED)
	key_state_rm_auth_control_file (ks);
#endif

      setenv_del (session->opt->es, "password");
      setenv_str (session->opt->es, "username", up->username);
    }
  else
    {
      msg (D_TLS_ERRORS, "TLS Auth Error (verify_user_pass_plugin): peer provided a blank username");
    }

  return retval;
}

/*
 * MANAGEMENT_DEF_AUTH internal ssl.c status codes
 */
#define KMDA_ERROR   0
#define KMDA_SUCCESS 1
#define KMDA_UNDEF   2
#define KMDA_DEF     3

#ifdef MANAGEMENT_DEF_AUTH
static int
verify_user_pass_management (struct tls_session *session, const struct user_pass *up, const char *raw_username)
{
  int retval = KMDA_ERROR;

  /* Is username defined? */
  if ((session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL) || strlen (up->username))
    {
      /* set username/password in private env space */
      setenv_str (session->opt->es, "username", raw_username);
      setenv_str (session->opt->es, "password", up->password);

      /* setenv incoming cert common name for script */
      setenv_str (session->opt->es, "common_name", session->common_name);

      /* setenv client real IP address */
      setenv_untrusted (session);

      if (management)
	management_notify_client_needing_auth (management, ks->mda_key_id, session->opt->mda_context, session->opt->es);

      setenv_del (session->opt->es, "password");
      setenv_str (session->opt->es, "username", up->username);

      retval = KMDA_SUCCESS;
    }
  else
    {
      msg (D_TLS_ERRORS, "TLS Auth Error (verify_user_pass_management): peer provided a blank username");
    }

  return retval;
}
#endif

/*
 * Handle the reading and writing of key data to and from
 * the TLS control channel (cleartext).
 */

static bool
key_method_1_write (struct buffer *buf, struct tls_session *session)
{
  struct key key;

  ASSERT (session->opt->key_method == 1);
  ASSERT (buf_init (buf, 0));

  generate_key_random (&key, &session->opt->key_type);
  if (!check_key (&key, &session->opt->key_type))
    {
      msg (D_TLS_ERRORS, "TLS Error: Bad encrypting key generated");
      return false;
    }

  if (!write_key (&key, &session->opt->key_type, buf))
    {
      msg (D_TLS_ERRORS, "TLS Error: write_key failed");
      return false;
    }

  init_key_ctx (&ks->key.encrypt, &key, &session->opt->key_type,
		DO_ENCRYPT, "Data Channel Encrypt");
  CLEAR (key);

  /* send local options string */
  {
    const char *local_options = local_options_string (session);
    const int optlen = strlen (local_options) + 1;
    if (!buf_write (buf, local_options, optlen))
      {
	msg (D_TLS_ERRORS, "TLS Error: KM1 write options failed");
	return false;
      }
  }

  return true;
}

static bool
push_peer_info(struct buffer *buf, struct tls_session *session)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;

#ifdef ENABLE_PUSH_PEER_INFO
  if (session->opt->push_peer_info) /* write peer info */
    {
      struct env_set *es = session->opt->es;
      struct env_item *e;
      struct buffer out = alloc_buf_gc (512*3, &gc);

      /* push version */
      buf_printf (&out, "IV_VER=%s\n", PACKAGE_VERSION);

      /* push platform */
#if defined(TARGET_LINUX)
      buf_printf (&out, "IV_PLAT=linux\n");
#elif defined(TARGET_SOLARIS)
      buf_printf (&out, "IV_PLAT=solaris\n");
#elif defined(TARGET_OPENBSD)
      buf_printf (&out, "IV_PLAT=openbsd\n");
#elif defined(TARGET_DARWIN)
      buf_printf (&out, "IV_PLAT=mac\n");
#elif defined(TARGET_NETBSD)
      buf_printf (&out, "IV_PLAT=netbsd\n");
#elif defined(TARGET_FREEBSD)
      buf_printf (&out, "IV_PLAT=freebsd\n");
#elif defined(WIN32)
      buf_printf (&out, "IV_PLAT=win\n");
#endif

      /* push mac addr */
      {
	bool get_default_gateway_mac_addr (unsigned char *macaddr);
	uint8_t macaddr[6];
	get_default_gateway_mac_addr (macaddr);
	buf_printf (&out, "IV_HWADDR=%s\n", format_hex_ex (macaddr, 6, 0, 1, ":", &gc));
      }

      /* push env vars that begin with UV_ */
      for (e=es->list; e != NULL; e=e->next)
	{
	  if (e->string)
	    {
	      if (!strncmp(e->string, "UV_", 3) && buf_safe(&out, strlen(e->string)+1))
		buf_printf (&out, "%s\n", e->string);
	    }
	}

      if (!write_string(buf, BSTR(&out), -1))
	goto error;
    }
  else
#endif
    {
      if (!write_empty_string (buf)) /* no peer info */
	goto error;
    }
  ret = true;

 error:
  gc_free (&gc);
  return ret;
}

static bool
key_method_2_write (struct buffer *buf, struct tls_session *session)
{
  ASSERT (session->opt->key_method == 2);
  ASSERT (buf_init (buf, 0));

  /* write a uint32 0 */
  if (!buf_write_u32 (buf, 0))
    goto error;

  /* write key_method + flags */
  if (!buf_write_u8 (buf, (session->opt->key_method & KEY_METHOD_MASK)))
    goto error;

  /* write key source material */
  if (!key_source2_randomize_write (ks->key_src, buf, session->opt->server))
    goto error;

  /* write options string */
  {
    if (!write_string (buf, local_options_string (session), TLS_OPTIONS_LEN))
      goto error;
  }

  /* write username/password if specified */
  if (auth_user_pass_enabled)
    {
      auth_user_pass_setup (NULL);
      if (!write_string (buf, auth_user_pass.username, -1))
	goto error;
      if (!write_string (buf, auth_user_pass.password, -1))
	goto error;
      purge_user_pass (&auth_user_pass, false);
    }
  else
    {
      if (!write_empty_string (buf)) /* no username */
	goto error;
      if (!write_empty_string (buf)) /* no password */
	goto error;
    }

  if (!push_peer_info (buf, session))
    goto error;

  /*
   * generate tunnel keys if server
   */
  if (session->opt->server)
    {
      if (ks->authenticated)
	{
	  if (!generate_key_expansion (&ks->key,
				       &session->opt->key_type,
				       ks->key_src,
				       &ks->session_id_remote,
				       &session->session_id,
				       true))
	    {
	      msg (D_TLS_ERRORS, "TLS Error: server generate_key_expansion failed");
	      goto error;
	    }
	}
		      
      CLEAR (*ks->key_src);
    }

  return true;

 error:
  msg (D_TLS_ERRORS, "TLS Error: Key Method #2 write failed");
  CLEAR (*ks->key_src);
  return false;
}

static bool
key_method_1_read (struct buffer *buf, struct tls_session *session)
{
  int status;
  struct key key;

  ASSERT (session->opt->key_method == 1);

  if (!session->verified)
    {
      msg (D_TLS_ERRORS,
	   "TLS Error: Certificate verification failed (key-method 1)");
      goto error;
    }

  status = read_key (&key, &session->opt->key_type, buf);
  if (status != 1)
    {
      msg (D_TLS_ERRORS,
	   "TLS Error: Error reading data channel key from plaintext buffer");
      goto error;
    }

  if (!check_key (&key, &session->opt->key_type))
    {
      msg (D_TLS_ERRORS, "TLS Error: Bad decrypting key received from peer");
      goto error;
    }

  if (buf->len < 1)
    {
      msg (D_TLS_ERRORS, "TLS Error: Missing options string");
      goto error;
    }

#ifdef ENABLE_OCC
  /* compare received remote options string
     with our locally computed options string */
  if (!session->opt->disable_occ &&
      !options_cmp_equal_safe ((char *) BPTR (buf), session->opt->remote_options, buf->len))
    {
      options_warning_safe ((char *) BPTR (buf), session->opt->remote_options, buf->len);
    }
#endif

  buf_clear (buf);

  init_key_ctx (&ks->key.decrypt, &key, &session->opt->key_type,
		DO_DECRYPT, "Data Channel Decrypt");
  CLEAR (key);
  ks->authenticated = true;
  return true;

 error:
  buf_clear (buf);
  CLEAR (key);
  return false;
}

static bool
key_method_2_read (struct buffer *buf, struct tls_multi *multi, struct tls_session *session)
{
  struct gc_arena gc = gc_new ();
  int key_method_flags;
  char *options;
  struct user_pass *up;

  bool man_def_auth = KMDA_UNDEF;

#ifdef MANAGEMENT_DEF_AUTH
  if (management_enable_def_auth (management))
    man_def_auth = KMDA_DEF;
#endif

  ASSERT (session->opt->key_method == 2);

  /* allocate temporary objects */
  ALLOC_ARRAY_CLEAR_GC (options, char, TLS_OPTIONS_LEN, &gc);
		  
  /* discard leading uint32 */
  ASSERT (buf_advance (buf, 4));

  /* get key method */
  key_method_flags = buf_read_u8 (buf);
  if ((key_method_flags & KEY_METHOD_MASK) != 2)
    {
      msg (D_TLS_ERRORS,
	   "TLS ERROR: Unknown key_method/flags=%d received from remote host",
	   key_method_flags);
      goto error;
    }

  /* get key source material (not actual keys yet) */
  if (!key_source2_read (ks->key_src, buf, session->opt->server))
    {
      msg (D_TLS_ERRORS, "TLS Error: Error reading remote data channel key source entropy from plaintext buffer");
      goto error;
    }

  /* get options */
  if (!read_string (buf, options, TLS_OPTIONS_LEN))
    {
      msg (D_TLS_ERRORS, "TLS Error: Failed to read required OCC options string");
      goto error;
    }

  /* should we check username/password? */
  ks->authenticated = false;
  if (session->opt->auth_user_pass_verify_script
      || plugin_defined (session->opt->plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
      || man_def_auth == KMDA_DEF)
    {
      int s1 = OPENVPN_PLUGIN_FUNC_SUCCESS;
      bool s2 = true;
      char *raw_username;
      bool username_status, password_status;

      /* get username/password from plaintext buffer */
      ALLOC_OBJ_CLEAR_GC (up, struct user_pass, &gc);
      username_status = read_string (buf, up->username, USER_PASS_LEN);
      password_status = read_string (buf, up->password, USER_PASS_LEN);
      if (!username_status || !password_status)
	{
	  CLEAR (*up);
	  if (!(session->opt->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL))
	    {
	      msg (D_TLS_ERRORS, "TLS Error: Auth Username/Password was not provided by peer");
	      goto error;
	    }
	}

      /* preserve raw username before string_mod remapping, for plugins */
      ALLOC_ARRAY_CLEAR_GC (raw_username, char, USER_PASS_LEN, &gc);
      strcpy (raw_username, up->username);
      string_mod (raw_username, CC_PRINT, CC_CRLF, '_');

      /* enforce character class restrictions in username/password */
      string_mod_sslname (up->username, COMMON_NAME_CHAR_CLASS, session->opt->ssl_flags);
      string_mod (up->password, CC_PRINT, CC_CRLF, '_');

      /* call plugin(s) and/or script */
#ifdef MANAGEMENT_DEF_AUTH
      /* get peer info from control channel */
      free (multi->peer_info);
      multi->peer_info = read_string_alloc (buf);

      if (man_def_auth == KMDA_DEF)
	man_def_auth = verify_user_pass_management (session, up, raw_username);
#endif
      if (plugin_defined (session->opt->plugins, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY))
	s1 = verify_user_pass_plugin (session, up, raw_username);
      if (session->opt->auth_user_pass_verify_script)
	s2 = verify_user_pass_script (session, up);

      /* check sizing of username if it will become our common name */
      if ((session->opt->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME) && strlen (up->username) >= TLS_USERNAME_LEN)
	{
	  msg (D_TLS_ERRORS, "TLS Auth Error: --username-as-common name specified and username is longer than the maximum permitted Common Name length of %d characters", TLS_USERNAME_LEN);
	  s1 = OPENVPN_PLUGIN_FUNC_ERROR;
	}

      /* auth succeeded? */
      if ((s1 == OPENVPN_PLUGIN_FUNC_SUCCESS
#ifdef PLUGIN_DEF_AUTH
	   || s1 == OPENVPN_PLUGIN_FUNC_DEFERRED
#endif
	   ) && s2 && man_def_auth != KMDA_ERROR
	  && tls_lock_username (multi, up->username))
	{
	  ks->authenticated = true;
#ifdef PLUGIN_DEF_AUTH
	  if (s1 == OPENVPN_PLUGIN_FUNC_DEFERRED)
	    ks->auth_deferred = true;
#endif
#ifdef MANAGEMENT_DEF_AUTH
	  if (man_def_auth != KMDA_UNDEF)
	    ks->auth_deferred = true;
#endif
	  if ((session->opt->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME))
	    set_common_name (session, up->username);
#ifdef ENABLE_DEF_AUTH
	  msg (D_HANDSHAKE, "TLS: Username/Password authentication %s for username '%s' %s",
	       ks->auth_deferred ? "deferred" : "succeeded",
	       up->username,
	       (session->opt->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME) ? "[CN SET]" : "");
#else
	  msg (D_HANDSHAKE, "TLS: Username/Password authentication %s for username '%s' %s",
	       "succeeded",
	       up->username,
	       (session->opt->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME) ? "[CN SET]" : "");
#endif
	}
      else
	{
	  msg (D_TLS_ERRORS, "TLS Auth Error: Auth Username/Password verification failed for peer");
	}

      CLEAR (*up);
    }
  else
    {
      if (!session->verified)
	{
	  msg (D_TLS_ERRORS,
	       "TLS Error: Certificate verification failed (key-method 2)");
	  goto error;
	}
      ks->authenticated = true;
    }

  /* While it shouldn't really happen, don't allow the common name to be NULL */
  if (!session->common_name)
    set_common_name (session, "");

  /* Don't allow the CN to change once it's been locked */
  if (ks->authenticated && multi->locked_cn)
    {
      const char *cn = session->common_name;
      if (cn && strcmp (cn, multi->locked_cn))
	{
	  msg (D_TLS_ERRORS, "TLS Auth Error: TLS object CN attempted to change from '%s' to '%s' -- tunnel disabled",
	       multi->locked_cn,
	       cn);

	  /* change the common name back to its original value and disable the tunnel */
	  set_common_name (session, multi->locked_cn);
	  tls_deauthenticate (multi);
	}
    }

  /* Don't allow the cert hashes to change once they have been locked */
  if (ks->authenticated && multi->locked_cert_hash_set)
    {
      const struct cert_hash_set *chs = session->cert_hash_set;
      if (chs && !cert_hash_compare (chs, multi->locked_cert_hash_set))
	{
	  msg (D_TLS_ERRORS, "TLS Auth Error: TLS object CN=%s client-provided SSL certs unexpectedly changed during mid-session reauth",
	       session->common_name);

	  /* disable the tunnel */
	  tls_deauthenticate (multi);
	}
    }

  /* verify --client-config-dir based authentication */
  if (ks->authenticated && session->opt->client_config_dir_exclusive)
    {
      const char *cn = session->common_name;
      const char *path = gen_path (session->opt->client_config_dir_exclusive, cn, &gc);
      if (!cn || !strcmp (cn, CCD_DEFAULT) || !test_file (path))
	{
	  ks->authenticated = false;
	  msg (D_TLS_ERRORS, "TLS Auth Error: --client-config-dir authentication failed for common name '%s' file='%s'",
	       session->common_name,
	       path ? path : "UNDEF");
	}
    }

#ifdef ENABLE_OCC
  /* check options consistency */
  if (!session->opt->disable_occ &&
      !options_cmp_equal (options, session->opt->remote_options))
    {
      options_warning (options, session->opt->remote_options);
      if (session->opt->ssl_flags & SSLF_OPT_VERIFY)
	{
	  msg (D_TLS_ERRORS, "Option inconsistency warnings triggering disconnect due to --opt-verify");
	  ks->authenticated = false;
	}
    }
#endif

  buf_clear (buf);

  /*
   * Call OPENVPN_PLUGIN_TLS_FINAL plugin if defined, for final
   * veto opportunity over authentication decision.
   */
  if (ks->authenticated && plugin_defined (session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL))
    {
      if (plugin_call (session->opt->plugins, OPENVPN_PLUGIN_TLS_FINAL, NULL, NULL, session->opt->es) != OPENVPN_PLUGIN_FUNC_SUCCESS)
	ks->authenticated = false;
    }

  /*
   * Generate tunnel keys if client
   */
  if (!session->opt->server)
    {
      if (!generate_key_expansion (&ks->key,
				   &session->opt->key_type,
				   ks->key_src,
				   &session->session_id,
				   &ks->session_id_remote,
				   false))
	{
	  msg (D_TLS_ERRORS, "TLS Error: client generate_key_expansion failed");
	  goto error;
	}
		      
      CLEAR (*ks->key_src);
    }

  gc_free (&gc);
  return true;

 error:
  CLEAR (*ks->key_src);
  buf_clear (buf);
  gc_free (&gc);
  return false;
}

static int
auth_deferred_expire_window (const struct tls_options *o)
{
  int ret = o->handshake_window;
  const int r2 = o->renegotiate_seconds / 2;

  if (o->renegotiate_seconds && r2 < ret)
    ret = r2;
  return ret;
}

/*
 * This is the primary routine for processing TLS stuff inside the
 * the main event loop.  When this routine exits
 * with non-error status, it will set *wakeup to the number of seconds
 * when it wants to be called again.
 *
 * Return value is true if we have placed a packet in *to_link which we
 * want to send to our peer.
 */
static bool
tls_process (struct tls_multi *multi,
	     struct tls_session *session,
	     struct buffer *to_link,
	     struct link_socket_actual **to_link_addr,
	     struct link_socket_info *to_link_socket_info,
	     interval_t *wakeup)
{
  struct gc_arena gc = gc_new ();
  struct buffer *buf;
  bool state_change = false;
  bool active = false;

  /* Make sure we were initialized and that we're not in an error state */
  ASSERT (ks->state != S_UNDEF);
  ASSERT (ks->state != S_ERROR);
  ASSERT (session_id_defined (&session->session_id));

  /* Should we trigger a soft reset? -- new key, keeps old key for a while */
  if (ks->state >= S_ACTIVE &&
      ((session->opt->renegotiate_seconds
	&& now >= ks->established + session->opt->renegotiate_seconds)
       || (session->opt->renegotiate_bytes
	   && ks->n_bytes >= session->opt->renegotiate_bytes)
       || (session->opt->renegotiate_packets
	   && ks->n_packets >= session->opt->renegotiate_packets)
       || (packet_id_close_to_wrapping (&ks->packet_id.send))))
    {
      msg (D_TLS_DEBUG_LOW,
           "TLS: soft reset sec=%d bytes=" counter_format "/%d pkts=" counter_format "/%d",
	   (int)(ks->established + session->opt->renegotiate_seconds - now),
	   ks->n_bytes, session->opt->renegotiate_bytes,
	   ks->n_packets, session->opt->renegotiate_packets);
      key_state_soft_reset (session);
    }

  /* Kill lame duck key transition_window seconds after primary key negotiation */
  if (lame_duck_must_die (session, wakeup)) {
	key_state_free (ks_lame, true);
	msg (D_TLS_DEBUG_LOW, "TLS: tls_process: killed expiring key");
  }

  do
    {
      update_time ();

      dmsg (D_TLS_DEBUG, "TLS: tls_process: chg=%d ks=%s lame=%s to_link->len=%d wakeup=%d",
	   state_change,
	   state_name (ks->state),
	   state_name (ks_lame->state),
	   to_link->len,
	   *wakeup);

      state_change = false;

      /*
       * TLS activity is finished once we get to S_ACTIVE,
       * though we will still process acknowledgements.
       *
       * CHANGED with 2.0 -> now we may send tunnel configuration
       * info over the control channel.
       */
      if (true)
	{
	  /* Initial handshake */
	  if (ks->state == S_INITIAL)
	    {
	      buf = reliable_get_buf_output_sequenced (ks->send_reliable);
	      if (buf)
		{
		  ks->must_negotiate = now + session->opt->handshake_window;
		  ks->auth_deferred_expire = now + auth_deferred_expire_window (session->opt);

		  /* null buffer */
		  reliable_mark_active_outgoing (ks->send_reliable, buf, ks->initial_opcode);
		  INCR_GENERATED;
	      
		  ks->state = S_PRE_START;
		  state_change = true;
		  dmsg (D_TLS_DEBUG, "TLS: Initial Handshake, sid=%s",
		       session_id_print (&session->session_id, &gc));

#ifdef ENABLE_MANAGEMENT
		  if (management && ks->initial_opcode != P_CONTROL_SOFT_RESET_V1)
		    {
		      management_set_state (management,
					    OPENVPN_STATE_WAIT,
					    NULL,
					    0,
					    0);
		    }
#endif
		}
	    }

	  /* Are we timed out on receive? */
	  if (now >= ks->must_negotiate)
	    {
	      if (ks->state < S_ACTIVE)
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: TLS key negotiation failed to occur within %d seconds (check your network connectivity)",
		       session->opt->handshake_window);
		  goto error;
		}
	      else /* assume that ks->state == S_ACTIVE */
		{
		  dmsg (D_TLS_DEBUG_MED, "STATE S_NORMAL_OP");
		  ks->state = S_NORMAL_OP;
		  ks->must_negotiate = 0;
		}
	    }

	  /* Wait for Initial Handshake ACK */
	  if (ks->state == S_PRE_START && FULL_SYNC)
	    {
	      ks->state = S_START;
	      state_change = true;
	      dmsg (D_TLS_DEBUG_MED, "STATE S_START");
	    }

	  /* Wait for ACK */
	  if (((ks->state == S_GOT_KEY && !session->opt->server) ||
	       (ks->state == S_SENT_KEY && session->opt->server)))
	    {
	      if (FULL_SYNC)
		{
		  ks->established = now;
		  dmsg (D_TLS_DEBUG_MED, "STATE S_ACTIVE");
		  if (check_debug_level (D_HANDSHAKE))
		    print_details (ks->ssl, "Control Channel:");
		  state_change = true;
		  ks->state = S_ACTIVE;
		  INCR_SUCCESS;

		  /* Set outgoing address for data channel packets */
		  link_socket_set_outgoing_addr (NULL, to_link_socket_info, &ks->remote_addr, session->common_name, session->opt->es);

		  /* Flush any payload packets that were buffered before our state transitioned to S_ACTIVE */
		  flush_payload_buffer (multi, ks);

#ifdef MEASURE_TLS_HANDSHAKE_STATS
		  show_tls_performance_stats();
#endif
		}
	    }

	  /* Reliable buffer to outgoing TCP/UDP (send up to CONTROL_SEND_ACK_MAX ACKs
	     for previously received packets) */
	  if (!to_link->len && reliable_can_send (ks->send_reliable))
	    {
	      int opcode;
	      struct buffer b;

	      buf = reliable_send (ks->send_reliable, &opcode);
	      ASSERT (buf);
	      b = *buf;
	      INCR_SENT;

	      write_control_auth (session, ks, &b, to_link_addr, opcode,
				  CONTROL_SEND_ACK_MAX, true);
	      *to_link = b;
	      active = true;
	      state_change = true;
	      dmsg (D_TLS_DEBUG, "Reliable -> TCP/UDP");
	      break;
	    }

#ifndef TLS_AGGREGATE_ACK
	  /* Send 1 or more ACKs (each received control packet gets one ACK) */
	  if (!to_link->len && !reliable_ack_empty (ks->rec_ack))
	    {
	      buf = &ks->ack_write_buf;
	      ASSERT (buf_init (buf, FRAME_HEADROOM (&multi->opt.frame)));
	      write_control_auth (session, ks, buf, to_link_addr, P_ACK_V1,
				  RELIABLE_ACK_SIZE, false);
	      *to_link = *buf;
	      active = true;
	      state_change = true;
	      dmsg (D_TLS_DEBUG, "Dedicated ACK -> TCP/UDP");
	      break;
	    }
#endif

	  /* Write incoming ciphertext to TLS object */
	  buf = reliable_get_buf_sequenced (ks->rec_reliable);
	  if (buf)
	    {
	      int status = 0;
	      if (buf->len)
		{
		  status = key_state_write_ciphertext (multi, ks, buf);
		  if (status == -1)
		    {
		      msg (D_TLS_ERRORS,
			   "TLS Error: Incoming Ciphertext -> TLS object write error");
		      goto error;
		    }
		}
	      else
		{
		  status = 1;
		}
	      if (status == 1)
		{
		  reliable_mark_deleted (ks->rec_reliable, buf, true);
		  state_change = true;
		  dmsg (D_TLS_DEBUG, "Incoming Ciphertext -> TLS");
		}
	    }

	  /* Read incoming plaintext from TLS object */
	  buf = &ks->plaintext_read_buf;
	  if (!buf->len)
	    {
	      int status;

	      ASSERT (buf_init (buf, 0));
	      status = key_state_read_plaintext (multi, ks, buf, TLS_CHANNEL_BUF_SIZE);
	      update_time ();
	      if (status == -1)
		{
		  msg (D_TLS_ERRORS, "TLS Error: TLS object -> incoming plaintext read error");
		  goto error;
		}
	      if (status == 1)
		{
		  state_change = true;
		  dmsg (D_TLS_DEBUG, "TLS -> Incoming Plaintext");
		}
#if 0 /* show null plaintext reads */
	      if (!status)
		msg (M_INFO, "TLS plaintext read -> NULL return");
#endif
	    }

	  /* Send Key */
	  buf = &ks->plaintext_write_buf;
	  if (!buf->len && ((ks->state == S_START && !session->opt->server) ||
			    (ks->state == S_GOT_KEY && session->opt->server)))
	    {
	      if (session->opt->key_method == 1)
		{
		  if (!key_method_1_write (buf, session))
		    goto error;
		}
	      else if (session->opt->key_method == 2)
		{
		  if (!key_method_2_write (buf, session))
		    goto error;
		}
	      else
		{
		  ASSERT (0);
		}

	      state_change = true;
	      dmsg (D_TLS_DEBUG_MED, "STATE S_SENT_KEY");
	      ks->state = S_SENT_KEY;
	    }

	  /* Receive Key */
	  buf = &ks->plaintext_read_buf;
	  if (buf->len
	      && ((ks->state == S_SENT_KEY && !session->opt->server)
		  || (ks->state == S_START && session->opt->server)))
	    {
	      if (session->opt->key_method == 1)
		{
		  if (!key_method_1_read (buf, session))
		    goto error;
		}
	      else if (session->opt->key_method == 2)
		{
		  if (!key_method_2_read (buf, multi, session))
		    goto error;
		}
	      else
		{
		  ASSERT (0);
		}

	      state_change = true;
	      dmsg (D_TLS_DEBUG_MED, "STATE S_GOT_KEY");
	      ks->state = S_GOT_KEY;
	    }

	  /* Write outgoing plaintext to TLS object */
	  buf = &ks->plaintext_write_buf;
	  if (buf->len)
	    {
	      int status = key_state_write_plaintext (multi, ks, buf);
	      if (status == -1)
		{
		  msg (D_TLS_ERRORS,
		       "TLS ERROR: Outgoing Plaintext -> TLS object write error");
		  goto error;
		}
	      if (status == 1)
		{
		  state_change = true;
		  dmsg (D_TLS_DEBUG, "Outgoing Plaintext -> TLS");
		}
	    }

	  /* Outgoing Ciphertext to reliable buffer */
	  if (ks->state >= S_START)
	    {
	      buf = reliable_get_buf_output_sequenced (ks->send_reliable);
	      if (buf)
		{
		  int status = key_state_read_ciphertext (multi, ks, buf, PAYLOAD_SIZE_DYNAMIC (&multi->opt.frame));
		  if (status == -1)
		    {
		      msg (D_TLS_ERRORS,
			   "TLS Error: Ciphertext -> reliable TCP/UDP transport read error");
		      goto error;
		    }
		  if (status == 1)
		    {
		      reliable_mark_active_outgoing (ks->send_reliable, buf, P_CONTROL_V1);
		      INCR_GENERATED;
		      state_change = true;
		      dmsg (D_TLS_DEBUG, "Outgoing Ciphertext -> Reliable");
		    }
		}
	    }
	}
    }
  while (state_change);

  update_time ();

#ifdef TLS_AGGREGATE_ACK
  /* Send 1 or more ACKs (each received control packet gets one ACK) */
  if (!to_link->len && !reliable_ack_empty (ks->rec_ack))
    {
      buf = &ks->ack_write_buf;
      ASSERT (buf_init (buf, FRAME_HEADROOM (&multi->opt.frame)));
      write_control_auth (session, ks, buf, to_link_addr, P_ACK_V1,
			  RELIABLE_ACK_SIZE, false);
      *to_link = *buf;
      active = true;
      state_change = true;
      dmsg (D_TLS_DEBUG, "Dedicated ACK -> TCP/UDP");
    }
#endif

  /* When should we wake up again? */
  {
    if (ks->state >= S_INITIAL)
      {
	compute_earliest_wakeup (wakeup,
	  reliable_send_timeout (ks->send_reliable));
	
	if (ks->must_negotiate)
	  compute_earliest_wakeup (wakeup, ks->must_negotiate - now);
      }

    if (ks->established && session->opt->renegotiate_seconds)
      compute_earliest_wakeup (wakeup,
        ks->established + session->opt->renegotiate_seconds - now);

    /* prevent event-loop spinning by setting minimum wakeup of 1 second */
    if (*wakeup <= 0)
      {
	*wakeup = 1;

	/* if we had something to send to remote, but to_link was busy,
	   let caller know we need to be called again soon */
	active = true;
      }

    dmsg (D_TLS_DEBUG, "TLS: tls_process: timeout set to %d", *wakeup);

    gc_free (&gc);
    return active;
  }

error:
  ERR_clear_error ();
  ks->state = S_ERROR;
  msg (D_TLS_ERRORS, "TLS Error: TLS handshake failed");
  INCR_ERROR;
  gc_free (&gc);
  return false;
}

#undef ks
#undef ks_lame

/*
 * Called by the top-level event loop.
 *
 * Basically decides if we should call tls_process for
 * the active or untrusted sessions.
 */

int
tls_multi_process (struct tls_multi *multi,
		   struct buffer *to_link,
		   struct link_socket_actual **to_link_addr,
		   struct link_socket_info *to_link_socket_info,
		   interval_t *wakeup)
{
  struct gc_arena gc = gc_new ();
  int i;
  int active = TLSMP_INACTIVE;
  bool error = false;
  int tas;

  perf_push (PERF_TLS_MULTI_PROCESS);

  ERR_clear_error ();

  /*
   * Process each session object having state of S_INITIAL or greater,
   * and which has a defined remote IP addr.
   */

  for (i = 0; i < TM_SIZE; ++i)
    {
      struct tls_session *session = &multi->session[i];
      struct key_state *ks = &session->key[KS_PRIMARY];
      struct key_state *ks_lame = &session->key[KS_LAME_DUCK];

      /* set initial remote address */
      if (i == TM_ACTIVE && ks->state == S_INITIAL &&
	  link_socket_actual_defined (&to_link_socket_info->lsa->actual))
	ks->remote_addr = to_link_socket_info->lsa->actual;

      dmsg (D_TLS_DEBUG,
	   "TLS: tls_multi_process: i=%d state=%s, mysid=%s, stored-sid=%s, stored-ip=%s",
	   i,
	   state_name (ks->state),
	   session_id_print (&session->session_id, &gc),
	   session_id_print (&ks->session_id_remote, &gc),
	   print_link_socket_actual (&ks->remote_addr, &gc));

      if (ks->state >= S_INITIAL && link_socket_actual_defined (&ks->remote_addr))
	{
	  struct link_socket_actual *tla = NULL;

	  update_time ();

	  if (tls_process (multi, session, to_link, &tla,
			   to_link_socket_info, wakeup))
	    active = TLSMP_ACTIVE;

	  /*
	   * If tls_process produced an outgoing packet,
	   * return the link_socket_actual object (which
	   * contains the outgoing address).
	   */
	  if (tla)
	    {
	      multi->to_link_addr = *tla;
	      *to_link_addr = &multi->to_link_addr;
	    }

	  /*
	   * If tls_process hits an error:
	   * (1) If the session has an unexpired lame duck key, preserve it.
	   * (2) Reinitialize the session.
	   * (3) Increment soft error count
	   */
	  if (ks->state == S_ERROR)
	    {
	      ++multi->n_soft_errors;

	      if (i == TM_ACTIVE)
		error = true;

	      if (i == TM_ACTIVE
		  && ks_lame->state >= S_ACTIVE
		  && !multi->opt.single_session)
		move_session (multi, TM_LAME_DUCK, TM_ACTIVE, true);
	      else
		reset_session (multi, session);
	    }
	}
    }

  update_time ();

  tas = tls_authentication_status (multi, TLS_MULTI_AUTH_STATUS_INTERVAL);

  /*
   * If lame duck session expires, kill it.
   */
  if (lame_duck_must_die (&multi->session[TM_LAME_DUCK], wakeup)) {
    tls_session_free (&multi->session[TM_LAME_DUCK], true);
    msg (D_TLS_DEBUG_LOW, "TLS: tls_multi_process: killed expiring key");
  }

  /*
   * If untrusted session achieves TLS authentication,
   * move it to active session, usurping any prior session.
   *
   * A semi-trusted session is one in which the certificate authentication
   * succeeded (if cert verification is enabled) but the username/password
   * verification failed.  A semi-trusted session can forward data on the
   * TLS control channel but not on the tunnel channel.
   */
  if (DECRYPT_KEY_ENABLED (multi, &multi->session[TM_UNTRUSTED].key[KS_PRIMARY])) {
    move_session (multi, TM_ACTIVE, TM_UNTRUSTED, true);
    msg (D_TLS_DEBUG_LOW, "TLS: tls_multi_process: untrusted session promoted to %strusted",
	 tas == TLS_AUTHENTICATION_SUCCEEDED ? "" : "semi-");
  }

  /*
   * A hard error means that TM_ACTIVE hit an S_ERROR state and that no
   * other key state objects are S_ACTIVE or higher.
   */
  if (error)
    {
      for (i = 0; i < (int) SIZE (multi->key_scan); ++i)
	{
	  if (multi->key_scan[i]->state >= S_ACTIVE)
	    goto nohard;
	}
      ++multi->n_hard_errors;
    }
 nohard:

#ifdef ENABLE_DEBUG
  /* DEBUGGING -- flood peer with repeating connection attempts */
  {
    const int throw_level = GREMLIN_CONNECTION_FLOOD_LEVEL (multi->opt.gremlin);
    if (throw_level)
      {
	for (i = 0; i < (int) SIZE (multi->key_scan); ++i)
	  {
	    if (multi->key_scan[i]->state >= throw_level)
	      {
		++multi->n_hard_errors;
		++multi->n_soft_errors;
	      }
	  }
      }
  }
#endif

  perf_pop ();
  gc_free (&gc);

  return (tas == TLS_AUTHENTICATION_FAILED) ? TLSMP_KILL : active;
}

/*
 * Pre and post-process the encryption & decryption buffers in order
 * to implement a multiplexed TLS channel over the TCP/UDP port.
 */

/*
 *
 * When we are in TLS mode, this is the first routine which sees
 * an incoming packet.
 *
 * If it's a data packet, we set opt so that our caller can
 * decrypt it.  We also give our caller the appropriate decryption key.
 *
 * If it's a control packet, we authenticate it and process it,
 * possibly creating a new tls_session if it represents the
 * first packet of a new session.  For control packets, we will
 * also zero the size of *buf so that our caller ignores the
 * packet on our return.
 *
 * Note that openvpn only allows one active session at a time,
 * so a new session (once authenticated) will always usurp
 * an old session.
 *
 * Return true if input was an authenticated control channel
 * packet.
 *
 * If we are running in TLS thread mode, all public routines
 * below this point must be called with the L_TLS lock held.
 */

bool
tls_pre_decrypt (struct tls_multi *multi,
		 const struct link_socket_actual *from,
		 struct buffer *buf,
		 struct crypto_options *opt)
{
  struct gc_arena gc = gc_new ();
  bool ret = false;

  if (buf->len > 0)
    {
      int i;
      int op;
      int key_id;

      /* get opcode and key ID */
      {
	uint8_t c = *BPTR (buf);
	op = c >> P_OPCODE_SHIFT;
	key_id = c & P_KEY_ID_MASK;
      }

      if (op == P_DATA_V1)
	{			/* data channel packet */
	  for (i = 0; i < KEY_SCAN_SIZE; ++i)
	    {
	      struct key_state *ks = multi->key_scan[i];

	      /*
	       * This is the basic test of TLS state compatibility between a local OpenVPN 
	       * instance and its remote peer.
	       *
	       * If the test fails, it tells us that we are getting a packet from a source
	       * which claims reference to a prior negotiated TLS session, but the local
	       * OpenVPN instance has no memory of such a negotiation.
	       *
	       * It almost always occurs on UDP sessions when the passive side of the
	       * connection is restarted without the active side restarting as well (the 
	       * passive side is the server which only listens for the connections, the 
	       * active side is the client which initiates connections).
	       */
	      if (DECRYPT_KEY_ENABLED (multi, ks)
		  && key_id == ks->key_id
		  && ks->authenticated
#ifdef ENABLE_DEF_AUTH
		  && !ks->auth_deferred
#endif
		  && link_socket_actual_match (from, &ks->remote_addr))
		{
		  /* return appropriate data channel decrypt key in opt */
		  opt->key_ctx_bi = &ks->key;
		  opt->packet_id = multi->opt.replay ? &ks->packet_id : NULL;
		  opt->pid_persist = NULL;
		  opt->flags &= multi->opt.crypto_flags_and;
		  opt->flags |= multi->opt.crypto_flags_or;
		  ASSERT (buf_advance (buf, 1));
		  ++ks->n_packets;
		  ks->n_bytes += buf->len;
		  dmsg (D_TLS_KEYSELECT,
		       "TLS: tls_pre_decrypt, key_id=%d, IP=%s",
		       key_id, print_link_socket_actual (from, &gc));
		  gc_free (&gc);
		  return ret;
		}
#if 0 /* keys out of sync? */
	      else
		{
		  dmsg (D_TLS_ERRORS, "TLS_PRE_DECRYPT: [%d] dken=%d rkid=%d lkid=%d auth=%d def=%d match=%d",
			i,
			DECRYPT_KEY_ENABLED (multi, ks),
			key_id,
			ks->key_id,
			ks->authenticated,
#ifdef ENABLE_DEF_AUTH
			ks->auth_deferred,
#else
			-1,
#endif
			link_socket_actual_match (from, &ks->remote_addr));
		}
#endif
	    }

	  msg (D_TLS_ERRORS,
	       "TLS Error: local/remote TLS keys are out of sync: %s [%d]",
	       print_link_socket_actual (from, &gc), key_id);
	  goto error_lite;
	}
      else			  /* control channel packet */
	{
	  bool do_burst = false;
	  bool new_link = false;
	  struct session_id sid;  /* remote session ID */

	  /* verify legal opcode */
	  if (op < P_FIRST_OPCODE || op > P_LAST_OPCODE)
	    {
	      msg (D_TLS_ERRORS,
		   "TLS Error: unknown opcode received from %s op=%d",
		   print_link_socket_actual (from, &gc), op);
	      goto error;
	    }

	  /* hard reset ? */
	  if (is_hard_reset (op, 0))
	    {
	      /* verify client -> server or server -> client connection */
	      if (((op == P_CONTROL_HARD_RESET_CLIENT_V1
		    || op == P_CONTROL_HARD_RESET_CLIENT_V2) && !multi->opt.server)
		  || ((op == P_CONTROL_HARD_RESET_SERVER_V1
		       || op == P_CONTROL_HARD_RESET_SERVER_V2) && multi->opt.server))
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: client->client or server->server connection attempted from %s",
		       print_link_socket_actual (from, &gc));
		  goto error;
		}
	    }

	  /*
	   * Authenticate Packet
	   */
	  dmsg (D_TLS_DEBUG, "TLS: control channel, op=%s, IP=%s",
	       packet_opcode_name (op), print_link_socket_actual (from, &gc));

	  /* get remote session-id */
	  {
	    struct buffer tmp = *buf;
	    buf_advance (&tmp, 1);
	    if (!session_id_read (&sid, &tmp) || !session_id_defined (&sid))
	      {
		msg (D_TLS_ERRORS,
		     "TLS Error: session-id not found in packet from %s",
		     print_link_socket_actual (from, &gc));
		goto error;
	      }
	  }

	  /* use session ID to match up packet with appropriate tls_session object */
	  for (i = 0; i < TM_SIZE; ++i)
	    {
	      struct tls_session *session = &multi->session[i];
	      struct key_state *ks = &session->key[KS_PRIMARY];

	      dmsg (D_TLS_DEBUG,
		   "TLS: initial packet test, i=%d state=%s, mysid=%s, rec-sid=%s, rec-ip=%s, stored-sid=%s, stored-ip=%s",
		   i,
		   state_name (ks->state),
		   session_id_print (&session->session_id, &gc),
		   session_id_print (&sid, &gc),
		   print_link_socket_actual (from, &gc),
		   session_id_print (&ks->session_id_remote, &gc),
		   print_link_socket_actual (&ks->remote_addr, &gc));

	      if (session_id_equal (&ks->session_id_remote, &sid))
		/* found a match */
		{
		  if (i == TM_LAME_DUCK) {
		    msg (D_TLS_ERRORS,
			 "TLS ERROR: received control packet with stale session-id=%s",
			 session_id_print (&sid, &gc));
		    goto error;
		  }
		  dmsg (D_TLS_DEBUG,
		       "TLS: found match, session[%d], sid=%s",
		       i, session_id_print (&sid, &gc));
		  break;
		}
	    }

	  /*
	   * Initial packet received.
	   */

	  if (i == TM_SIZE && is_hard_reset (op, 0))
	    {
	      struct tls_session *session = &multi->session[TM_ACTIVE];
	      struct key_state *ks = &session->key[KS_PRIMARY];

	      if (!is_hard_reset (op, multi->opt.key_method))
		{
		  msg (D_TLS_ERRORS, "TLS ERROR: initial packet local/remote key_method mismatch, local key_method=%d, op=%s",
		       multi->opt.key_method,
		       packet_opcode_name (op));
		  goto error;
		}

	      /*
	       * If we have no session currently in progress, the initial packet will
	       * open a new session in TM_ACTIVE rather than TM_UNTRUSTED.
	       */
	      if (!session_id_defined (&ks->session_id_remote))
		{
		  if (multi->opt.single_session && multi->n_sessions)
		    {
		      msg (D_TLS_ERRORS,
			   "TLS Error: Cannot accept new session request from %s due to session context expire or --single-session [1]",
			   print_link_socket_actual (from, &gc));
		      goto error;
		    }

#ifdef ENABLE_MANAGEMENT
		  if (management)
		    {
		      management_set_state (management,
					    OPENVPN_STATE_AUTH,
					    NULL,
					    0,
					    0);
		    }
#endif

		  msg (D_TLS_DEBUG_LOW,
		       "TLS: Initial packet from %s, sid=%s",
		       print_link_socket_actual (from, &gc),
		       session_id_print (&sid, &gc));

		  do_burst = true;
		  new_link = true;
		  i = TM_ACTIVE;
		  session->untrusted_addr = *from;
		}
	    }

	  if (i == TM_SIZE && is_hard_reset (op, 0))
	    {
	      /*
	       * No match with existing sessions,
	       * probably a new session.
	       */
	      struct tls_session *session = &multi->session[TM_UNTRUSTED];

	      /*
	       * If --single-session, don't allow any hard-reset connection request
	       * unless it the the first packet of the session.
	       */
	      if (multi->opt.single_session)
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: Cannot accept new session request from %s due to session context expire or --single-session [2]",
		       print_link_socket_actual (from, &gc));
		  goto error;
		}
	      
	      if (!is_hard_reset (op, multi->opt.key_method))
		{
		  msg (D_TLS_ERRORS, "TLS ERROR: new session local/remote key_method mismatch, local key_method=%d, op=%s",
		       multi->opt.key_method,
		       packet_opcode_name (op));
		  goto error;
		}

	      if (!read_control_auth (buf, &session->tls_auth, from))
		goto error;

	      /*
	       * New session-initiating control packet is authenticated at this point,
	       * assuming that the --tls-auth command line option was used.
	       *
	       * Without --tls-auth, we leave authentication entirely up to TLS.
	       */
	      msg (D_TLS_DEBUG_LOW,
		   "TLS: new session incoming connection from %s",
		   print_link_socket_actual (from, &gc));

	      new_link = true;
	      i = TM_UNTRUSTED;
	      session->untrusted_addr = *from;
	    }
	  else
	    {
	      struct tls_session *session = &multi->session[i];
	      struct key_state *ks = &session->key[KS_PRIMARY];

	      /*
	       * Packet must belong to an existing session.
	       */
	      if (i != TM_ACTIVE && i != TM_UNTRUSTED)
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: Unroutable control packet received from %s (si=%d op=%s)",
		       print_link_socket_actual (from, &gc),
		       i,
		       packet_opcode_name (op));
		  goto error;
		}

	      /*
	       * Verify remote IP address
	       */
	      if (!new_link && !link_socket_actual_match (&ks->remote_addr, from))
		{
		  msg (D_TLS_ERRORS, "TLS Error: Received control packet from unexpected IP addr: %s",
		      print_link_socket_actual (from, &gc));
		  goto error;
		}

	      /*
	       * Remote is requesting a key renegotiation
	       */
	      if (op == P_CONTROL_SOFT_RESET_V1
		  && DECRYPT_KEY_ENABLED (multi, ks))
		{
		  if (!read_control_auth (buf, &session->tls_auth, from))
		    goto error;

		  key_state_soft_reset (session);

		  dmsg (D_TLS_DEBUG,
		       "TLS: received P_CONTROL_SOFT_RESET_V1 s=%d sid=%s",
		       i, session_id_print (&sid, &gc));
		}
	      else
		{
		  /*
		   * Remote responding to our key renegotiation request?
		   */
		  if (op == P_CONTROL_SOFT_RESET_V1)
		    do_burst = true;

		  if (!read_control_auth (buf, &session->tls_auth, from))
		    goto error;

		  dmsg (D_TLS_DEBUG,
		       "TLS: received control channel packet s#=%d sid=%s",
		       i, session_id_print (&sid, &gc));
		}
	    }
	  
	  /*
	   * We have an authenticated packet (if --tls-auth was set).
           * Now pass to our reliability level which deals with
	   * packet acknowledgements, retransmits, sequencing, etc.
	   */
	  {
	    struct tls_session *session = &multi->session[i];
	    struct key_state *ks = &session->key[KS_PRIMARY];

	    /* Make sure we were initialized and that we're not in an error state */
	    ASSERT (ks->state != S_UNDEF);
	    ASSERT (ks->state != S_ERROR);
	    ASSERT (session_id_defined (&session->session_id));

	    /* Let our caller know we processed a control channel packet */
	    ret = true;

	    /*
	     * Set our remote address and remote session_id
	     */
	    if (new_link)
	      {
		ks->session_id_remote = sid;
		ks->remote_addr = *from;
		++multi->n_sessions;
	      }
	    else if (!link_socket_actual_match (&ks->remote_addr, from))
	      {
		msg (D_TLS_ERRORS,
		     "TLS Error: Existing session control channel packet from unknown IP address: %s",
		     print_link_socket_actual (from, &gc));
		goto error;
	      }

	    /*
	     * Should we do a retransmit of all unacknowledged packets in
	     * the send buffer?  This improves the start-up efficiency of the
	     * initial key negotiation after the 2nd peer comes online.
	     */
	    if (do_burst && !session->burst)
	      {
		reliable_schedule_now (ks->send_reliable);
		session->burst = true;
	      }

	    /* Check key_id */
	    if (ks->key_id != key_id)
	      {
		msg (D_TLS_ERRORS,
		     "TLS ERROR: local/remote key IDs out of sync (%d/%d) ID: %s",
		     ks->key_id, key_id, print_key_id (multi, &gc));
		goto error;
	      }
	      
	    /*
	     * Process incoming ACKs for packets we can now
	     * delete from reliable send buffer
	     */
	    {
	      /* buffers all packet IDs to delete from send_reliable */
	      struct reliable_ack send_ack;

	      send_ack.len = 0;
	      if (!reliable_ack_read (&send_ack, buf, &session->session_id))
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: reading acknowledgement record from packet");
		  goto error;
		}
	      reliable_send_purge (ks->send_reliable, &send_ack);
	    }

	    if (op != P_ACK_V1 && reliable_can_get (ks->rec_reliable))
	      {
		packet_id_type id;

		/* Extract the packet ID from the packet */
		if (reliable_ack_read_packet_id (buf, &id))
		  {
		    /* Avoid deadlock by rejecting packet that would de-sequentialize receive buffer */
		    if (reliable_wont_break_sequentiality (ks->rec_reliable, id))
		      {
			if (reliable_not_replay (ks->rec_reliable, id))
			  {
			    /* Save incoming ciphertext packet to reliable buffer */
			    struct buffer *in = reliable_get_buf (ks->rec_reliable);
			    ASSERT (in);
			    ASSERT (buf_copy (in, buf));
			    reliable_mark_active_incoming (ks->rec_reliable, in, id, op);
			  }

			/* Process outgoing acknowledgment for packet just received, even if it's a replay */
			reliable_ack_acknowledge_packet_id (ks->rec_ack, id);
		      }
		  }
	      }
	  }
	}
    }

 done:
  buf->len = 0;
  opt->key_ctx_bi = NULL;
  opt->packet_id = NULL;
  opt->pid_persist = NULL;
  opt->flags &= multi->opt.crypto_flags_and;
  gc_free (&gc);
  return ret;

 error:
  ++multi->n_soft_errors;
 error_lite:
  ERR_clear_error ();
  goto done;
}

/*
 * This function is similar to tls_pre_decrypt, except it is called
 * when we are in server mode and receive an initial incoming
 * packet.  Note that we don't modify
 * any state in our parameter objects.  The purpose is solely to
 * determine whether we should generate a client instance
 * object, in which case true is returned.
 *
 * This function is essentially the first-line HMAC firewall
 * on the UDP port listener in --mode server mode.
 */
bool
tls_pre_decrypt_lite (const struct tls_auth_standalone *tas,
		      const struct link_socket_actual *from,
		      const struct buffer *buf)

{
  struct gc_arena gc = gc_new ();
  bool ret = false;

  if (buf->len > 0)
    {
      int op;
      int key_id;

      /* get opcode and key ID */
      {
	uint8_t c = *BPTR (buf);
	op = c >> P_OPCODE_SHIFT;
	key_id = c & P_KEY_ID_MASK;
      }

      /* this packet is from an as-yet untrusted source, so
	 scrutinize carefully */

      if (op != P_CONTROL_HARD_RESET_CLIENT_V2)
	{
	  /*
	   * This can occur due to bogus data or DoS packets.
	   */
	  dmsg (D_TLS_STATE_ERRORS,
	       "TLS State Error: No TLS state for client %s, opcode=%d",
	       print_link_socket_actual (from, &gc),
	       op);
	  goto error;
	}

      if (key_id != 0)
	{
	  dmsg (D_TLS_STATE_ERRORS,
	       "TLS State Error: Unknown key ID (%d) received from %s -- 0 was expected",
	       key_id,
	       print_link_socket_actual (from, &gc));
	  goto error;
	}

      if (buf->len > EXPANDED_SIZE_DYNAMIC (&tas->frame))
	{
	  dmsg (D_TLS_STATE_ERRORS,
	       "TLS State Error: Large packet (size %d) received from %s -- a packet no larger than %d bytes was expected",
	       buf->len,
	       print_link_socket_actual (from, &gc),
	       EXPANDED_SIZE_DYNAMIC (&tas->frame));
	  goto error;
	}

      {
	struct buffer newbuf = clone_buf (buf);
	struct crypto_options co = tas->tls_auth_options;
	bool status;

	/*
	 * We are in read-only mode at this point with respect to TLS
	 * control channel state.  After we build a new client instance
	 * object, we will process this session-initiating packet for real.
	 */
	co.flags |= CO_IGNORE_PACKET_ID;

	/* HMAC test, if --tls-auth was specified */
	status = read_control_auth (&newbuf, &co, from);
	free_buf (&newbuf);
	if (!status)
	  goto error;

	/*
	 * At this point, if --tls-auth is being used, we know that
	 * the packet has passed the HMAC test, but we don't know if
	 * it is a replay yet.  We will attempt to defeat replays
	 * by not advancing to the S_START state until we
	 * receive an ACK from our first reply to the client
	 * that includes an HMAC of our randomly generated 64 bit
	 * session ID.
	 *
	 * On the other hand if --tls-auth is not being used, we
	 * will proceed to begin the TLS authentication
	 * handshake with only cursory integrity checks having
	 * been performed, since we will be leaving the task
	 * of authentication solely up to TLS.
	 */

	ret = true;
      }
    }
  gc_free (&gc);
  return ret;

 error:
  ERR_clear_error ();
  gc_free (&gc);
  return ret;
}

/* Choose the key with which to encrypt a data packet */
void
tls_pre_encrypt (struct tls_multi *multi,
		 struct buffer *buf, struct crypto_options *opt)
{
  multi->save_ks = NULL;
  if (buf->len > 0)
    {
      int i;
      struct key_state *ks_select = NULL;
      for (i = 0; i < KEY_SCAN_SIZE; ++i)
	{
	  struct key_state *ks = multi->key_scan[i];
	  if (ks->state >= S_ACTIVE
	      && ks->authenticated
#ifdef ENABLE_DEF_AUTH
	      && !ks->auth_deferred
#endif
	      )
	    {
	      if (!ks_select)
		ks_select = ks;
	      if (now >= ks->auth_deferred_expire)
		{
		  ks_select = ks;
		  break;
		}
	    }
	}

      if (ks_select)
	{
	  opt->key_ctx_bi = &ks_select->key;
	  opt->packet_id = multi->opt.replay ? &ks_select->packet_id : NULL;
	  opt->pid_persist = NULL;
	  opt->flags &= multi->opt.crypto_flags_and;
	  opt->flags |= multi->opt.crypto_flags_or;
	  multi->save_ks = ks_select;
	  dmsg (D_TLS_KEYSELECT, "TLS: tls_pre_encrypt: key_id=%d", ks_select->key_id);
	  return;
	}
      else
	{
	  struct gc_arena gc = gc_new ();
	  dmsg (D_TLS_KEYSELECT, "TLS Warning: no data channel send key available: %s",
		print_key_id (multi, &gc));
	  gc_free (&gc);
	}
    }

  buf->len = 0;
  opt->key_ctx_bi = NULL;
  opt->packet_id = NULL;
  opt->pid_persist = NULL;
  opt->flags &= multi->opt.crypto_flags_and;
}

/* Prepend the appropriate opcode to encrypted buffer prior to TCP/UDP send */
void
tls_post_encrypt (struct tls_multi *multi, struct buffer *buf)
{
  struct key_state *ks;
  uint8_t *op;

  ks = multi->save_ks;
  multi->save_ks = NULL;
  if (buf->len > 0)
    {
      ASSERT (ks);
      ASSERT (op = buf_prepend (buf, 1));
      *op = (P_DATA_V1 << P_OPCODE_SHIFT) | ks->key_id;
      ++ks->n_packets;
      ks->n_bytes += buf->len;
    }
}

/*
 * Send a payload over the TLS control channel.
 * Called externally.
 */

bool
tls_send_payload (struct tls_multi *multi,
		  const uint8_t *data,
		  int size)
{
  struct tls_session *session;
  struct key_state *ks;
  bool ret = false;

  ERR_clear_error ();

  ASSERT (multi);

  session = &multi->session[TM_ACTIVE];
  ks = &session->key[KS_PRIMARY];

  if (ks->state >= S_ACTIVE)
    {
      if (key_state_write_plaintext_const (multi, ks, data, size) == 1)
	ret = true;
    }
  else
    {
      if (!ks->paybuf)
	ks->paybuf = buffer_list_new (0);
      buffer_list_push_data (ks->paybuf, data, (size_t)size);
      ret = true;
    }

  ERR_clear_error ();

  return ret;
}

bool
tls_rec_payload (struct tls_multi *multi,
		 struct buffer *buf)
{
  struct tls_session *session;
  struct key_state *ks;
  bool ret = false;

  ERR_clear_error ();

  ASSERT (multi);

  session = &multi->session[TM_ACTIVE];
  ks = &session->key[KS_PRIMARY];

  if (ks->state >= S_ACTIVE && BLEN (&ks->plaintext_read_buf))
    {
      if (buf_copy (buf, &ks->plaintext_read_buf))
	ret = true;
      ks->plaintext_read_buf.len = 0;
    }

  ERR_clear_error ();

  return ret;
}

/*
 * Dump a human-readable rendition of an openvpn packet
 * into a garbage collectable string which is returned.
 */
const char *
protocol_dump (struct buffer *buffer, unsigned int flags, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  struct buffer buf = *buffer;

  uint8_t c;
  int op;
  int key_id;

  int tls_auth_hmac_size = (flags & PD_TLS_AUTH_HMAC_SIZE_MASK);

  if (buf.len <= 0)
    {
      buf_printf (&out, "DATA UNDEF len=%d", buf.len);
      goto done;
    }

  if (!(flags & PD_TLS))
    goto print_data;

  /*
   * Initial byte (opcode)
   */
  if (!buf_read (&buf, &c, sizeof (c)))
    goto done;
  op = (c >> P_OPCODE_SHIFT);
  key_id = c & P_KEY_ID_MASK;
  buf_printf (&out, "%s kid=%d", packet_opcode_name (op), key_id);

  if (op == P_DATA_V1)
    goto print_data;

  /*
   * Session ID
   */
  {
    struct session_id sid;

    if (!session_id_read (&sid, &buf))
      goto done;
    if (flags & PD_VERBOSE)
	buf_printf (&out, " sid=%s", session_id_print (&sid, gc));
  }

  /*
   * tls-auth hmac + packet_id
   */
  if (tls_auth_hmac_size)
    {
      struct packet_id_net pin;
      uint8_t tls_auth_hmac[MAX_HMAC_KEY_LENGTH];

      ASSERT (tls_auth_hmac_size <= MAX_HMAC_KEY_LENGTH);

      if (!buf_read (&buf, tls_auth_hmac, tls_auth_hmac_size))
	goto done;
      if (flags & PD_VERBOSE)
	buf_printf (&out, " tls_hmac=%s", format_hex (tls_auth_hmac, tls_auth_hmac_size, 0, gc));

      if (!packet_id_read (&pin, &buf, true))
	goto done;
      buf_printf(&out, " pid=%s", packet_id_net_print (&pin, (flags & PD_VERBOSE), gc));
    }

  /*
   * ACK list
   */
  buf_printf (&out, " %s", reliable_ack_print(&buf, (flags & PD_VERBOSE), gc));

  if (op == P_ACK_V1)
    goto done;

  /*
   * Packet ID
   */
  {
    packet_id_type l;
    if (!buf_read (&buf, &l, sizeof (l)))
      goto done;
    l = ntohpid (l);
    buf_printf (&out, " pid=" packet_id_format, (packet_id_print_type)l);
  }

print_data:
  if (flags & PD_SHOW_DATA)
    buf_printf (&out, " DATA %s", format_hex (BPTR (&buf), BLEN (&buf), 80, gc));
  else
    buf_printf (&out, " DATA len=%d", buf.len);

done:
  return BSTR (&out);
}

#else
static void dummy(void) {}
#endif /* USE_CRYPTO && USE_SSL*/
