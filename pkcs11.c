/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
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
 * The routines in this file deal with providing private key cryptography
 * using RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki).
 *
 */

#if defined(WIN32)
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#if defined(ENABLE_PKCS11)

#define PKCS11H_NO_NEED_INCLUDE_CONFIG

#include "pkcs11-helper.h"
#include "pkcs11.h"

static
unsigned
_pkcs11_msg_pkcs112openvpn (
	IN const unsigned flags
) {
	unsigned openvpn_flags;

	switch (flags) {
		case PKCS11H_LOG_DEBUG2:
			openvpn_flags = D_PKCS11_DEBUG;
		break;
		case PKCS11H_LOG_DEBUG1:
			openvpn_flags = D_SHOW_PKCS11;
		break;
		case PKCS11H_LOG_INFO:
			openvpn_flags = M_INFO;
		break;
		case PKCS11H_LOG_WARN:
			openvpn_flags = M_WARN;
		break;
		case PKCS11H_LOG_ERROR:
			openvpn_flags = M_FATAL;
		break;
		default:
			openvpn_flags = M_FATAL;
		break;
	}

#if defined(ENABLE_PKCS11_FORCE_DEBUG)
	openvpn_flags=M_INFO;
#endif

	return openvpn_flags;
}

static
unsigned
_pkcs11_msg_openvpn2pkcs11 (
	IN const unsigned flags
) {
	unsigned pkcs11_flags;

	if ((flags & D_PKCS11_DEBUG) != 0) {
		pkcs11_flags = PKCS11H_LOG_DEBUG2;
	}
	else if ((flags & D_SHOW_PKCS11) != 0) {
		pkcs11_flags = PKCS11H_LOG_DEBUG1;
	}
	else if ((flags & M_INFO) != 0) {
		pkcs11_flags = PKCS11H_LOG_INFO;
	}
	else if ((flags & M_WARN) != 0) {
		pkcs11_flags = PKCS11H_LOG_WARN;
	}
	else if ((flags & M_FATAL) != 0) {
		pkcs11_flags = PKCS11H_LOG_ERROR;
	}
	else {
		pkcs11_flags = PKCS11H_LOG_ERROR;
	}

#if defined(ENABLE_PKCS11_FORCE_DEBUG)
	pkcs11_flags = PKCS11H_LOG_DEBUG2;
#endif

	return pkcs11_flags;
}

static
void
_pkcs11_openvpn_print (
	IN const void *pData,
	IN const char * const szFormat,
	IN ...
) {
	char Buffer[10*1024];
	va_list args;
	
	va_start (args, szFormat);
	vsnprintf (Buffer, sizeof (Buffer), szFormat, args);
	va_end (args);
	Buffer[sizeof (Buffer)-1] = 0;
	
	msg (M_INFO|M_NOPREFIX|M_NOLF, "%s", Buffer);
}

static
void
_pkcs11_openvpn_log (
	IN const void *pData,
	IN unsigned flags,
	IN const char * const szFormat,
	IN va_list args
) {
	char Buffer[10*1024];
	
	vsnprintf (Buffer, sizeof (Buffer), szFormat, args);
	Buffer[sizeof (Buffer)-1] = 0;

	msg (_pkcs11_msg_pkcs112openvpn (flags), "%s", Buffer);
}

static
bool
_pkcs11_openvpn_token_prompt (
	IN const void *pData,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
) {
	static struct user_pass token_resp;

	(void)retry;
	ASSERT (token!=NULL);

	CLEAR (token_resp);
	token_resp.defined = false;
	token_resp.nocache = true;
	openvpn_snprintf (
		token_resp.username,
		sizeof (token_resp.username),
		"Please insert %s token",
		token->label
	);

	if (
		!get_user_pass (
			&token_resp,
			NULL,
			"token-insertion-request",
			GET_USER_PASS_MANAGEMENT|GET_USER_PASS_NEED_OK|GET_USER_PASS_NOFATAL
		)
	) {
		return false;
	}
	else {
		return strcmp (token_resp.password, "ok") == 0;
	}
}

static
bool
_pkcs11_openvpn_pin_prompt (
	IN const void *pData,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	static struct user_pass token_pass;
	char szPrompt[1024];

	(void)retry;
	ASSERT (token!=NULL);

	openvpn_snprintf (szPrompt, sizeof (szPrompt), "%s token", token->label);

	token_pass.defined = false;
	token_pass.nocache = true;

	if (
		!get_user_pass (
			&token_pass,
			NULL,
			szPrompt,
			GET_USER_PASS_MANAGEMENT|GET_USER_PASS_PASSWORD_ONLY|GET_USER_PASS_NOFATAL
		)
	) {
		return false;
	}
	else {
		strncpynt (szPIN, token_pass.password, nMaxPIN);
		purge_user_pass (&token_pass, true);

		if (strlen (szPIN) == 0) {
			return false;
		}
		else {
			return true;
		}
	}
}

bool
pkcs11_initialize (
	IN const bool fProtectedAuthentication,
	IN const int nPINCachePeriod
) {
	CK_RV rv = CKR_OK;

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_initialize - entered"
	);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot initialize %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setLogHook (_pkcs11_openvpn_log, NULL)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (rv == CKR_OK) {
		pkcs11h_setLogLevel (_pkcs11_msg_openvpn2pkcs11 (get_debug_level ()));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setTokenPromptHook (_pkcs11_openvpn_token_prompt, NULL)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setPINPromptHook (_pkcs11_openvpn_pin_prompt, NULL)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setProtectedAuthentication (fProtectedAuthentication)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot set protected authentication mode %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setPINCachePeriod (nPINCachePeriod)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot set PIN cache period %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_initialize - return %ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK;
}

void
pkcs11_terminate () {
	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_terminate - entered"
	);

	pkcs11h_terminate ();

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_terminate - return"
	);
}

void
pkcs11_forkFixup () {
	pkcs11h_forkFixup ();
}

bool
pkcs11_addProvider (
	IN const char * const provider,
	IN const bool fProtectedAuthentication,
	IN const char * const sign_mode,
	IN const bool fCertIsPrivate
) {
	unsigned maskSignMode = 0;

	CK_RV rv = CKR_OK;

	ASSERT (provider!=NULL);
	/*ASSERT (sign_mode!=NULL); NULL is default */

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_addProvider - entered - provider='%s', sign_mode='%s'",
		provider,
		sign_mode == NULL ? "default" : sign_mode
	);

	msg (
		M_INFO,
		"PKCS#11: Adding PKCS#11 provider '%s'",
		provider
	);

	if (rv == CKR_OK) {
		if (sign_mode == NULL || !strcmp (sign_mode, "auto")) {
			maskSignMode = 0;
		}
		else if (!strcmp (sign_mode, "sign")) {
			maskSignMode = PKCS11H_SIGNMODE_MASK_SIGN;
		}
		else if (!strcmp (sign_mode, "recover")) {
			maskSignMode = PKCS11H_SIGNMODE_MASK_RECOVER;
		}
		else if (!strcmp (sign_mode, "any")) {
			maskSignMode = (
				PKCS11H_SIGNMODE_MASK_SIGN |
				PKCS11H_SIGNMODE_MASK_RECOVER
			);
		}
		else {
			msg (M_FATAL, "PKCS#11: Invalid sign mode '%s'", sign_mode);
			rv = CKR_ARGUMENTS_BAD;
		}
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			fProtectedAuthentication,
			maskSignMode,
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			fCertIsPrivate
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot initialize provider '%s' %ld-'%s'", provider, rv, pkcs11h_getMessage (rv));
	}

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_addProvider - return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK;
}

int
SSL_CTX_use_pkcs11 (
	IN OUT SSL_CTX * const ssl_ctx,
	IN const char * const pkcs11_slot_type,
	IN const char * const pkcs11_slot,
	IN const char * const pkcs11_id_type,
	IN const char * const pkcs11_id
) {
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_certificate_t certificate = NULL;
	pkcs11h_openssl_session_t openssl_session = NULL;
	CK_RV rv = CKR_OK;

	bool fOK = true;

	ASSERT (ssl_ctx!=NULL);
	ASSERT (pkcs11_slot_type!=NULL);
	ASSERT (pkcs11_slot!=NULL);
	ASSERT (pkcs11_id_type!=NULL);
	ASSERT (pkcs11_id!=NULL);

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: SSL_CTX_use_pkcs11 - entered - ssl_ctx=%p, pkcs11_slot_type='%s', pkcs11_slot='%s', pkcs11_id_type='%s', pkcs11_id='%s'",
		(void *)ssl_ctx,
		pkcs11_slot_type,
		pkcs11_slot,
		pkcs11_id_type,
		pkcs11_id
	);

	ASSERT (ssl_ctx!=NULL);
	ASSERT (pkcs11_slot_type!=NULL);
	ASSERT (pkcs11_slot!=NULL);
	ASSERT (pkcs11_id_type!=NULL);
	ASSERT (pkcs11_id!=NULL);

	if (
		fOK &&
		(rv = pkcs11h_locate_certificate (
			pkcs11_slot_type,
			pkcs11_slot,
			pkcs11_id_type,
			pkcs11_id,
			&certificate_id
		)) != CKR_OK
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot set parameters %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		fOK &&
		(rv = pkcs11h_certificate_create (
			certificate_id,
			PKCS11H_PIN_CACHE_INFINITE,
			&certificate
		)) != CKR_OK
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot get certificate %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		fOK &&
		(openssl_session = pkcs11h_openssl_createSession (certificate)) == NULL
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot initialize openssl session");
	}

	if (fOK) {
		/*
		 * Will be released by openssl_session
		 */
		certificate = NULL;
	}

	if (
		fOK &&
		(rsa = pkcs11h_openssl_getRSA (openssl_session)) == NULL
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Unable get rsa object");
	}

	if (
		fOK &&
		(x509 = pkcs11h_openssl_getX509 (openssl_session)) == NULL
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Unable get certificate object");
	}

	if (
		fOK &&
		!SSL_CTX_use_RSAPrivateKey (ssl_ctx, rsa)
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot set private key for openssl");
	}

	if (
		fOK &&
		!SSL_CTX_use_certificate (ssl_ctx, x509)
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot set certificate for openssl");
	}

	/*
	 * openssl objects have reference
	 * count, so release them
	 */

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}

	if (rsa != NULL) {
		RSA_free (rsa);
		rsa = NULL;
	}

	if (certificate != NULL) {
		pkcs11h_freeCertificate (certificate);
		certificate = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}
	
	if (openssl_session != NULL) {
		pkcs11h_openssl_freeSession (openssl_session);
		openssl_session = NULL;
	}

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: SSL_CTX_use_pkcs11 - return fOK=%d, rv=%ld",
		fOK ? 1 : 0,
		rv
	);

	return fOK ? 1 : 0;
}

void
show_pkcs11_slots (
	const char * const provider
) {
	pkcs11h_standalone_dump_slots (
		_pkcs11_openvpn_print,
		NULL,
		provider
	);
}

void
show_pkcs11_objects (
	const char * const provider,
	const char * const slot,
	const char * const pin
) {
	pkcs11h_standalone_dump_objects (
		_pkcs11_openvpn_print,
		NULL,
		provider,
		slot,
		pin
	);
}

#else
static void dummy (void) {}
#endif /* ENABLE_PKCS11 */
