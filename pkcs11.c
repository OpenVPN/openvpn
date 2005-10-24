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

#define snprintf openvpn_snprintf

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
bool
_pkcs11_openvpn_card_prompt (
	IN const void *pData,
	IN const char * const szLabel
) {
	static struct user_pass token_resp;

	ASSERT (szLabel!=NULL);

	CLEAR (token_resp);
	token_resp.defined = false;
	token_resp.nocache = true;
	openvpn_snprintf (token_resp.username, sizeof (token_resp.username), "Please insert %s token", szLabel);
	get_user_pass (&token_resp, NULL, "token-insertion-request", GET_USER_PASS_MANAGEMENT|GET_USER_PASS_NEED_OK);

	return strcmp (token_resp.password, "ok") == 0;
}

static
bool
_pkcs11_openvpn_pin_prompt (
	IN const void *pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	static struct user_pass token_pass;
	char szPrompt[1024];

	ASSERT (szLabel!=NULL);

	openvpn_snprintf (szPrompt, sizeof (szPrompt), "%s token", szLabel);

	token_pass.defined = false;
	token_pass.nocache = true;
	get_user_pass (&token_pass, NULL, szPrompt, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_PASSWORD_ONLY);
	strncpynt (szPIN, token_pass.password, nMaxPIN);
	purge_user_pass (&token_pass, true);

	if (strlen (szPIN) == 0) {
		return false;
	}
	else {
		return true;
	}
}

bool
pkcs11_initialize (
	const int nPINCachePeriod
) {
	CK_RV rv = CKR_OK;

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11_initialize - entered"
	);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		PKCS11LOG (PKCS11_LOG_ERROR, "PKCS#11: Cannot initialize %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setCardPromptHook (_pkcs11_openvpn_card_prompt, NULL)) != CKR_OK
	) {
		PKCS11LOG (PKCS11_LOG_ERROR, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setPINPromptHook (_pkcs11_openvpn_pin_prompt, NULL)) != CKR_OK
	) {
		PKCS11LOG (PKCS11_LOG_ERROR, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setPINCachePeriod (nPINCachePeriod)) != CKR_OK
	) {
		PKCS11LOG (PKCS11_LOG_ERROR, "PKCS#11: Cannot set PIN cache period %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11_initialize - return %ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK;
}

void
pkcs11_terminate () {
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11_terminate - entered"
	);

	pkcs11h_terminate ();

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
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
	IN const char * const sign_mode
) {
	CK_RV rv = CKR_OK;

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11_addProvider - entered - provider='%s', sign_mode='%s'",
		provider,
		sign_mode == NULL ? "default" : sign_mode
	);

	PKCS11LOG (
		PKCS11_LOG_INFO,
		"PKCS#11: Adding PKCS#11 provider '%s'",
		provider
	);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (provider, sign_mode)) != CKR_OK
	) {
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot initialize provider '%s' %ld-'%s'", provider, rv, pkcs11h_getMessage (rv));
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11_addProvider - return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK;
}

int
SSL_CTX_use_pkcs11 (
	IN OUT SSL_CTX * const ssl_ctx,
	IN const char * const pkcs11h_slot_type,
	IN const char * const pkcs11h_slot,
	IN const char * const pkcs11h_id_type,
	IN const char * const pkcs11h_id,
	IN const bool pkcs11h_protected_authentication
) {
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	pkcs11h_openssl_session_t pkcs11h_openssl_session = NULL;
	CK_RV rv = CKR_OK;

	bool fOK = true;

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: SSL_CTX_use_pkcs11 - entered - ssl_ctx=%p, pkcs11h_slot_type='%s', pkcs11h_slot='%s', pkcs11h_id_type='%s', pkcs11h_id='%s', pkcs11h_protected_authentication=%d",
		(void *)ssl_ctx,
		pkcs11h_slot_type,
		pkcs11h_slot,
		pkcs11h_id_type,
		pkcs11h_id,
		pkcs11h_protected_authentication ? 1 : 0
	);

	PKCS11ASSERT (ssl_ctx!=NULL);
	PKCS11ASSERT (pkcs11h_slot_type!=NULL);
	PKCS11ASSERT (pkcs11h_slot!=NULL);
	PKCS11ASSERT (pkcs11h_id_type!=NULL);
	PKCS11ASSERT (pkcs11h_id!=NULL);

	if (
		fOK &&
		(pkcs11h_openssl_session = pkcs11h_openssl_createSession ()) == NULL
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot initialize openssh session");
	}

	if (
		fOK &&
		(rv = pkcs11h_createCertificateSession (
			pkcs11h_slot_type,
			pkcs11h_slot,
			pkcs11h_id_type,
			pkcs11h_id,
			pkcs11h_protected_authentication,
			PKCS11H_PIN_CACHE_INFINITE,
			&pkcs11h_openssl_session->pkcs11h_certificate
		)) != CKR_OK
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot set parameters %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	if (
		fOK &&
		(rsa = pkcs11h_openssl_getRSA (pkcs11h_openssl_session)) == NULL
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Unable get rsa object");
	}

	if (
		fOK &&
		(x509 = pkcs11h_openssl_getX509 (pkcs11h_openssl_session)) == NULL
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Unable get certificate object");
	}

	if (
		fOK &&
		!SSL_CTX_use_RSAPrivateKey (ssl_ctx, rsa)
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot set private key for openssl");
	}

	if (
		fOK &&
		!SSL_CTX_use_certificate (ssl_ctx, x509)
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot set certificate for openssl");
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
	
	if (pkcs11h_openssl_session != NULL) {
		pkcs11h_openssl_freeSession (pkcs11h_openssl_session);
		pkcs11h_openssl_session = NULL;
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
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
