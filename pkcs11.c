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

#include "syshead.h"

#if defined(ENABLE_PKCS11)

#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include <pkcs11-helper-1.0/pkcs11h-openssl.h>
#include "basic.h"
#include "error.h"
#include "manage.h"
#include "base64.h"
#include "pkcs11.h"
#include "misc.h"
#include "otime.h"

static
time_t
__mytime (void) {
	return openvpn_time (NULL);
}

#if !defined(_WIN32)
static
int
__mygettimeofday (struct timeval *tv) {
	return gettimeofday (tv, NULL);
}
#endif

static
void
__mysleep (const unsigned long usec) {
#if defined(_WIN32)
	Sleep (usec/1000);
#else
	usleep (usec);
#endif
}


static pkcs11h_engine_system_t s_pkcs11h_sys_engine = {
	malloc,
	free,
	__mytime,
	__mysleep,
#if defined(_WIN32)
	NULL
#else
	__mygettimeofday
#endif
};

static
unsigned
_pkcs11_msg_pkcs112openvpn (
	const unsigned flags
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
	const unsigned flags
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
_pkcs11_openvpn_log (
	void * const global_data,
	unsigned flags,
	const char * const szFormat,
	va_list args
) {
	char Buffer[10*1024];

	(void)global_data;
	
	vsnprintf (Buffer, sizeof (Buffer), szFormat, args);
	Buffer[sizeof (Buffer)-1] = 0;

	msg (_pkcs11_msg_pkcs112openvpn (flags), "%s", Buffer);
}

static
PKCS11H_BOOL
_pkcs11_openvpn_token_prompt (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry
) {
	struct user_pass token_resp;

	(void)global_data;
	(void)user_data;
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
PKCS11H_BOOL
_pkcs11_openvpn_pin_prompt (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry,
	char * const pin,
	const size_t pin_max
) {
	struct user_pass token_pass;
	char prompt[1024];

	(void)global_data;
	(void)user_data;
	(void)retry;

	ASSERT (token!=NULL);

	openvpn_snprintf (prompt, sizeof (prompt), "%s token", token->label);

	token_pass.defined = false;
	token_pass.nocache = true;
	
	if (
		!get_user_pass (
			&token_pass,
			NULL,
			prompt,
			GET_USER_PASS_MANAGEMENT|GET_USER_PASS_PASSWORD_ONLY|GET_USER_PASS_NOFATAL
		)
	) {
		return false;
	}
	else {
		strncpynt (pin, token_pass.password, pin_max);
		purge_user_pass (&token_pass, true);

		if (strlen (pin) == 0) {
			return false;
		}
		else {
			return true;
		}
	}
}

bool
pkcs11_initialize (
	const bool protected_auth,
	const int nPINCachePeriod
) {
	CK_RV rv = CKR_FUNCTION_FAILED;

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_initialize - entered"
	);

	if ((rv = pkcs11h_engine_setSystem (&s_pkcs11h_sys_engine)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot initialize system engine %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot initialize %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_setLogHook (_pkcs11_openvpn_log, NULL)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	pkcs11h_setLogLevel (_pkcs11_msg_openvpn2pkcs11 (get_debug_level ()));

	if ((rv = pkcs11h_setForkMode (TRUE)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set fork mode %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_setTokenPromptHook (_pkcs11_openvpn_token_prompt, NULL)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_setPINPromptHook (_pkcs11_openvpn_pin_prompt, NULL)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_setProtectedAuthentication (protected_auth)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set protected authentication mode %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_setPINCachePeriod (nPINCachePeriod)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set Pcache period %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	rv = CKR_OK;

cleanup:
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
	const char * const provider,
	const bool protected_auth,
	const unsigned private_mode,
	const bool cert_private
) {
	CK_RV rv = CKR_OK;

	ASSERT (provider!=NULL);

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_addProvider - entered - provider='%s', private_mode=%08x",
		provider,
		private_mode
	);

	msg (
		M_INFO,
		"PKCS#11: Adding PKCS#11 provider '%s'",
		provider
	);

	if (
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			protected_auth,
			private_mode,
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			cert_private
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
pkcs11_logout() {
	return pkcs11h_logout () == CKR_OK;
}

int
pkcs11_management_id_count () {
	pkcs11h_certificate_id_list_t id_list = NULL;
	pkcs11h_certificate_id_list_t t = NULL;
	CK_RV rv = CKR_OK;
	int count = 0;

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_management_id_count - entered"
	);

	if (
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE_EXIST,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			NULL,
			&id_list
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot get certificate list %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	for (count = 0, t = id_list; t != NULL; t = t->next) {
		count++;
	}

cleanup:

	if (id_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (id_list);
		id_list = NULL;
	}

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_management_id_count - return count=%d",
		count
	);

	return count;
}

bool
pkcs11_management_id_get (
	const int index,
	char ** id,
	char **base64
) {
	pkcs11h_certificate_id_list_t id_list = NULL;
	pkcs11h_certificate_id_list_t entry = NULL;
#if 0 /* certificate_id seems to be unused -- JY */
	pkcs11h_certificate_id_t certificate_id = NULL;
#endif
	pkcs11h_certificate_t certificate = NULL;
	CK_RV rv = CKR_OK;
	unsigned char *certificate_blob = NULL;
	size_t certificate_blob_size = 0;
	size_t max;
	char *internal_id = NULL;
	char *internal_base64 = NULL;
	int count = 0;
	bool success = false;

	ASSERT (id!=NULL);
	ASSERT (base64!=NULL);

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_management_id_get - entered index=%d",
		index
	);

	*id = NULL;
	*base64 = NULL;

	if (
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE_EXIST,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			NULL,
			&id_list
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot get certificate list %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	entry = id_list;
	count = 0;
	while (entry != NULL && count != index) {
		count++;
		entry = entry->next;
	}

	if (entry == NULL) {
		dmsg (
			D_PKCS11_DEBUG,
			"PKCS#11: pkcs11_management_id_get - no certificate at index=%d",
			index
		);
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_serializeCertificateId (
			NULL,
			&max,
			entry->certificate_id
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot serialize certificate id %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((internal_id = (char *)malloc (max)) == NULL) {
		msg (M_FATAL, "PKCS#11: Cannot allocate memory");
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_serializeCertificateId (
			internal_id,
			&max,
			entry->certificate_id
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot serialize certificate id %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_create (
			entry->certificate_id,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&certificate
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot get certificate %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_getCertificateBlob (
			certificate,
			NULL,
			&certificate_blob_size
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot get certificate blob %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((certificate_blob = (unsigned char *)malloc (certificate_blob_size)) == NULL) {
		msg (M_FATAL, "PKCS#11: Cannot allocate memory");
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_getCertificateBlob (
			certificate,
			certificate_blob,
			&certificate_blob_size
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot get certificate blob %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if (base64_encode (certificate_blob, certificate_blob_size, &internal_base64) == -1) {
		msg (M_WARN, "PKCS#11: Cannot encode certificate");
		goto cleanup;
	}

	*id = internal_id;
	internal_id = NULL;
	*base64 = internal_base64;
	internal_base64 = NULL;
	success = true;
	
cleanup:

	if (id_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (id_list);
		id_list = NULL;
	}

	if (internal_id != NULL) {
		free (internal_id);
		internal_id = NULL;
	}

	if (internal_base64 != NULL) {
		free (internal_base64);
		internal_base64 = NULL;
	}

	if (certificate_blob != NULL) {
		free (certificate_blob);
		certificate_blob = NULL;
	}

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: pkcs11_management_id_get - return success=%d, id='%s'",
		success ? 1 : 0,
		*id
	);

	return success;
}

int
SSL_CTX_use_pkcs11 (
	SSL_CTX * const ssl_ctx,
	bool pkcs11_id_management,
	const char * const pkcs11_id
) {
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_certificate_t certificate = NULL;
	pkcs11h_openssl_session_t openssl_session = NULL;
	CK_RV rv = CKR_OK;

	bool ok = false;

	ASSERT (ssl_ctx!=NULL);
	ASSERT (pkcs11_id_management || pkcs11_id!=NULL);

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: SSL_CTX_use_pkcs11 - entered - ssl_ctx=%p, pkcs11_id_management=%d, pkcs11_id='%s'",
		(void *)ssl_ctx,
		pkcs11_id_management ? 1 : 0,
		pkcs11_id
	);

	if (pkcs11_id_management) {
		struct user_pass id_resp;

		CLEAR (id_resp);

		id_resp.defined = false;
		id_resp.nocache = true;
		openvpn_snprintf (
			id_resp.username,
			sizeof (id_resp.username),
			"Please specify PKCS#11 id to use"
		);

		if (
			!get_user_pass (
				&id_resp,
				NULL,
				"pkcs11-id-request",
				GET_USER_PASS_MANAGEMENT|GET_USER_PASS_NEED_STR|GET_USER_PASS_NOFATAL
			)
		) {
			goto cleanup;
		}

		if (
			(rv = pkcs11h_certificate_deserializeCertificateId (
				&certificate_id,
				id_resp.password
			)) != CKR_OK
		) {
			msg (M_WARN, "PKCS#11: Cannot deserialize id %ld-'%s'", rv, pkcs11h_getMessage (rv));
			goto cleanup;
		}
	}
	else {
		if (
			(rv = pkcs11h_certificate_deserializeCertificateId (
				&certificate_id,
				pkcs11_id
			)) != CKR_OK
		) {
			msg (M_WARN, "PKCS#11: Cannot deserialize id %ld-'%s'", rv, pkcs11h_getMessage (rv));
			goto cleanup;
		}
	}

	if (
		(rv = pkcs11h_certificate_create (
			certificate_id,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&certificate
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot get certificate %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((openssl_session = pkcs11h_openssl_createSession (certificate)) == NULL	) {
		msg (M_WARN, "PKCS#11: Cannot initialize openssl session");
		goto cleanup;
	}

	/*
	 * Will be released by openssl_session
	 */
	certificate = NULL;

	if ((rsa = pkcs11h_openssl_session_getRSA (openssl_session)) == NULL) {
		msg (M_WARN, "PKCS#11: Unable get rsa object");
		goto cleanup;
	}

	if ((x509 = pkcs11h_openssl_session_getX509 (openssl_session)) == NULL) {
		msg (M_WARN, "PKCS#11: Unable get certificate object");
		goto cleanup;
	}

	if (!SSL_CTX_use_RSAPrivateKey (ssl_ctx, rsa)) {
		msg (M_WARN, "PKCS#11: Cannot set private key for openssl");
		goto cleanup;
	}

	if (!SSL_CTX_use_certificate (ssl_ctx, x509)) {
		msg (M_WARN, "PKCS#11: Cannot set certificate for openssl");
		goto cleanup;
	}

	ok = true;

cleanup:
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
		pkcs11h_certificate_freeCertificate (certificate);
		certificate = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}
	
	if (openssl_session != NULL) {
		pkcs11h_openssl_freeSession (openssl_session);
		openssl_session = NULL;
	}

	dmsg (
		D_PKCS11_DEBUG,
		"PKCS#11: SSL_CTX_use_pkcs11 - return ok=%d, rv=%ld",
		ok ? 1 : 0,
		rv
	);

	return ok ? 1 : 0;
}

static
bool
_pkcs11_openvpn_show_pkcs11_ids_pin_prompt (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry,
	char * const pin,
	const size_t pin_max
) {
	struct gc_arena gc = gc_new ();
	struct buffer pass_prompt = alloc_buf_gc (128, &gc);

	(void)global_data;
	(void)user_data;
	(void)retry;

	ASSERT (token!=NULL);

	buf_printf (&pass_prompt, "Please enter '%s' token PIN or 'cancel': ", token->display);

	if (!get_console_input (BSTR (&pass_prompt), false, pin, pin_max)) {
		msg (M_FATAL, "Cannot read password from stdin");
	}

	gc_free (&gc);

	if (!strcmp (pin, "cancel")) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}

void
show_pkcs11_ids (
	const char * const provider,
	bool cert_private
) {
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t current = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot initialize %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_setLogHook (_pkcs11_openvpn_log, NULL)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	pkcs11h_setLogLevel (_pkcs11_msg_openvpn2pkcs11 (get_debug_level ()));

	if ((rv = pkcs11h_setProtectedAuthentication (TRUE)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set protected authentication %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = pkcs11h_setPINPromptHook (_pkcs11_openvpn_show_pkcs11_ids_pin_prompt, NULL)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set PIN hook %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if (
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			TRUE,
			0,
			FALSE,
			0,
			cert_private ? TRUE : FALSE
		)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot add provider '%s' %ld-'%s'", provider, rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE_EXIST,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			NULL,
			&user_certificates
		)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot enumerate certificates %ld-'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	msg (
		M_INFO|M_NOPREFIX|M_NOLF,
		(
			"\n"
			"The following objects are available for use.\n"
			"Each object shown below may be used as parameter to\n"
			"--pkcs11-id option please remember to use single quote mark.\n"
		)
	);
	for (current = user_certificates;current != NULL; current = current->next) {
		pkcs11h_certificate_t certificate = NULL;
		X509 *x509 = NULL;
		BIO *bio = NULL;
		char dn[1024] = {0};
		char serial[1024] = {0};
		char *ser = NULL;
		size_t ser_len = 0;
		int n;

		if (
			(rv = pkcs11h_certificate_serializeCertificateId (
				NULL,
				&ser_len,
				current->certificate_id
			)) != CKR_OK
		) {
			msg (M_FATAL, "PKCS#11: Cannot serialize certificate %ld-'%s'", rv, pkcs11h_getMessage (rv));
			goto cleanup1;
		}

		if (
			rv == CKR_OK &&
			(ser = (char *)malloc (ser_len)) == NULL
		) {
			msg (M_FATAL, "PKCS#11: Cannot allocate memory");
			goto cleanup1;
		}

		if (
			(rv = pkcs11h_certificate_serializeCertificateId (
				ser,
				&ser_len,
				current->certificate_id
			)) != CKR_OK
		) {
			msg (M_FATAL, "PKCS#11: Cannot serialize certificate %ld-'%s'", rv, pkcs11h_getMessage (rv));
			goto cleanup1;
		}

		if (
			(rv = pkcs11h_certificate_create (
				current->certificate_id,
				NULL,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				PKCS11H_PIN_CACHE_INFINITE,
				&certificate
			))
		) {
			msg (M_FATAL, "PKCS#11: Cannot create certificate %ld-'%s'", rv, pkcs11h_getMessage (rv));
			goto cleanup1;
		}

		if ((x509 = pkcs11h_openssl_getX509 (certificate)) == NULL) {
			msg (M_FATAL, "PKCS#11: Cannot get X509");
			goto cleanup1;
		}

		X509_NAME_oneline (
			X509_get_subject_name (x509),
			dn,
			sizeof (dn)
		);

		if ((bio = BIO_new (BIO_s_mem ())) == NULL) {
			msg (M_FATAL, "PKCS#11: Cannot create BIO");
			goto cleanup1;
		}

		i2a_ASN1_INTEGER(bio, X509_get_serialNumber (x509));
		n = BIO_read (bio, serial, sizeof (serial)-1);
		if (n<0) {
			serial[0] = '\x0';
		}
		else {
			serial[n] = 0;
		}

		msg (
			M_INFO|M_NOPREFIX|M_NOLF,
			(
				"\n"
				"Certificate\n"
				"       DN:             %s\n"
				"       Serial:         %s\n"
				"       Serialized id:  %s\n"
			),
			dn,
			serial,
			ser
		);

	cleanup1:
		if (x509 != NULL) {
			X509_free (x509);
			x509 = NULL;
		}

		if (certificate != NULL) {
			pkcs11h_certificate_freeCertificate (certificate);
			certificate = NULL;
		}

		if (ser != NULL) {
			free (ser);
			ser = NULL;
		}
	}

cleanup:
	if (user_certificates != NULL) {
		pkcs11h_certificate_freeCertificateIdList (user_certificates);
		user_certificates = NULL;
	}

	pkcs11h_terminate ();
}

#else
#ifdef _MSC_VER  /* Dummy function needed to avoid empty file compiler warning in Microsoft VC */
static void dummy (void) {}
#endif
#endif /* ENABLE_PKCS11 */
