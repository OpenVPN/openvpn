/*
 * Copyright (c) 2005 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The routines in this file deal with providing private key cryptography
 * using RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki).
 *
 */

#ifndef __PKCS11_HELPER_H
#define __PKCS11_HELPER_H

#include "pkcs11-helper-config.h"

#define PKCS11H_MAX_ATTRIBUTE_SIZE	(10*1024)
#define PKCS11H_PIN_CACHE_INFINITE	-1

typedef void (*pkcs11h_output_print_t)(
	IN const void *pData,
	IN const char * const szFormat,
	IN ...
);

typedef bool (*pkcs11h_hook_card_prompt_t)(
	IN const void *pData,
	IN const char * const szLabel
);

typedef bool (*pkcs11h_hook_pin_prompt_t)(
	IN const void *pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
);


typedef struct pkcs11h_hooks_s {
	void *card_prompt_data;
	void *pin_prompt_data;
	pkcs11h_hook_card_prompt_t card_prompt;
	pkcs11h_hook_pin_prompt_t pin_prompt;
} *pkcs11h_hooks_t;

typedef struct pkcs11h_provider_s {
	struct pkcs11h_provider_s *next;

	bool fEnabled;
	char *szName;
	
#if defined(WIN32)
	HANDLE hLibrary;
#else
	void *hLibrary;
#endif
	CK_FUNCTION_LIST_PTR f;
	bool fShouldFinalize;
	char *szSignMode;

} *pkcs11h_provider_t;

typedef struct pkcs11h_session_s {
	struct pkcs11h_session_s *next;

	int nReferenceCount;
	bool fValid;

	pkcs11h_provider_t provider;

	bool fProtectedAuthentication;

	char szLabel[sizeof (((CK_TOKEN_INFO *)NULL)->label)+1];
	CK_CHAR serialNumber[sizeof (((CK_TOKEN_INFO *)NULL)->serialNumber)];

	CK_SESSION_HANDLE hSession;

	int nPINCachePeriod;
	time_t timePINExpire;
} *pkcs11h_session_t;

typedef struct pkcs11h_certificate_s {

	pkcs11h_session_t session;

	unsigned char *certificate;
	size_t certificate_size;
	unsigned char *certificate_id;
	size_t certificate_id_size;

	enum {
		pkcs11h_signmode_none = 0,
		pkcs11h_signmode_sign,
		pkcs11h_signmode_recover
	} signmode;

	CK_OBJECT_HANDLE hKey;

	bool fCertPrivate;
} *pkcs11h_certificate_t;

typedef struct pkcs11h_data_s {
	bool fInitialized;
	int nPINCachePeriod;

	pkcs11h_provider_t providers;
	pkcs11h_session_t sessions;
	pkcs11h_hooks_t hooks;

	CK_SESSION_HANDLE session;
} *pkcs11h_data_t;

typedef struct pkcs11h_openssl_session_s {
	int nReferenceCount;
	bool fInitialized;
	X509 *x509;
	RSA_METHOD smart_rsa;
	int (*orig_finish)(RSA *rsa);
	pkcs11h_certificate_t certificate;
} *pkcs11h_openssl_session_t;

CK_RV
pkcs11h_initialize ();

CK_RV
pkcs11h_terminate ();

CK_RV
pkcs11h_setCardPromptHook (
	IN const pkcs11h_hook_card_prompt_t hook,
	IN void * const pData
);

CK_RV
pkcs11h_setPINPromptHook (
	IN const pkcs11h_hook_pin_prompt_t hook,
	IN void * const pData
);

CK_RV
pkcs11h_setPINCachePeriod (
	IN const int nPINCachePeriod
);

CK_RV
pkcs11h_addProvider (
	IN const char * const szProvider,
	IN const char * const szSignMode
);

CK_RV
pkcs11h_forkFixup ();

CK_RV
pkcs11h_createCertificateSession (
	IN const char * const szSlotType,
	IN const char * const szSlot,
	IN const char * const szIdType,
	IN const char * const szId,
	IN const bool fProtectedAuthentication,
	IN const bool fCertPrivate,
	IN const int nPINCachePeriod,
	OUT pkcs11h_certificate_t * const pkcs11h_certificate
);

CK_RV
pkcs11h_freeCertificateSession (
	IN const pkcs11h_certificate_t pkcs11h_certificate
);

CK_RV
pkcs11h_sign (
	IN const pkcs11h_certificate_t pkcs11h_certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
);

CK_RV
pkcs11h_signRecover (
	IN const pkcs11h_certificate_t pkcs11h_certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
);

CK_RV
pkcs11h_decrypt (
	IN const pkcs11h_certificate_t pkcs11h_certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
);

CK_RV
pkcs11h_getCertificate (
	IN const pkcs11h_certificate_t pkcs11h_certificate,
	OUT unsigned char * const certificate,
	IN OUT size_t * const certificate_size
);

char *
pkcs11h_getMessage (
	IN const int rv
);

pkcs11h_openssl_session_t
pkcs11h_openssl_createSession ();

void
pkcs11h_openssl_freeSession (
	IN const pkcs11h_openssl_session_t pkcs11h_openssl_session
);

RSA *
pkcs11h_openssl_getRSA (
	IN const pkcs11h_openssl_session_t pkcs11h_openssl_session
);

X509 *
pkcs11h_openssl_getX509 (
	IN const pkcs11h_openssl_session_t pkcs11h_openssl_session
);

void
pkcs11h_standalone_dump_slots (
	IN const pkcs11h_output_print_t my_output,
	IN const void *pData,
	IN const char * const provider
);

void
pkcs11h_standalone_dump_objects (
	IN const pkcs11h_output_print_t my_output,
	IN const void *pData,
	IN const char * const provider,
	IN const char * const slot,
	IN const char * const pin
);

#endif
