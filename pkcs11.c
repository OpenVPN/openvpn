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

#include "error.h"
#include "misc.h"
#include "ssl.h"

#if !defined(IN)
#define IN
#endif
#if !defined(OUT)
#define OUT
#endif

#if defined(WIN32)
#include "cryptoki-win32.h"
#else
#include "cryptoki.h"
#endif

#include "pkcs11.h"

/*===========================================
 * MACROS
 */

#define snprintf openvpn_snprintf

/*===========================================
 * Constants
 */

#if OPENSSL_VERSION_NUMBER < 0x00907000L && defined(CRYPTO_LOCK_ENGINE)
# define RSA_get_default_method RSA_get_default_openssl_method
#else
# ifdef HAVE_ENGINE_GET_DEFAULT_RSA
#  include <openssl/engine.h>
#  if OPENSSL_VERSION_NUMBER < 0x0090704fL
#   define BROKEN_OPENSSL_ENGINE
#  endif
# endif
#endif

#define PKCS11_MAX_ATTRIBUTE_SIZE (10*1024)

/*===========================================
 * Types
 */

typedef bool (*pkcs11_hook_card_prompt_t)(
	IN const void *pData,
	IN const char * const szLabel
);

typedef bool (*pkcs11_hook_pin_prompt_t)(
	IN const void *pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
);
	
typedef struct pkcs11_hooks_s {
	void *card_prompt_data;
	void *pin_prompt_data;
	pkcs11_hook_card_prompt_t card_prompt;
	pkcs11_hook_pin_prompt_t pin_prompt;
} *pkcs11_hooks_t;

typedef struct pkcs11_provider_s {
	struct pkcs11_provider_s *next;

	bool fEnabled;
	
#if defined(WIN32)
	HANDLE hLibrary;
#else
	void *hLibrary;
#endif
	CK_FUNCTION_LIST_PTR f;
	bool fShouldFinalize;
	char *szSignMode;

} *pkcs11_provider_t;

typedef struct pkcs11_session_s {

	pkcs11_provider_t provider;

	bool fProtectedAuthentication;

	char szLabel[sizeof (((CK_TOKEN_INFO *)NULL)->label)+1];
	CK_CHAR serialNumber[sizeof (((CK_TOKEN_INFO *)NULL)->serialNumber)];
	
	unsigned char *certificate;
	size_t certificate_size;
	unsigned char *certificate_id;
	size_t certificate_id_size;

	CK_SLOT_ID slot;
	bool fKeySignRecover;

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;

	time_t timePINExpire;
} *pkcs11_session_t;

typedef struct pkcs11_data_s {
	bool fInitialized;
	int nPINCachePeriod;
	pkcs11_provider_t providers;
	pkcs11_hooks_t hooks;
} *pkcs11_data_t;

/*===========================================
 * Low level prototypes
 */

static
void
_fixupFixedString (
	IN const char * const szSource,
	OUT char * const szTarget,			/* MUST BE >= nLength+1 */
	IN const size_t nLength				/* FIXED STRING LENGTH */
);
static
void
_hexToBinary (
	IN const char * const szSource,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
);
static
CK_RV
_pkcs11_getSlotById (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szSlot
);
static
CK_RV
_pkcs11_getSlotByName (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szName
);
static
CK_RV
_pkcs11_getSlotByLabel (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szLabel
);
static
CK_RV
_pkcs11_getObjectById (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_OBJECT_CLASS class,
	IN const unsigned char * const id,
	IN const size_t id_size,
	OUT CK_OBJECT_HANDLE * const handle
);
static
CK_RV
_pkcs11_setSessionTokenInfo (
	IN const pkcs11_session_t pkcs11_session
);
static
CK_RV
_pkcs11_resetSlot (
	IN const pkcs11_session_t pkcs11_session
);
static
CK_RV
_pkcs11_loadCertificate (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szIdType,
	IN const char * const szId
);
static
CK_RV
_pkcs11_loadKeyProperties (
	IN const pkcs11_session_t pkcs11_session
);
static
bool
_isBetterCertificate (
	IN const unsigned char * const pCurrent,
	IN const size_t nCurrentSize,
	IN const unsigned char * const pNew,
	IN const size_t nNewSize
);
static
CK_RV
_pkcs11_validateSession (
	IN const pkcs11_session_t pkcs11_session
);
static
CK_RV
_pkcs11_login (
	IN const pkcs11_session_t pkcs11_session
);
static
CK_RV
_pkcs11_logout (
	IN const pkcs11_session_t pkcs11_session
);

/*=========================================
 * Simplified functions prototypes
 */
static
bool
_pkcs11_hooks_card_prompt_default (
	IN const void *pData,
	IN const char * const szLabel
);
static
bool
_pkcs11_hooks_pin_prompt_default (
	IN const void *pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
);
static
CK_RV
pkcs11_initialize ();
static
CK_RV
pkcs11_terminate ();
static
CK_RV
pkcs11_setCardPromptHook (
	IN const pkcs11_hook_card_prompt_t hook,
	IN void * const pData
);
static
CK_RV
pkcs11_setPINPromptHook (
	IN const pkcs11_hook_pin_prompt_t hook,
	IN void * const pData
);
static
CK_RV
pkcs11_setPINCachePeriod (
	IN const int nPINCachePeriod
);
static
CK_RV
pkcs11_addProvider (
	IN const char * const szProvider,
	IN const char * const szSignMode
);
static
CK_RV
pkcs11_forkFixup ();
static
CK_RV
pkcs11_createSession (
	IN const char * const szSlotType,
	IN const char * const szSlot,
	IN const char * const szIdType,
	IN const char * const szId,
	IN const bool fProtectedAuthentication,
	OUT pkcs11_session_t * const pkcs11_session
);
static
CK_RV
pkcs11_freeSession (
	IN const pkcs11_session_t pkcs11_session
);
static
CK_RV
pkcs11_sign (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
);
static
CK_RV
pkcs11_signRecover (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
);
static
CK_RV
pkcs11_decrypt (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
);
static
CK_RV
pkcs11_getCertificate (
	IN const pkcs11_session_t pkcs11_session,
	OUT unsigned char * const certificate,
	IN OUT size_t * const certificate_size
);
static
char *
pkcs11_getMessage (
	IN const int rv
);

/*==========================================
 * Static data
 */

static pkcs11_data_t pkcs11_data = NULL;

/*==========================================
 * Internal utility functions
 */

static
void
_fixupFixedString (
	IN const char * const szSource,
	OUT char * const szTarget,			/* MUST BE >= nLength+1 */
	IN const size_t nLength				/* FIXED STRING LENGTH */
) {
	char *p;

	ASSERT (szSource!=NULL);
	ASSERT (szTarget!=NULL);
	
	p = szTarget+nLength;
	memmove (szTarget, szSource, nLength);
	*p = '\0';
	p--;
	while (p >= szTarget && *p == ' ') {
		*p = '\0';
		p--;
	}
}

static
void
_hexToBinary (
	IN const char * const szSource,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
) {
	size_t target_max_size;
	const char *p;
	char buf[3] = {'\0', '\0', '\0'};
	int i = 0;

	ASSERT (szSource!=NULL);
	ASSERT (target!=NULL);
	ASSERT (target_size!=NULL);

	target_max_size = *target_size;
	p = szSource;
	*target_size = 0;

	while (*p != '\0' && *target_size < target_max_size) {
		if (isxdigit (*p)) {
			buf[i%2] = *p;

			if ((i%2) == 1) {
				unsigned v;
				sscanf (buf, "%x", &v);
				target[*target_size] = v & 0xff;
				(*target_size)++;
			}

			i++;
		}
		p++;
	}
}

static
bool
_isBetterCertificate (
	IN const unsigned char * const pCurrent,
	IN const size_t nCurrentSize,
	IN const unsigned char * const pNew,
	IN const size_t nNewSize
) {
	/*
	 * This function compare the notBefore
	 * and select the most recent certificate
	 * it does not deal with timezones...
	 * When openssl will have ASN1_TIME compare function
	 * it should be used.
	 */

	X509 *x509Current = NULL, *x509New = NULL;
	char szNotBeforeCurrent[1024], szNotBeforeNew[1024];

	/*
	 * First certificae
	 * always select
	 */
	if (nCurrentSize == 0) {
		return true;
	}

	szNotBeforeCurrent[0] = '\0';
	szNotBeforeNew[0] = '\0';

	x509Current = X509_new ();
	x509New = X509_new ();

	if (x509Current != NULL && x509New != NULL) {
		const unsigned char *p1, *p2;

		p1 = pCurrent;
		p2 = pNew;
		if (
			d2i_X509 (&x509Current, (unsigned char **)&p1, nCurrentSize) &&
			d2i_X509 (&x509New, (unsigned char **)&p2, nNewSize)
		) {
			ASN1_TIME *notBeforeCurrent = X509_get_notBefore (x509Current);
			ASN1_TIME *notBeforeNew = X509_get_notBefore (x509New);

			if (
				notBeforeCurrent != NULL &&
				notBeforeNew != NULL &&
				notBeforeCurrent->length < (int) sizeof (szNotBeforeCurrent) - 1 &&
				notBeforeNew->length < (int) sizeof (szNotBeforeNew) - 1
			) {
				memmove (szNotBeforeCurrent, notBeforeCurrent->data, notBeforeCurrent->length);
				szNotBeforeCurrent[notBeforeCurrent->length] = '\0';
				memmove (szNotBeforeNew, notBeforeNew->data, notBeforeNew->length);
				szNotBeforeNew[notBeforeNew->length] = '\0';
			}
		}
	}

	if (x509Current != NULL) {
		X509_free (x509Current);
		x509Current = NULL;
	}
	if (x509New != NULL) {
		X509_free (x509New);
		x509New = NULL;
	}

	return strcmp (szNotBeforeCurrent, szNotBeforeNew) < 0;
}

/*========================================
 * Low level PKCS#11 functions
 */

static
CK_RV
_pkcs11_getSlotById (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szSlot
) {
	pkcs11_provider_t provider;
	int provider_number;
	int slot_number;
	int i;

	ASSERT (pkcs11_session!=NULL);
	ASSERT (szSlot!=NULL);

	if (strchr (szSlot, ':') == NULL) {
		provider_number = 0;
		slot_number = atoi (szSlot);
	}
	else {
		sscanf (szSlot, "%d:%d", &provider_number, &slot_number);
	}

	for (
		i=0, provider=pkcs11_data->providers;
		i < provider_number && provider != NULL;
		i++, provider = provider->next
	);

	if (
		provider == NULL ||
		(
			provider != NULL &&
			!provider->fEnabled
		)
	) {
		return CKR_SLOT_ID_INVALID;
	}

	pkcs11_session->provider = provider;
	pkcs11_session->slot = slot_number;
	return CKR_OK;
}

static
CK_RV
_pkcs11_getSlotByName (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szName
) {
	CK_RV rv;

	pkcs11_provider_t provider;
	bool fFound = false;

	ASSERT (pkcs11_session!=NULL);
	ASSERT (szName!=NULL);

	for (
		provider = pkcs11_data->providers;
		(
			provider != NULL &&
			!fFound
		);
		provider = provider->next
	) {
		CK_SLOT_ID slots[1024];
		CK_ULONG slotnum;

		if (!provider->fEnabled) {
			continue;
		}

		slotnum = sizeof (slots) / sizeof (CK_SLOT_ID);
		if (
			(rv = provider->f->C_GetSlotList (
				TRUE,
				slots,
				&slotnum
			)) == CKR_OK
		) {
			CK_SLOT_ID s;

			for (s=0;!fFound && s<slotnum;s++) {
				CK_SLOT_INFO info;

				if (
					(rv = provider->f->C_GetSlotInfo (
						slots[s],
						&info
					)) == CKR_OK
				) {
					char szCurrentName[sizeof (info.slotDescription)+1];
	
					_fixupFixedString (
						(char *)info.slotDescription,
						szCurrentName,
						sizeof (info.slotDescription)
					);

					if (!strcmp (szCurrentName, szName)) {
						fFound = true;
						pkcs11_session->provider = provider;
						pkcs11_session->slot = slots[s];
					}
				}
			}
		}
	}

	return fFound ? CKR_OK : CKR_SLOT_ID_INVALID;
}

static
CK_RV
_pkcs11_getSlotByLabel (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szLabel
) {
	CK_RV rv;

	pkcs11_provider_t provider;
	bool fFound = false;

	ASSERT (pkcs11_session!=NULL);
	ASSERT (szLabel!=NULL);

	for (
		provider = pkcs11_data->providers;
		(
			provider != NULL &&
			!fFound
		);
		provider = provider->next
	) {
		CK_SLOT_ID slots[1024];
		CK_ULONG slotnum;

		if (!provider->fEnabled) {
			continue;
		}

		slotnum = sizeof (slots) / sizeof (CK_SLOT_ID);
		if (
			(rv = provider->f->C_GetSlotList (
				TRUE,
				slots,
				&slotnum
			)) == CKR_OK
		) {
			CK_SLOT_ID s;

			for (s=0;!fFound && s<slotnum;s++) {
				CK_TOKEN_INFO info;

				if (
					(rv = provider->f->C_GetTokenInfo (
						slots[s],
						&info
					)) == CKR_OK
				) {
					char szCurrentLabel[sizeof (info.label)+1];
			
					_fixupFixedString (
						(char *)info.label,
						szCurrentLabel,
						sizeof (info.label)
					);

					if (!strcmp (szCurrentLabel, szLabel)) {
						fFound = true;
						pkcs11_session->provider = provider;
						pkcs11_session->slot = slots[s];
					}
				}
			}
		}
	}

	return fFound ? CKR_OK : CKR_SLOT_ID_INVALID;
}

static
CK_RV
_pkcs11_setSessionTokenInfo (
	IN const pkcs11_session_t pkcs11_session
) {
	CK_TOKEN_INFO info;
	CK_RV rv;

	ASSERT (pkcs11_session!=NULL);

	if (
		(rv = pkcs11_session->provider->f->C_GetTokenInfo (
			pkcs11_session->slot,
			&info
		)) == CKR_OK
	) {
		_fixupFixedString (
			(char *)info.label,
			pkcs11_session->szLabel,
			sizeof (info.label)
		);
		
		memmove (
			pkcs11_session->serialNumber,
			info.serialNumber,
			sizeof (pkcs11_session->serialNumber)
		);
	}

	return rv;
}

static
CK_RV
_pkcs11_resetSlot (
	IN const pkcs11_session_t pkcs11_session
) {
	CK_SLOT_ID slots[1024];
	CK_ULONG slotnum;
	CK_RV rv;
	bool fFound = false;
	bool fCancel = false;

	ASSERT (pkcs11_session!=NULL);

	do {
		slotnum = sizeof (slots) / sizeof (CK_SLOT_ID);
		if (
			(rv = pkcs11_session->provider->f->C_GetSlotList (
				TRUE,
				slots,
				&slotnum
			)) == CKR_OK
		) {
			CK_SLOT_ID s;

			for (s=0;!fFound && s<slotnum;s++) {
				CK_TOKEN_INFO info;

				if (
					(rv = pkcs11_session->provider->f->C_GetTokenInfo (
						slots[s],
						&info
					)) == CKR_OK
				) {
					if (
						!memcmp (
							pkcs11_session->serialNumber,
							info.serialNumber,
							sizeof (pkcs11_session->serialNumber)
						)
					) {
						pkcs11_session->slot = slots[s];
						fFound = true;
					}
				}
			}
		}

		if (!fFound) {
			fCancel = !pkcs11_data->hooks->card_prompt (
				pkcs11_data->hooks->card_prompt_data,
				pkcs11_session->szLabel
			);
		}
	} while (!fFound && !fCancel);

	return fFound ? CKR_OK : CKR_SLOT_ID_INVALID;
}

static
CK_RV
_pkcs11_getObjectById (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_OBJECT_CLASS class,
	IN const unsigned char * const id,
	IN const size_t id_size,
	OUT CK_OBJECT_HANDLE * const handle
) {
	CK_ULONG count;
	CK_RV rv = CKR_OK;

	CK_ATTRIBUTE filter[] = {
		{CKA_CLASS, (void *)&class, sizeof (class)},
		{CKA_ID, (void *)id, id_size}
	};
	
	ASSERT (pkcs11_session!=NULL);
	ASSERT (id!=NULL);
	ASSERT (handle!=NULL);

	if (rv == CKR_OK) {
		rv = pkcs11_session->provider->f->C_FindObjectsInit (
			pkcs11_session->session,
			filter,
			sizeof (filter) / sizeof (CK_ATTRIBUTE)
		);
	}

	if (rv == CKR_OK) {
		rv = pkcs11_session->provider->f->C_FindObjects (
			pkcs11_session->session,
			handle,
			1,
			&count
		);
	}

	if (
		rv == CKR_OK &&
		count == 0
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	pkcs11_session->provider->f->C_FindObjectsFinal (
		pkcs11_session->session
	);

	return rv;
}

static
CK_RV
_pkcs11_loadCertificate (
	IN const pkcs11_session_t pkcs11_session,
	IN const char * const szIdType,
	IN const char * const szId
) {
	CK_OBJECT_HANDLE objects[10];
	CK_ULONG objects_found;
	CK_RV rv;

	unsigned char selected_id[PKCS11_MAX_ATTRIBUTE_SIZE];
	int selected_id_size = 0;
	unsigned char selected_certificate[PKCS11_MAX_ATTRIBUTE_SIZE];
	int selected_certificate_size = 0;

	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	unsigned char cert_filter_by[PKCS11_MAX_ATTRIBUTE_SIZE];
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{0, cert_filter_by, 0}
	};

	ASSERT (pkcs11_session!=NULL);
	ASSERT (szIdType!=NULL);
	ASSERT (szId!=NULL);

	if (!strcmp (szIdType, "label")) {
		cert_filter[1].type = CKA_LABEL;
		cert_filter[1].ulValueLen = (CK_ULONG)(
			strlen (szId) < sizeof (cert_filter_by)  ?
			strlen (szId) :
			sizeof (cert_filter_by)
		);
		memmove (
			cert_filter_by,
			szId,
			cert_filter[1].ulValueLen
		);
	}
	else if (!strcmp (szIdType, "id")) {
		size_t s = sizeof (cert_filter_by);

		cert_filter[1].type = CKA_ID;
		_hexToBinary (
			szId,
			cert_filter_by,
			&s
		);
		cert_filter[1].ulValueLen = s;
	}
	else if (!strcmp (szIdType, "subject")) {
		memmove (&cert_filter[1], &cert_filter[0], sizeof (CK_ATTRIBUTE));
	}
	else {
		return CKR_ARGUMENTS_BAD;
	}

	if (
		(rv = pkcs11_session->provider->f->C_FindObjectsInit (
			pkcs11_session->session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE)
		)) != CKR_OK
	) {
		return rv;
	}

	while (
		(rv = pkcs11_session->provider->f->C_FindObjects (
			pkcs11_session->session,
			objects,
			sizeof (objects) / sizeof (CK_OBJECT_HANDLE),
			&objects_found
		)) == CKR_OK &&
		objects_found > 0
	) { 
		CK_ULONG i;
		
		for (i=0;i<objects_found;i++) {
			unsigned char attrs_id[PKCS11_MAX_ATTRIBUTE_SIZE];
			unsigned char attrs_value[PKCS11_MAX_ATTRIBUTE_SIZE];
			CK_ATTRIBUTE attrs[] = {
				{CKA_ID, attrs_id, sizeof (attrs_id)},
				{CKA_VALUE, attrs_value, sizeof (attrs_value)}
			};
	
			if (
				pkcs11_session->provider->f->C_GetAttributeValue (
					pkcs11_session->session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				) == CKR_OK
			) {
				bool fSelected = false;

				if (!strcmp (szIdType, "subject")) {
					X509 *x509 = NULL;
					char szSubject[1024];
					unsigned char *p;

					x509 = X509_new ();

					p = attrs_value;
					if (d2i_X509 (&x509, &p, attrs[1].ulValueLen)) {
  						X509_NAME_oneline (
							X509_get_subject_name (x509),
							szSubject,
							sizeof (szSubject)
						);
						szSubject[sizeof (szSubject) - 1] = '\0';
					}

					if (x509 != NULL) {
						X509_free (x509);
						x509 = NULL;
					}

					if (!strcmp (szId, szSubject)) {
						fSelected = true;
					}
				}
				else {
					fSelected = true;
				}

				if (
					fSelected &&
					_isBetterCertificate (
						selected_certificate,
						selected_certificate_size,
						attrs_value,
						attrs[1].ulValueLen
					)
				) {
					selected_certificate_size = attrs[1].ulValueLen;
					memmove (
						selected_certificate,
						attrs_value,
						selected_certificate_size
					);
					selected_id_size = attrs[0].ulValueLen;
					memmove (
						selected_id,
						attrs_id,
						selected_id_size
					);
				}
			}
		}
	}

	pkcs11_session->provider->f->C_FindObjectsFinal (
		pkcs11_session->session
	);

	if (selected_certificate_size == 0) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if ((pkcs11_session->certificate = (unsigned char *)malloc (selected_certificate_size)) == NULL) {
		return CKR_HOST_MEMORY;
	}
	pkcs11_session->certificate_size = selected_certificate_size;
	memmove (
		pkcs11_session->certificate,
		selected_certificate,
		selected_certificate_size
	);
	if ((pkcs11_session->certificate_id = (unsigned char *)malloc (selected_id_size)) == NULL) {
		return CKR_HOST_MEMORY;
	}
	pkcs11_session->certificate_id_size = selected_id_size;
	memmove (
		pkcs11_session->certificate_id,
		selected_id,
		selected_id_size
	);

	return CKR_OK;
}

static
CK_RV
_pkcs11_loadKeyProperties (
	IN const pkcs11_session_t pkcs11_session
) {
	CK_OBJECT_HANDLE key;
	CK_RV rv;

	CK_BBOOL key_attrs_sign_recover;
	CK_BBOOL key_attrs_sign;
	CK_ATTRIBUTE key_attrs[] = {
		{CKA_SIGN, &key_attrs_sign_recover, sizeof (key_attrs_sign_recover)},
		{CKA_SIGN_RECOVER, &key_attrs_sign, sizeof (key_attrs_sign)}
	};

	ASSERT (pkcs11_session!=NULL);

	if (!strcmp (pkcs11_session->provider->szSignMode, "recover")) {
		pkcs11_session->fKeySignRecover = true;
	}
	else if (!strcmp (pkcs11_session->provider->szSignMode, "sign")) {
		pkcs11_session->fKeySignRecover = false;
	}
	else {
		if (
			(rv = _pkcs11_getObjectById (
				pkcs11_session,
				CKO_PRIVATE_KEY,
				pkcs11_session->certificate_id,
				pkcs11_session->certificate_id_size,
				&key
			)) != CKR_OK
		) {
			return rv;
		}

		if (
			pkcs11_session->provider->f->C_GetAttributeValue (
				pkcs11_session->session,
				key,
				key_attrs,
				sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
			) == CKR_OK
		) {
			if (key_attrs_sign_recover != CK_FALSE) {
				pkcs11_session->fKeySignRecover = true;
			}
			else if (key_attrs_sign != CK_FALSE) {
				pkcs11_session->fKeySignRecover = false;
			}
			else {
				return CKR_KEY_TYPE_INCONSISTENT;
			}
		}

	}

	return CKR_OK;
}

static
CK_RV
_pkcs11_validateSession (
	IN const pkcs11_session_t pkcs11_session
) {
	if (
		pkcs11_session->timePINExpire != (time_t)0 &&
		pkcs11_session->timePINExpire < time (NULL)
	) {
		_pkcs11_logout (pkcs11_session);
	}
	return CKR_OK;
}

static
CK_RV
_pkcs11_login (
	IN const pkcs11_session_t pkcs11_session
) {
	CK_RV rv = CKR_OK;


	ASSERT (pkcs11_session!=NULL);

	_pkcs11_logout (pkcs11_session);

	if (rv == CKR_OK) {
		rv = _pkcs11_resetSlot (pkcs11_session);
	}

	if (rv == CKR_OK) {
		rv = pkcs11_session->provider->f->C_OpenSession (
			pkcs11_session->slot,
			CKF_SERIAL_SESSION,
			NULL_PTR,
			NULL_PTR,
			&pkcs11_session->session
		);
	}

	if (rv == CKR_OK) {
		int nRetryCount = 0;
		do {
			CK_UTF8CHAR_PTR utfPIN = NULL;
			CK_ULONG lPINLength = 0;
			char szPIN[1024];

			/*
			 * Assume OK for next iteration
			 */
			rv = CKR_OK;

			if (
				rv == CKR_OK &&
				!pkcs11_session->fProtectedAuthentication
			) {
				if (
					!pkcs11_data->hooks->pin_prompt (
						pkcs11_data->hooks->pin_prompt_data,
						pkcs11_session->szLabel,
						szPIN,
						sizeof (szPIN)
					)
				) {
					rv = CKR_FUNCTION_FAILED;
				}
				else {
					utfPIN = (CK_UTF8CHAR_PTR)szPIN;
					lPINLength = strlen (szPIN);
				}
			}

			if (pkcs11_data->nPINCachePeriod == -1) {
				pkcs11_session->timePINExpire = 0;
			}
			else {
				pkcs11_session->timePINExpire = (
					time (NULL) +
					(time_t)pkcs11_data->nPINCachePeriod
				);
			}
			if (
				rv == CKR_OK &&
				(rv = pkcs11_session->provider->f->C_Login (
					pkcs11_session->session,
					CKU_USER,
					utfPIN,
					lPINLength
				)) != CKR_OK
			) {
				if (rv == CKR_USER_ALREADY_LOGGED_IN) {
					rv = CKR_OK;
				}
			}

			/*
			 * Clean PIN buffer
			 */
			memset (szPIN, 0, sizeof (szPIN));
		} while (
			++nRetryCount < 3 &&
			(
				rv == CKR_PIN_INCORRECT ||
				rv == CKR_PIN_INVALID
			)
		);
	}

	if (
		rv == CKR_OK &&
		pkcs11_session->certificate_id != NULL
	) {
		rv = _pkcs11_getObjectById (
			pkcs11_session,
			CKO_PRIVATE_KEY,
			pkcs11_session->certificate_id,
			pkcs11_session->certificate_id_size,
			&pkcs11_session->key
		);
	}

	return rv;
}

static
CK_RV
_pkcs11_logout (
	IN const pkcs11_session_t pkcs11_session
) {
	ASSERT (pkcs11_session!=NULL);

	if (pkcs11_session->session != (CK_SESSION_HANDLE)-1) {
		pkcs11_session->provider->f->C_Logout (pkcs11_session->session);
		pkcs11_session->provider->f->C_CloseSession (pkcs11_session->session);
		pkcs11_session->key = (CK_OBJECT_HANDLE)-1;
		pkcs11_session->session = (CK_SESSION_HANDLE)-1;
	}

	return CKR_OK;
}


/*=======================================
 * Simplified PKCS#11 functions
 */

static
bool
_pkcs11_hooks_card_prompt_default (
	IN const void * pData,
	IN const char * const szLabel
) {
	return false;
}

static
bool
_pkcs11_hooks_pin_prompt_default (
	IN const void * pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	return false;
}

static
CK_RV
pkcs11_initialize () {

	pkcs11_terminate ();

	pkcs11_data = (pkcs11_data_t)malloc (sizeof (struct pkcs11_data_s));
	if (pkcs11_data == NULL) {
		return CKR_HOST_MEMORY;
	}

	memset (pkcs11_data, 0, sizeof (struct pkcs11_data_s));

	pkcs11_data->nPINCachePeriod = -1;

	pkcs11_data->hooks = (pkcs11_hooks_t)malloc (sizeof (struct pkcs11_hooks_s));
	if (pkcs11_data->hooks == NULL) {
		return CKR_HOST_MEMORY;
	}

	memset (pkcs11_data->hooks, 0, sizeof (struct pkcs11_hooks_s));

	pkcs11_data->fInitialized = true;

	pkcs11_setCardPromptHook (_pkcs11_hooks_card_prompt_default, NULL);
	pkcs11_setPINPromptHook (_pkcs11_hooks_pin_prompt_default, NULL);

	return CKR_OK;
}

static
CK_RV
pkcs11_terminate () {

	if (pkcs11_data != NULL) {
		pkcs11_provider_t last = NULL;

		for (
			;
			pkcs11_data->providers != NULL;
			pkcs11_data->providers = pkcs11_data->providers->next
		) {
			if (last != NULL) {
				free (last);
			}
			last = pkcs11_data->providers;
		
			if (pkcs11_data->providers->szSignMode != NULL) {
				free (pkcs11_data->providers->szSignMode);
				pkcs11_data->providers->szSignMode = NULL;
			}
	
			if (pkcs11_data->providers->fShouldFinalize) {
				pkcs11_data->providers->f->C_Finalize (NULL);
				pkcs11_data->providers->fShouldFinalize = false;
			}

			if (pkcs11_data->providers->f != NULL) {
				pkcs11_data->providers->f = NULL;
			}
	
			if (pkcs11_data->providers->hLibrary != NULL) {
#if defined(WIN32)
				FreeLibrary (pkcs11_data->providers->hLibrary);
#else
				dlclose (pkcs11_data->providers->hLibrary);
#endif
				pkcs11_data->providers->hLibrary = NULL;
			}
		}

		if (last != NULL) {
			free (last);
		}

		if (pkcs11_data->hooks != NULL) {
			free (pkcs11_data->hooks);
			pkcs11_data->hooks = NULL;
		}

		free (pkcs11_data);
		pkcs11_data = NULL;
	}

	return CKR_OK;
}

static
CK_RV
pkcs11_setPINPromptHook (
	IN const pkcs11_hook_pin_prompt_t hook,
	IN void * const pData
) {
	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);

	pkcs11_data->hooks->pin_prompt = hook;
	pkcs11_data->hooks->pin_prompt_data = pData;

	return CKR_OK;
}

static
CK_RV
pkcs11_setCardPromptHook (
	IN const pkcs11_hook_card_prompt_t hook,
	IN void * const pData
) {
	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);

	pkcs11_data->hooks->card_prompt = hook;
	pkcs11_data->hooks->card_prompt_data = pData;

	return CKR_OK;
}

static
CK_RV
pkcs11_setPINCachePeriod (
	IN const int nPINCachePeriod
) {
	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);

	pkcs11_data->nPINCachePeriod = nPINCachePeriod;

	return CKR_OK;
}

static
CK_RV
pkcs11_addProvider (
	IN const char * const szProvider,
	IN const char * const szSignMode
) {
	pkcs11_provider_t provider = NULL;
	CK_C_GetFunctionList gfl = NULL;
	CK_RV rv = CKR_OK;

	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);
	ASSERT (szProvider!=NULL);

	if (
		rv == CKR_OK &&
		(provider = (pkcs11_provider_t)malloc (sizeof (struct pkcs11_provider_s))) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}

	if (rv == CKR_OK) {
		memset (provider, 0, sizeof (struct pkcs11_provider_s));
		if (szSignMode == NULL) {
			provider->szSignMode = strdup ("auto");
		}
		else {
			provider->szSignMode = strdup (szSignMode);
		}
		if (provider->szSignMode == NULL) {
			rv = CKR_HOST_MEMORY;
		}
	}
		
	if (rv == CKR_OK) {
#if defined(WIN32)
		provider->hLibrary = LoadLibrary (szProvider);
#else
		provider->hLibrary = dlopen (szProvider, RTLD_NOW);
#endif
		if (provider->hLibrary == NULL) {
			rv = CKR_FUNCTION_FAILED;
		}
	}

	if (rv == CKR_OK) {
#if defined(WIN32)
		gfl = (CK_C_GetFunctionList)GetProcAddress (
			provider->hLibrary,
			"C_GetFunctionList"
		);
#else
		/*
		 * Make compiler happy!
		 */
		void *p = dlsym (
			provider->hLibrary,
			"C_GetFunctionList"
		);
		memmove (
			&gfl, 
			&p,
			sizeof (void *)
		);
#endif
		if (gfl == NULL) {
			rv = CKR_FUNCTION_FAILED;
		}
	}

	if (rv == CKR_OK) {
		rv = gfl (&provider->f);
	}

	if (rv == CKR_OK) {
		if ((rv = provider->f->C_Initialize (NULL)) != CKR_OK) {
			if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				rv = CKR_OK;
			}
		}
		else {
			provider->fShouldFinalize = true;
		}
	}

	if (rv == CKR_OK) {
		provider->fEnabled = true;
	}

	if (provider != NULL) {
		if (pkcs11_data->providers == NULL) {
			pkcs11_data->providers = provider;
		}
		else {
			pkcs11_provider_t last = NULL;
	
			for (
				last = pkcs11_data->providers;
				last->next != NULL;
				last = last->next
			);
			last->next = provider;
		}
	}

	return rv;
}

static
CK_RV
pkcs11_forkFixup () {

	if (pkcs11_data != NULL && pkcs11_data->fInitialized) {

		pkcs11_provider_t current;

		for (
			current = pkcs11_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->fEnabled) {
				current->f->C_Initialize (NULL);
			}
		}
	}

	return CKR_OK;
}
	
static
CK_RV
pkcs11_createSession (
	IN const char * const szSlotType,
	IN const char * const szSlot,
	IN const char * const szIdType,
	IN const char * const szId,
	IN const bool fProtectedAuthentication,
	OUT pkcs11_session_t * const p_pkcs11_session
) {
	pkcs11_session_t pkcs11_session;
	CK_RV rv = CKR_OK;

	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);
	ASSERT (szSlotType!=NULL);
	ASSERT (szSlot!=NULL);
	ASSERT (szIdType!=NULL);
	ASSERT (szId!=NULL);
	ASSERT (p_pkcs11_session!=NULL);
	
	if (
		rv == CKR_OK &&
		(pkcs11_session = (pkcs11_session_t)malloc (sizeof (struct pkcs11_session_s))) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}

	if (rv == CKR_OK) {
		*p_pkcs11_session = pkcs11_session;
		memset (pkcs11_session, 0, sizeof (struct pkcs11_session_s));
	}
	
	if (rv == CKR_OK) {
		pkcs11_session->key = (CK_OBJECT_HANDLE)-1;
		pkcs11_session->session = (CK_SESSION_HANDLE)-1;
		pkcs11_session->fProtectedAuthentication = fProtectedAuthentication;
	}

	if (rv == CKR_OK) {
		bool fCancel = false;

		do {
			if (!strcmp (szSlotType, "id")) {
				rv = _pkcs11_getSlotById (pkcs11_session, szSlot);
			}
			else if (!strcmp (szSlotType, "name")) {
				rv = _pkcs11_getSlotByName (pkcs11_session, szSlot);
			}
			else if (!strcmp (szSlotType, "label")) {
				rv = _pkcs11_getSlotByLabel (pkcs11_session, szSlot);
			}
			else {
				rv = CKR_ARGUMENTS_BAD;
			}

			if (rv == CKR_SLOT_ID_INVALID) {
				char szLabel[1024];
				snprintf (szLabel, sizeof (szLabel), "SLOT(%s=%s)", szSlotType, szSlot);
				fCancel = !pkcs11_data->hooks->card_prompt (
					pkcs11_data->hooks->card_prompt_data,
					szLabel
				);
			}
		} while (rv == CKR_SLOT_ID_INVALID && !fCancel);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11_setSessionTokenInfo (pkcs11_session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11_login (
			pkcs11_session
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11_loadCertificate (
			pkcs11_session,
			szIdType,
			szId
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11_loadKeyProperties (
			pkcs11_session
		);
	}
	
	/*
	 * Complete missing login process
	 */
	if (rv == CKR_OK) {
		rv = _pkcs11_getObjectById (
			pkcs11_session,
			CKO_PRIVATE_KEY,
			pkcs11_session->certificate_id,
			pkcs11_session->certificate_id_size,
			&pkcs11_session->key
		);
	}

	return rv;
}

CK_RV
pkcs11_freeSession (
	IN const pkcs11_session_t pkcs11_session
) {
	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);

	if (pkcs11_session != NULL) {
		_pkcs11_logout (pkcs11_session);

		if (pkcs11_session->certificate != NULL) {
			free (pkcs11_session->certificate);
		}
		if (pkcs11_session->certificate_id != NULL) {
			free (pkcs11_session->certificate_id);
		}

		free (pkcs11_session);
	}

	return CKR_OK;
}

static
CK_RV
pkcs11_sign (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
) {
	CK_MECHANISM mech = {
		mech_type, NULL, 0
	};
	CK_RV rv = CKR_OK;
	bool fLogonRetry = false;
	bool fOpSuccess = false;

	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);
	ASSERT (pkcs11_session!=NULL);
	ASSERT (source!=NULL);
	ASSERT (target_size!=NULL);

	rv = _pkcs11_validateSession (pkcs11_session);

	while (rv == CKR_OK && !fOpSuccess) {
		rv = pkcs11_session->provider->f->C_SignInit (
			pkcs11_session->session,
			&mech,
			pkcs11_session->key
		);

		if (rv == CKR_OK) {
			fOpSuccess = true;
		}
		else {
			if (!fLogonRetry) {
				fLogonRetry = true;
				rv = _pkcs11_login (pkcs11_session);
			}
		}
	}

	if (rv == CKR_OK) {
		CK_ULONG size = *target_size;
		rv = pkcs11_session->provider->f->C_Sign (
			pkcs11_session->session,
			(CK_BYTE_PTR)source,
			source_size,
			(CK_BYTE_PTR)target,
			&size
		);

		*target_size = (int)size;
	}

	return rv;
}

static
CK_RV
pkcs11_signRecover (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
) {
	CK_MECHANISM mech = {
		mech_type, NULL, 0
	};
	CK_RV rv = CKR_OK;
	bool fLogonRetry = false;
	bool fOpSuccess = false;

	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);
	ASSERT (pkcs11_session!=NULL);
	ASSERT (source!=NULL);
	ASSERT (target_size!=NULL);

	rv = _pkcs11_validateSession (pkcs11_session);

	while (rv == CKR_OK && !fOpSuccess) {
		rv = pkcs11_session->provider->f->C_SignRecoverInit (
			pkcs11_session->session,
			&mech,
			pkcs11_session->key
		);

		if (rv == CKR_OK) {
			fOpSuccess = true;
		}
		else {
			if (!fLogonRetry) {
				fLogonRetry = true;
				rv = _pkcs11_login (pkcs11_session);
			}
		}
	}

	if (rv == CKR_OK) {
		CK_ULONG size = *target_size;
		rv = pkcs11_session->provider->f->C_SignRecover (
			pkcs11_session->session,
			(CK_BYTE_PTR)source,
			source_size,
			(CK_BYTE_PTR)target,
			&size
		);

		*target_size = (int)size;
	}

	return rv;
}

static
CK_RV
pkcs11_decrypt (
	IN const pkcs11_session_t pkcs11_session,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const target_size
) {
	CK_MECHANISM mech = {
		mech_type, NULL, 0
	};
	CK_ULONG size;
	CK_RV rv = CKR_OK;
	bool fLogonRetry = false;
	bool fOpSuccess = false;

	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);
	ASSERT (pkcs11_session!=NULL);
	ASSERT (source!=NULL);
	ASSERT (target_size!=NULL);

	rv = _pkcs11_validateSession (pkcs11_session);

	while (rv == CKR_OK && !fOpSuccess) {
		rv = pkcs11_session->provider->f->C_DecryptInit (
			pkcs11_session->session,
			&mech,
			pkcs11_session->key
		);

		if (rv == CKR_OK) {
			fOpSuccess = true;
		}
		else {
			if (!fLogonRetry) {
				fLogonRetry = true;
				rv = _pkcs11_login (pkcs11_session);
			}
		}
	}

	if (rv == CKR_OK) {
		size = *target_size;
		rv = pkcs11_session->provider->f->C_Decrypt (
			pkcs11_session->session,
			(CK_BYTE_PTR)source,
			source_size,
			(CK_BYTE_PTR)target,
			&size
		);

		*target_size = (int)size;
	}

	return rv;
}

static
CK_RV
pkcs11_getCertificate (
	IN const pkcs11_session_t pkcs11_session,
	OUT unsigned char * const certificate,
	IN OUT size_t * const certificate_size
) {
	ASSERT (pkcs11_data!=NULL);
	ASSERT (pkcs11_data->fInitialized);
	ASSERT (certificate_size!=NULL);

	*certificate_size = pkcs11_session->certificate_size;

	if (certificate == NULL) {
		return CKR_OK;
	}

	if (*certificate_size > pkcs11_session->certificate_size) {
		return CKR_BUFFER_TOO_SMALL;
	}

	memmove (certificate, pkcs11_session->certificate, *certificate_size);	

	return CKR_OK;
}

static
char *
pkcs11_getMessage (
	IN const int rv
) {
	switch (rv) {
		case CKR_OK: return "CKR_OK";
		case CKR_CANCEL: return "CKR_CANCEL";
		case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
		case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
		case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
		case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
		case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
		case CKR_NO_EVENT: return "CKR_NO_EVENT";
		case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
		case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
		case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
		case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
		case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
		case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
		case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
		case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
		case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
		case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
		case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
		case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
		case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
		case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
		case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
		case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
		case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
		case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
		case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
		case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
		case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
		case CKR_FUNCTION_REJECTED: return "CKR_FUNCTION_REJECTED";
		case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
		default: return "Unknown PKCS#11 error";
	}
}

/*==========================================
 * openssl interface
 */

typedef struct openssl_session_s {
	RSA_METHOD smart_rsa;
	int (*orig_finish)(RSA *rsa);
	pkcs11_session_t pkcs11_session;
} *openssl_session_t;

static
pkcs11_session_t
_openssl_get_pkcs11_session (const RSA *rsa) {
	openssl_session_t session;
	
	ASSERT (rsa!=NULL);
	session = (openssl_session_t)RSA_get_app_data (rsa);
	ASSERT (session!=NULL);
	ASSERT (session->pkcs11_session!=NULL);

	return session->pkcs11_session;
}

static
int
openssl_pkcs11_priv_enc (
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	msg(M_WARN, "PKCS#11: Private key encryption not supported");
	return -1;
}

static
int
openssl_pkcs11_priv_dec (
	int flen, const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	pkcs11_session_t pkcs11_session = _openssl_get_pkcs11_session (rsa);
	CK_RV rv = CKR_OK;

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: openssl_pkcs11_priv_dec entered - flen=%d, from=%p, to=%p, rsa=%p, padding=%d",
		flen,
		from,
		to,
		(void *)rsa,
		padding
	);

	ASSERT (from!=NULL);
	ASSERT (to!=NULL);

	msg (
		D_SHOW_PKCS11,
		"PKCS#11: Performing decryption using private key"
	);

	if (padding != RSA_PKCS1_PADDING) {
		rv = CKR_ARGUMENTS_BAD;
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11_decrypt (
			pkcs11_session,
			CKM_RSA_PKCS,
			from,
			flen,
			to,
			(size_t *)&flen
		)) != CKR_OK
	) {
		msg (M_WARN, "PKCS#11: Cannot decrypt using private key %ld:'%s'", rv, pkcs11_getMessage (rv));
	}

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: openssl_pkcs11_priv_dec - return rv=%ld",
		rv
	);
	
	return rv == CKR_OK ? 1 : -1; 
}

static
int
openssl_pkcs11_sign (
	int type,
	const unsigned char *m,
	unsigned int m_len,
	unsigned char *sigret,
	unsigned int *siglen,
	const RSA *rsa
) {
	pkcs11_session_t pkcs11_session = _openssl_get_pkcs11_session (rsa);
	CK_RV rv = CKR_OK;

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: openssl_pkcs11_priv_sign entered - type=%d, m=%p, m_len=%u, signret=%p, signlen=%p, rsa=%p",
		type,
		m,
		m_len,
		sigret,
		(void *)siglen,
		(void *)rsa
	);

	ASSERT (m!=NULL);
	ASSERT (siglen!=NULL);

	msg (
		D_SHOW_PKCS11,
		"PKCS#11: Performing signature"
	);

	*siglen = RSA_size(rsa);

	if (pkcs11_session->fKeySignRecover) {
		if (
			(rv = pkcs11_signRecover (
				pkcs11_session,
				CKM_RSA_PKCS,
				m,
				m_len,
				sigret,
				siglen
			)) != CKR_OK
		) {
			msg (M_WARN, "PKCS#11: Cannot perform signature-recover %ld:'%s'", rv, pkcs11_getMessage (rv));
		}
	}
	else {
		if (
			(rv = pkcs11_sign (
				pkcs11_session,
				CKM_RSA_PKCS,
				m,
				m_len,
				sigret,
				siglen
			)) != CKR_OK
		) {
			msg (M_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11_getMessage (rv));
		}
	}

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: openssl_pkcs11_priv_sign - return rv=%ld",
		rv
	);
	
	return rv == CKR_OK ? 1 : -1; 
}

static
int
openssl_pkcs11_finish(RSA *rsa) {
	pkcs11_session_t pkcs11_session = _openssl_get_pkcs11_session (rsa);
	openssl_session_t openssl_session;

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: openssl_pkcs11_finish - entered rsa=%p",
		(void *)rsa
	);

	openssl_session = (openssl_session_t)RSA_get_app_data (rsa);

	RSA_set_app_data (rsa, NULL);
	pkcs11_freeSession (pkcs11_session);
	
	if (openssl_session->orig_finish != NULL) {
		openssl_session->orig_finish (rsa);

#ifdef BROKEN_OPENSSL_ENGINE
		{
			/* We get called TWICE here, once for
			 * releasing the key and also for
			 * releasing the engine.
			 * To prevent endless recursion, FIRST
			 * clear rsa->engine, THEN call engine->finish
			 */
			ENGINE *e = rsa->engine;
			rsa->engine = NULL;
			if (e) {
				ENGINE_finish(e);
			}
		}
#endif
	}

	free  (openssl_session);

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: openssl_pkcs11_finish - return"
	);
	
	return 1;
}

void
openssl_pkcs11_set_rsa(const openssl_session_t openssl_session, RSA *rsa)
{
	const RSA_METHOD *def = RSA_get_default_method();

	ASSERT (openssl_session!=NULL);
	ASSERT (rsa!=NULL);

	memmove (&openssl_session->smart_rsa, def, sizeof(RSA_METHOD));

	openssl_session->orig_finish = def->finish;

	openssl_session->smart_rsa.name = "pkcs11";
	openssl_session->smart_rsa.rsa_priv_enc = openssl_pkcs11_priv_enc;
	openssl_session->smart_rsa.rsa_priv_dec = openssl_pkcs11_priv_dec;
	openssl_session->smart_rsa.rsa_sign = openssl_pkcs11_sign;
	openssl_session->smart_rsa.finish = openssl_pkcs11_finish;
	openssl_session->smart_rsa.flags  = RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY;

	RSA_set_method (rsa, &openssl_session->smart_rsa);
	RSA_set_app_data (rsa, openssl_session);
	
#ifdef BROKEN_OPENSSL_ENGINE
	if (fOK) {
		if (!rsa->engine)
			rsa->engine = ENGINE_get_default_RSA();

		ENGINE_set_RSA(ENGINE_get_default_RSA(), openssl_session->smart_rsa);
		msg(M_WARN, "PKCS#11: OpenSSL engine support is broken! Workaround enabled");
	}
#endif
}


#ifdef BROKEN_OPENSSL_ENGINE
static void broken_openssl_init() __attribute__ ((constructor));
static void  broken_openssl_init()
{
	SSL_library_init();
	ENGINE_load_openssl();
	ENGINE_register_all_RSA();
}
#endif

/*==========================================
 * openvpn interface
 */

static
bool
_openvpn_pkcs11_card_prompt (
	IN const void *pData,
	IN const char * const szLabel
) {
	static struct user_pass token_pass;
	char szPrompt[1024];
	char szTemp[1024];

	ASSERT (szLabel!=NULL);

	openvpn_snprintf (szPrompt, sizeof (szPrompt), "INSERT");

	token_pass.defined = false;
	token_pass.nocache = true;
	get_user_pass (&token_pass, NULL, true, szPrompt, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_SENSITIVE);
	strncpynt (szTemp, token_pass.password, sizeof (szTemp));
	purge_user_pass (&token_pass, true);

	if (strlen (szTemp) == 0) {
		return false;
	}
	else {
		return true;
	}
}

static
bool
_openvpn_pkcs11_pin_prompt (
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
	get_user_pass (&token_pass, NULL, true, szPrompt, GET_USER_PASS_MANAGEMENT|GET_USER_PASS_SENSITIVE);
	strncpynt (szPIN, token_pass.password, nMaxPIN);
	purge_user_pass (&token_pass, true);

	if (strlen (szPIN) == 0) {
		return false;
	}
	else {
		return true;
	}
}

void
init_pkcs11 (
	const int nPINCachePeriod
) {
	CK_RV rv;

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: init_pkcs11 - entered"
	);

	if ((rv = pkcs11_initialize ()) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot initialize %ld-'%s'", rv, pkcs11_getMessage (rv));
	}
/*Until REQUEST/REPLY interface.
	if ((rv = pkcs11_setCardPromptHook (_openvpn_pkcs11_card_prompt, NULL)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11_getMessage (rv));
	}
*/
	if ((rv = pkcs11_setPINPromptHook (_openvpn_pkcs11_pin_prompt, NULL)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	if ((rv = pkcs11_setPINCachePeriod (nPINCachePeriod)) != CKR_OK) {
		msg (M_FATAL, "PKCS#11: Cannot set PIN cache period %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: init_pkcs11 - return"
	);
}

void
free_pkcs11 () {
	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: free_pkcs11 - entered"
	);

	pkcs11_terminate ();

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: free_pkcs11 - return"
	);
}

void
fork_fix_pkcs11 () {
	pkcs11_forkFixup ();
}

void
add_pkcs11 (
	IN const char * const provider,
	IN const char * const sign_mode
) {
	CK_RV rv;

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: add_pkcs11 - entered - provider='%s', sign_mode='%s'",
		provider,
		sign_mode == NULL ? "default" : sign_mode
	);

	msg (
		M_INFO,
		"PKCS#11: Adding PKCS#11 provider '%s'",
		provider
	);

	if ((rv = pkcs11_addProvider (provider, sign_mode)) != CKR_OK) {
		msg (M_WARN, "PKCS#11: Cannot initialize provider '%s' %ld-'%s'", provider, rv, pkcs11_getMessage (rv));
	}

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: add_pkcs11 - return"
	);
}

int
SSL_CTX_use_pkcs11 (
	IN OUT SSL_CTX * const ssl_ctx,
	IN const char * const pkcs11_slot_type,
	IN const char * const pkcs11_slot,
	IN const char * const pkcs11_id_type,
	IN const char * const pkcs11_id,
	IN const bool pkcs11_protected_authentication
) {
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pubkey = NULL;
	openssl_session_t openssl_session = NULL;
	bool fShouldFreeOpenSSLSession = true;
	CK_RV rv = CKR_OK;

	unsigned char certificate[10*1024];
	size_t certificate_size;
	unsigned char *p;
	bool fOK = true;

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: SSL_CTX_use_pkcs11 - entered - ssl_ctx=%p, pkcs11_slot_type='%s', pkcs11_slot='%s', pkcs11_id_type='%s', pkcs11_id='%s', pkcs11_protected_authentication=%d",
		(void *)ssl_ctx,
		pkcs11_slot_type,
		pkcs11_slot,
		pkcs11_id_type,
		pkcs11_id,
		pkcs11_protected_authentication ? 1 : 0
	);

	ASSERT (ssl_ctx!=NULL);
	ASSERT (pkcs11_slot_type!=NULL);
	ASSERT (pkcs11_slot!=NULL);
	ASSERT (pkcs11_id_type!=NULL);
	ASSERT (pkcs11_id!=NULL);

	if (
		fOK &&
		(openssl_session = (openssl_session_t)malloc (sizeof (struct openssl_session_s))) == NULL
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot allocate memory");
	}

	if (fOK) {
		memset (openssl_session, 0, sizeof (struct openssl_session_s));
	}
	
	if (
		fOK &&
		(rv = pkcs11_createSession (
			pkcs11_slot_type,
			pkcs11_slot,
			pkcs11_id_type,
			pkcs11_id,
			pkcs11_protected_authentication,
			&openssl_session->pkcs11_session
		)) != CKR_OK
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot set parameters %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	if (
		fOK &&
		(x509 = X509_new ()) == NULL
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Unable to allocate certificate object");
	}

	certificate_size = sizeof (certificate);
	if (
		fOK &&
		(rv = pkcs11_getCertificate (
			openssl_session->pkcs11_session,
			certificate,
			&certificate_size
		)) != CKR_OK
	) { 
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot read X.509 certificate from token %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	p = certificate;
	if (
		fOK &&
		!d2i_X509 (&x509, &p, certificate_size)
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Unable to parse X.509 certificate");
	}

	if (
		fOK &&
		(pubkey = X509_get_pubkey (x509)) == NULL
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot get public key");
	}
	
	if (
		fOK &&
		pubkey->type != EVP_PKEY_RSA
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Invalid public key algorithm");
	}

	if (
		fOK &&
		(rsa = EVP_PKEY_get1_RSA (pubkey)) == NULL
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot get RSA key");
	}

	if (fOK) {
		openssl_pkcs11_set_rsa (openssl_session, rsa);
		rsa->flags |= RSA_FLAG_SIGN_VER;

		/* it will be freed when rsa usage count will be zero */
		fShouldFreeOpenSSLSession = false;
	}

	if (
		fOK &&
		!SSL_CTX_use_certificate (ssl_ctx, x509)
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot set certificate for openssl");
	}

	if (
		fOK &&
		!SSL_CTX_use_RSAPrivateKey (ssl_ctx, rsa)
	) {
		fOK = false;
		msg (M_WARN, "PKCS#11: Cannot set private key for openssl");
	}

	/*
	 * openssl objects have reference
	 * count, so release them
	 */
	if (pubkey != NULL) {
		EVP_PKEY_free (pubkey);
		pubkey = NULL;
	}

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}

	if (rsa != NULL) {
		RSA_free (rsa);
		rsa = NULL;
	}

	if (fShouldFreeOpenSSLSession) {
		if (openssl_session != NULL) {
			if (openssl_session->pkcs11_session != NULL) {
				pkcs11_freeSession (openssl_session->pkcs11_session);
			}
			free (openssl_session);
			openssl_session = NULL;
		}
	}

	msg (
		D_PKCS11_DEBUG,
		"PKCS#11: SSL_CTX_use_pkcs11 - return fOK=%d, rv=%ld",
		fOK ? 1 : 0,
		rv
	);

	return fOK;
}

void
show_pkcs11_slots (
	IN const int msglev,
	IN const int warnlev,
	IN const char * const provider
) {
	CK_INFO info;
	CK_SLOT_ID slots[1024];
	CK_ULONG slotnum;
	CK_SLOT_ID s;
	CK_RV rv;

	pkcs11_provider_t pkcs11_provider;

	ASSERT (provider!=NULL);

	if (
		(rv = pkcs11_initialize ()) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot initialize interface %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	if (
		(rv = pkcs11_addProvider (provider, NULL)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot initialize provider %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	pkcs11_provider = pkcs11_data->providers;
	if (pkcs11_provider == NULL || !pkcs11_provider->fEnabled) {
		msg (M_FATAL, "PKCS#11: Cannot get provider %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	if (
		(rv = pkcs11_provider->f->C_GetInfo (&info)) != CKR_OK
	) {
		msg (warnlev, "PKCS#11: Cannot get PKCS#11 provider information %ld-'%s'", rv, pkcs11_getMessage (rv));
	}
	else {
		char szManufacturerID[sizeof (info.manufacturerID)+1];

		_fixupFixedString (
			(char *)info.manufacturerID,
			szManufacturerID,
			sizeof (info.manufacturerID)
		);

		msg (
			msglev,
			(
			 	"Provider Information:\n"
				"\tcryptokiVersion: %u.%u\n"
				"\tmanufacturerID: %s\n"
				"\tflags: %d\n"
			),
			info.cryptokiVersion.major,
			info.cryptokiVersion.minor,
			szManufacturerID,
			(unsigned)info.flags
		);
	}
	
	slotnum = sizeof (slots) / sizeof (CK_SLOT_ID);
	if (
		(rv = pkcs11_provider->f->C_GetSlotList (
			FALSE,
			slots,
			&slotnum
		)) != CKR_OK
	) {
		msg (warnlev, "PKCS#11: Cannot get slot list %ld-'%s'", rv, pkcs11_getMessage (rv));
	}
	else {
		msg (
			msglev,
			(
			 	"The following slots are available for use with this provider.\n"
				"Each slot shown below may be used as a parameter to a\n"
				"--pkcs11-slot-type and --pkcs11-slot options.\n"
				"\n"
				"Slots: (id - name)"
			)
		);
		for (s=0;s<slotnum;s++) {
			CK_SLOT_INFO info;

			if (
				(rv = pkcs11_provider->f->C_GetSlotInfo (
					slots[s],
					&info
				)) == CKR_OK
			) {
				char szCurrentName[sizeof (info.slotDescription)+1];
			
				_fixupFixedString (
					(char *)info.slotDescription,
					szCurrentName,
					sizeof (info.slotDescription)
				);

				msg (msglev, "\t%lu - %s", slots[s], szCurrentName);
			}
		}
	}

	pkcs11_terminate ();
}

static
bool
_show_pkcs11_objects_pin_prompt (
	IN const void *pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	strncpy (szPIN, (char *)pData, nMaxPIN);
	return true;
}

void
show_pkcs11_objects (
	IN const int msglev,
	IN const int warnlev,
	IN const char * const provider,
	IN const char * const slot,
	IN const char * const pin
) {
	CK_OBJECT_HANDLE objects[10];
	CK_SESSION_HANDLE session;
	CK_ULONG objects_found;
	CK_TOKEN_INFO info;
	CK_SLOT_ID s;
	CK_RV rv;

	pkcs11_provider_t pkcs11_provider;

	ASSERT (provider!=NULL);
	ASSERT (slot!=NULL);
	ASSERT (pin!=NULL);

	s = atoi (slot);

	if (
		(rv = pkcs11_initialize ()) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot initialize interface %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	if (
		(rv = pkcs11_setPINPromptHook (_show_pkcs11_objects_pin_prompt, (void *)pin)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot set hooks %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	if (
		(rv = pkcs11_addProvider (provider, NULL)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot initialize provider %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

  	/*
	 * our provider is head
	 */
	pkcs11_provider = pkcs11_data->providers;
	if (pkcs11_provider == NULL || !pkcs11_provider->fEnabled) {
		msg (M_FATAL, "PKCS#11: Cannot get provider %ld-'%s'", rv, pkcs11_getMessage (rv));
	}

	if (
		(rv = pkcs11_provider->f->C_GetTokenInfo (
			s,
			&info
		)) != CKR_OK
	) {
		msg (warnlev, "PKCS#11: Cannot get token information for slot %ld %ld-'%s'", s, rv, pkcs11_getMessage (rv));
	}
	else {
		char szLabel[sizeof (info.label)+1];
		char szManufacturerID[sizeof (info.manufacturerID)+1];
		char szModel[sizeof (info.model)+1];
		char szSerialNumber[sizeof (info.serialNumber)+1];
		
		_fixupFixedString (
			(char *)info.label,
			szLabel,
			sizeof (info.label)
		);
		_fixupFixedString (
			(char *)info.manufacturerID,
			szManufacturerID,
			sizeof (info.manufacturerID)
		);
		_fixupFixedString (
			(char *)info.model,
			szModel,
			sizeof (info.model)
		);
		_fixupFixedString (
			(char *)info.serialNumber,
			szSerialNumber,
			sizeof (info.serialNumber)
		);

		msg (
			msglev,
			(
			 	"Token Information:\n"
				"\tlabel:\t\t%s\n"
				"\tmanufacturerID:\t%s\n"
				"\tmodel:\t\t%s\n"
				"\tserialNumber:\t%s\n"
				"\tflags:\t\t%08x\n"
				"\n"
				"You can access this token using\n"
				"--pkcs11-slot-type \"label\" --pkcs11-slot \"%s\" options.\n"
			),
			szLabel,
			szManufacturerID,
			szModel,
			szSerialNumber,
			(unsigned)info.flags,
			szLabel
		);
	}

	if (
		(rv = pkcs11_provider->f->C_OpenSession (
			s,
			CKF_SERIAL_SESSION,
			NULL_PTR,
			NULL_PTR,
			&session
		)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot open session to slot %ld %ld-'%s'", s, rv, pkcs11_getMessage (rv));
	}

	if (
		(rv = pkcs11_provider->f->C_Login (
			session,
			CKU_USER,
			(CK_CHAR_PTR)pin,
			(CK_ULONG)strlen (pin)
		)) != CKR_OK &&
		rv != CKR_USER_ALREADY_LOGGED_IN
	) {
		msg (M_FATAL, "PKCS#11: Cannot login to token on slot %ld %ld-'%s'", s, rv, pkcs11_getMessage (rv));
	}

	if (
		(rv = pkcs11_provider->f->C_FindObjectsInit (
			session,
			NULL,
			0
		)) != CKR_OK
	) {
		msg (M_FATAL, "PKCS#11: Cannot query objects for token on slot %ld %ld-'%s'", s, rv, pkcs11_getMessage (rv));
	}

	msg (
		msglev,
		"The following objects are available for use with this token.\n"
		"Each object shown below may be used as a parameter to\n"
		"--pkcs11-id-type and --pkcs11-id options.\n"
	);

	while (
		(rv = pkcs11_provider->f->C_FindObjects (
			session,
			objects,
			sizeof (objects) / sizeof (CK_OBJECT_HANDLE),
			&objects_found
		)) == CKR_OK &&
		objects_found > 0
	) { 
		CK_ULONG i;
		
		for (i=0;i<objects_found;i++) {
			CK_OBJECT_CLASS attrs_class;
			unsigned char attrs_id[PKCS11_MAX_ATTRIBUTE_SIZE];
			unsigned char attrs_label[PKCS11_MAX_ATTRIBUTE_SIZE];
			CK_ATTRIBUTE attrs[] = {
				{CKA_CLASS, &attrs_class, sizeof (attrs_class)},
				{CKA_ID, attrs_id, sizeof (attrs_id)},
				{CKA_LABEL, attrs_label, sizeof (attrs_label)-1}
			};
	
			if (
				pkcs11_provider->f->C_GetAttributeValue (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				) == CKR_OK
			) {
				int id_len = attrs[1].ulValueLen;
				int j;
					
				attrs_label[attrs[2].ulValueLen] = 0;

				msg (
					msglev,
					(
					 	"Object\n"
						"\tLabel:\t\t%s\n"
						"\tId:"
					),
					attrs_label
				);

					
				for (j=0;j<id_len;j+=16) {
					char szLine[3*16+1];
					int k;

					szLine[0] = '\0';
					for (k=0;k<16 && j+k<id_len;k++) {
						sprintf (szLine+strlen (szLine), "%02x ", attrs_id[j+k]);
					}

					msg (msglev, "\t\t%s", szLine);
				}

				if (attrs_class == CKO_CERTIFICATE) {
					unsigned char certificate[PKCS11_MAX_ATTRIBUTE_SIZE];
					CK_ATTRIBUTE attrs_cert[] = {
						{CKA_VALUE, certificate, sizeof (certificate)}
					};

					msg (msglev, "\tType:\t\tCertificate");

					if (
						pkcs11_provider->f->C_GetAttributeValue (
							session,
							objects[i],
							attrs_cert,
							sizeof (attrs_cert) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK
					) {
						X509 *x509 = NULL;
						BIO *bioSerial = NULL;

						char szSubject[1024];
						char szSerial[1024];
						char szNotBefore[1024];

						szSubject[0] = '\0';
						szSerial[0] = '\0';
						szNotBefore[0] = '\0';

						if ((x509 = X509_new ()) == NULL) {
							msg (warnlev, "Cannot create x509 context");
						}
						else {
							unsigned char *p;

							p = certificate;
							if (d2i_X509 (&x509, &p, attrs_cert[0].ulValueLen)) {

								ASN1_TIME *notBefore = X509_get_notBefore (x509);
								if (notBefore != NULL && notBefore->length < (int) sizeof (szNotBefore) - 1) {
									memmove (szNotBefore, notBefore->data, notBefore->length);
									szNotBefore[notBefore->length] = '\0';
								}

  								X509_NAME_oneline (
									X509_get_subject_name (x509),
									szSubject,
									sizeof (szSubject)
								);
								szSubject[sizeof (szSubject) - 1] = '\0';
							}
						}

						if ((bioSerial = BIO_new (BIO_s_mem ())) == NULL) {
							msg (warnlev, "Cannot create BIO context");
						}
						else {
							int n;

							i2a_ASN1_INTEGER(bioSerial, X509_get_serialNumber (x509));
							n = BIO_read (bioSerial, szSerial, sizeof (szSerial)-1);
							if (n<0) {
								szSerial[0] = '\0';
							}
							else {
								szSerial[n] = '\0';
							}
						}


						if (x509 != NULL) {
							X509_free (x509);
							x509 = NULL;
						}
						if (bioSerial != NULL) {
							BIO_free_all (bioSerial);
							bioSerial = NULL;
						}

						msg (
							msglev,
							(
							 	"\tsubject:\t%s\n"
								"\tserialNumber:\t%s\n"
								"\tnotBefore:\t%s"
							),
							szSubject,
							szSerial,
							szNotBefore
						);
					}
				}
				else if (attrs_class == CKO_PRIVATE_KEY) {
					CK_BBOOL sign_recover;
					CK_BBOOL sign;
					CK_ATTRIBUTE attrs_key[] = {
						{CKA_SIGN, &sign_recover, sizeof (sign_recover)},
						{CKA_SIGN_RECOVER, &sign, sizeof (sign)}
					};

					msg (msglev, "\tType:\t\tPrivate Key");

					if (
						pkcs11_provider->f->C_GetAttributeValue (
							session,
							objects[i],
							attrs_key,
							sizeof (attrs_key) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK
					) {
						msg (
							msglev,
							(
								"\tSign:\t\t%s\n"
								"\tSign Recover:\t%s"
							),
							sign ? "TRUE" : "FALSE",
							sign_recover ? "TRUE" : "FALSE"
						);
					}
				}
				else {
					msg (msglev, "\tType:\t\tUnsupported");
				}
			}
		}
	}
	pkcs11_provider->f->C_FindObjectsFinal (session);
	pkcs11_provider->f->C_Logout (session);
	pkcs11_provider->f->C_CloseSession (session);
	pkcs11_terminate ();
}

#else
static void dummy (void) {}
#endif /* ENABLE_PKCS11 */
