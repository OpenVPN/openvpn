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

#include "pkcs11-helper-config.h"

#if defined(PKCS11H_ENABLE_HELPER)

#if defined(WIN32)
#include "cryptoki-win32.h"
#else
#include "cryptoki.h"
#endif

#include "pkcs11-helper.h"

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


/*===========================================
 * Low level prototypes
 */

static
void
_pkcs11h_fixupFixedString (
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
_pkcs11h_getSlotById (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szSlot
);
static
CK_RV
_pkcs11h_getSlotByName (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szName
);
static
CK_RV
_pkcs11h_getSlotByLabel (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szLabel
);
static
CK_RV
_pkcs11h_getObjectById (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const CK_OBJECT_CLASS class,
	IN const unsigned char * const id,
	IN const size_t id_size,
	OUT CK_OBJECT_HANDLE * const handle
);
static
CK_RV
_pkcs11h_setSessionTokenInfo (
	IN const pkcs11h_session_t pkcs11h_session
);
static
CK_RV
_pkcs11h_resetSlot (
	IN const pkcs11h_session_t pkcs11h_session
);
static
CK_RV
_pkcs11h_loadCertificate (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szIdType,
	IN const char * const szId
);
static
CK_RV
_pkcs11h_loadKeyProperties (
	IN const pkcs11h_session_t pkcs11h_session
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
_pkcs11h_validateSession (
	IN const pkcs11h_session_t pkcs11h_session
);
static
CK_RV
_pkcs11h_login (
	IN const pkcs11h_session_t pkcs11h_session
);
static
CK_RV
_pkcs11h_logout (
	IN const pkcs11h_session_t pkcs11h_session
);
static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN const unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT const RSA *rsa
);

/*==========================================
 * openssl interface
 */

static
int
_pkcs11h_openssl_finish (
	IN OUT RSA *rsa
);
static
int
_pkcs11h_openssl_priv_dec (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
);
static
int
_pkcs11h_openssl_priv_enc (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
);
static
pkcs11h_openssl_session_t
_pkcs11h_openssl_get_pkcs11h_openssl_session (
	IN OUT const RSA *rsa
);  
static
pkcs11h_session_t
_pkcs11h_openssl_get_pkcs11h_session (
	IN OUT const RSA *rsa
);  

/*==========================================
 * Static data
 */

pkcs11h_data_t pkcs11h_data = NULL;

/*==========================================
 * Internal utility functions
 */

static
void
_pkcs11h_fixupFixedString (
	IN const char * const szSource,
	OUT char * const szTarget,			/* MUST BE >= nLength+1 */
	IN const size_t nLength				/* FIXED STRING LENGTH */
) {
	char *p;

	PKCS11ASSERT (szSource!=NULL);
	PKCS11ASSERT (szTarget!=NULL);
	
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

	PKCS11ASSERT (szSource!=NULL);
	PKCS11ASSERT (target!=NULL);
	PKCS11ASSERT (target_size!=NULL);

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
	bool fBetter = false;

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _isBetterCertificate entry pCurrent=%p, nCurrentSize=%u, pNew=%p, nNewSize=%u",
		pCurrent,
		nCurrentSize,
		pNew,
		nNewSize
	);

	/*
	 * First certificae
	 * always select
	 */
	if (nCurrentSize == 0) {
		fBetter = true;
	}
	else {
		PKCS11ASSERT (pCurrent!=NULL);
		PKCS11ASSERT (pNew!=NULL);

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

		fBetter = strcmp (szNotBeforeCurrent, szNotBeforeNew) < 0;
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _isBetterCertificate return fBetter=%d",
		fBetter ? 1 : 0
	);
	
	return fBetter;
}

/*========================================
 * Low level PKCS#11 functions
 */

static
CK_RV
_pkcs11h_getSlotById (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szSlot
) {
	pkcs11h_provider_t provider;
	CK_RV rv = CKR_OK;
	int provider_number;
	int slot_number;
	int i;

	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (szSlot!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSlotById entry pkcs11h_session=%p, szSlot=%s",
		(void *)pkcs11h_session,
		szSlot
	);

	if (rv == CKR_OK) {
		if (strchr (szSlot, ':') == NULL) {
			provider_number = 0;
			slot_number = atoi (szSlot);
		}
		else {
			sscanf (szSlot, "%d:%d", &provider_number, &slot_number);
		}
	}
	
	if (rv == CKR_OK) {
		for (
			i=0, provider=pkcs11h_data->providers;
			(
				i < provider_number &&
				provider != NULL &&
				rv == CKR_OK
			);
			i++, provider = provider->next
		);
	
		if (
			provider == NULL ||
			(
				provider != NULL &&
				!provider->fEnabled
			)
		) {
			rv = CKR_SLOT_ID_INVALID;
		}
	}
	
	if (rv == CKR_OK) {
		pkcs11h_session->provider = provider;
		pkcs11h_session->slot = slot_number;
	
		PKCS11LOG (
			PKCS11_LOG_DEBUG1,
			"PKCS#11: slot selected %s-%ld",
			pkcs11h_session->provider->szName,
			pkcs11h_session->slot
		);
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSlotById return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_getSlotByName (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szName
) {
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t provider;
	bool fFound = false;

	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (szName!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSlotByName entry pkcs11h_session=%p, szName=%s",
		(void *)pkcs11h_session,
		szName
	);

	for (
		provider = pkcs11h_data->providers;
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
	
					_pkcs11h_fixupFixedString (
						(char *)info.slotDescription,
						szCurrentName,
						sizeof (info.slotDescription)
					);

					if (!strcmp (szCurrentName, szName)) {
						fFound = true;
						pkcs11h_session->provider = provider;
						pkcs11h_session->slot = slots[s];
					
						PKCS11LOG (
							PKCS11_LOG_DEBUG1,
							"PKCS#11: slot selected %s-%ld",
							pkcs11h_session->provider->szName,
							pkcs11h_session->slot
						);
					}
				}
			}
		}
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSlotByName return fFound=%d-'%s'",
		fFound ? 1 : 0,
		pkcs11h_getMessage (rv)
	);

	return fFound ? CKR_OK : CKR_SLOT_ID_INVALID;
}

static
CK_RV
_pkcs11h_getSlotByLabel (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szLabel
) {
	CK_RV rv;

	pkcs11h_provider_t provider;
	bool fFound = false;

	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (szLabel!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"_PKCS#11: pkcs11h_getSlotByLabel entry pkcs11h_session=%p, szName=%s",
		(void *)pkcs11h_session,
		szLabel
	);

	for (
		provider = pkcs11h_data->providers;
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
			
					_pkcs11h_fixupFixedString (
						(char *)info.label,
						szCurrentLabel,
						sizeof (info.label)
					);

					if (!strcmp (szCurrentLabel, szLabel)) {
						fFound = true;
						pkcs11h_session->provider = provider;
						pkcs11h_session->slot = slots[s];
					
						PKCS11LOG (
							PKCS11_LOG_DEBUG1,
							"PKCS#11: slot selected %s-%ld",
							pkcs11h_session->provider->szName,
							pkcs11h_session->slot
						);
					}
				}
			}
		}
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSlotByLabel return fFound=%d",
		fFound ? 1 : 0
	);

	return fFound ? CKR_OK : CKR_SLOT_ID_INVALID;
}

static
CK_RV
_pkcs11h_setSessionTokenInfo (
	IN const pkcs11h_session_t pkcs11h_session
) {
	CK_TOKEN_INFO info;
	CK_RV rv;

	PKCS11ASSERT (pkcs11h_session!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_setSessionTokenInfo entry pkcs11h_session=%p",
		(void *)pkcs11h_session
	);

	if (
		(rv = pkcs11h_session->provider->f->C_GetTokenInfo (
			pkcs11h_session->slot,
			&info
		)) == CKR_OK
	) {
		_pkcs11h_fixupFixedString (
			(char *)info.label,
			pkcs11h_session->szLabel,
			sizeof (info.label)
		);
		
		memmove (
			pkcs11h_session->serialNumber,
			info.serialNumber,
			sizeof (pkcs11h_session->serialNumber)
		);
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_setSessionTokenInfo return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_resetSlot (
	IN const pkcs11h_session_t pkcs11h_session
) {
	CK_SLOT_ID slots[1024];
	CK_ULONG slotnum;
	CK_RV rv;
	bool fFound = false;
	bool fCancel = false;

	PKCS11ASSERT (pkcs11h_session!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_resetSlot entry pkcs11h_session=%p",
		(void *)pkcs11h_session
	);

	do {
		slotnum = sizeof (slots) / sizeof (CK_SLOT_ID);
		if (
			(rv = pkcs11h_session->provider->f->C_GetSlotList (
				TRUE,
				slots,
				&slotnum
			)) == CKR_OK
		) {
			CK_SLOT_ID s;

			for (s=0;!fFound && s<slotnum;s++) {
				CK_TOKEN_INFO info;

				if (
					(rv = pkcs11h_session->provider->f->C_GetTokenInfo (
						slots[s],
						&info
					)) == CKR_OK
				) {
					if (
						!memcmp (
							pkcs11h_session->serialNumber,
							info.serialNumber,
							sizeof (pkcs11h_session->serialNumber)
						)
					) {
						pkcs11h_session->slot = slots[s];
						fFound = true;
					}
				}
			}
		}

		if (!fFound) {
			fCancel = !pkcs11h_data->hooks->card_prompt (
				pkcs11h_data->hooks->card_prompt_data,
				pkcs11h_session->szLabel
			);
		}
	} while (!fFound && !fCancel);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_resetSlot return fFound=%d",
		fFound ? 1 : 0
	);

	return fFound ? CKR_OK : CKR_SLOT_ID_INVALID;
}

static
CK_RV
_pkcs11h_getObjectById (
	IN const pkcs11h_session_t pkcs11h_session,
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
	
	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (id!=NULL);
	PKCS11ASSERT (handle!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getObjectById entry pkcs11h_session=%p, class=%ld, id=%p, id_size=%u, handle=%p",
		(void *)pkcs11h_session,
		class,
		id,
		id_size,
		(void *)handle
	);

	if (rv == CKR_OK) {
		rv = pkcs11h_session->provider->f->C_FindObjectsInit (
			pkcs11h_session->session,
			filter,
			sizeof (filter) / sizeof (CK_ATTRIBUTE)
		);
	}

	if (rv == CKR_OK) {
		rv = pkcs11h_session->provider->f->C_FindObjects (
			pkcs11h_session->session,
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

	pkcs11h_session->provider->f->C_FindObjectsFinal (
		pkcs11h_session->session
	);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getObjectById return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_loadCertificate (
	IN const pkcs11h_session_t pkcs11h_session,
	IN const char * const szIdType,
	IN const char * const szId
) {
	CK_OBJECT_HANDLE objects[10];
	CK_ULONG objects_found;
	CK_RV rv = CKR_OK;

	unsigned char selected_id[PKCS11H_MAX_ATTRIBUTE_SIZE];
	int selected_id_size = 0;
	unsigned char selected_certificate[PKCS11H_MAX_ATTRIBUTE_SIZE];
	int selected_certificate_size = 0;

	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	unsigned char cert_filter_by[PKCS11H_MAX_ATTRIBUTE_SIZE];
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{0, cert_filter_by, 0}
	};

	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (szIdType!=NULL);
	PKCS11ASSERT (szId!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_loadCertificate entry pkcs11h_session=%p, szIdType=%s, szId=%s",
		(void *)pkcs11h_session,
		szIdType,
		szId
	);

	if (rv == CKR_OK) {
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
			rv = CKR_ARGUMENTS_BAD;
		}
	}
	
	if (rv == CKR_OK) {
		rv = pkcs11h_session->provider->f->C_FindObjectsInit (
			pkcs11h_session->session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE)
		);
	}

	if (rv == CKR_OK) {
		while (
			(rv = pkcs11h_session->provider->f->C_FindObjects (
				pkcs11h_session->session,
				objects,
				sizeof (objects) / sizeof (CK_OBJECT_HANDLE),
				&objects_found
			)) == CKR_OK &&
			objects_found > 0
		) { 
			CK_ULONG i;
			
			for (i=0;i<objects_found;i++) {
				unsigned char attrs_id[PKCS11H_MAX_ATTRIBUTE_SIZE];
				unsigned char attrs_value[PKCS11H_MAX_ATTRIBUTE_SIZE];
				CK_ATTRIBUTE attrs[] = {
					{CKA_ID, attrs_id, sizeof (attrs_id)},
					{CKA_VALUE, attrs_value, sizeof (attrs_value)}
				};
		
				if (
					pkcs11h_session->provider->f->C_GetAttributeValue (
						pkcs11h_session->session,
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
	
		pkcs11h_session->provider->f->C_FindObjectsFinal (
			pkcs11h_session->session
		);
		rv = CKR_OK;
	}

	if (
		rv == CKR_OK &&
		selected_certificate_size == 0
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (
		rv == CKR_OK &&
		(pkcs11h_session->certificate = (unsigned char *)malloc (selected_certificate_size)) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}
	
	if (rv == CKR_OK) {
		pkcs11h_session->certificate_size = selected_certificate_size;
		memmove (
			pkcs11h_session->certificate,
			selected_certificate,
			selected_certificate_size
		);
	}
	
	if (
		rv == CKR_OK &&
		(pkcs11h_session->certificate_id = (unsigned char *)malloc (selected_id_size)) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}
	
	if (rv == CKR_OK) {
		pkcs11h_session->certificate_id_size = selected_id_size;
		memmove (
			pkcs11h_session->certificate_id,
			selected_id,
			selected_id_size
		);
	}
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_loadCertificate return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_loadKeyProperties (
	IN const pkcs11h_session_t pkcs11h_session
) {
	CK_OBJECT_HANDLE key;
	CK_RV rv = CKR_OK;

	CK_BBOOL key_attrs_sign_recover;
	CK_BBOOL key_attrs_sign;
	CK_ATTRIBUTE key_attrs[] = {
		{CKA_SIGN, &key_attrs_sign_recover, sizeof (key_attrs_sign_recover)},
		{CKA_SIGN_RECOVER, &key_attrs_sign, sizeof (key_attrs_sign)}
	};

	PKCS11ASSERT (pkcs11h_session!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_loadKeyProperties entry pkcs11h_session=%p",
		(void *)pkcs11h_session
	);

	if (!strcmp (pkcs11h_session->provider->szSignMode, "recover")) {
		pkcs11h_session->fKeySignRecover = true;
	}
	else if (!strcmp (pkcs11h_session->provider->szSignMode, "sign")) {
		pkcs11h_session->fKeySignRecover = false;
	}
	else {
		if (rv == CKR_OK) {
			rv = _pkcs11h_getObjectById (
				pkcs11h_session,
				CKO_PRIVATE_KEY,
				pkcs11h_session->certificate_id,
				pkcs11h_session->certificate_id_size,
				&key
			);
		}

		if (rv == CKR_OK) {
			rv = pkcs11h_session->provider->f->C_GetAttributeValue (
				pkcs11h_session->session,
				key,
				key_attrs,
				sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
			);
		}
		
		if (rv == CKR_OK) {
			if (key_attrs_sign_recover != CK_FALSE) {
				pkcs11h_session->fKeySignRecover = true;
			}
			else if (key_attrs_sign != CK_FALSE) {
				pkcs11h_session->fKeySignRecover = false;
			}
			else {
				rv = CKR_KEY_TYPE_INCONSISTENT;
			}
		}
	}
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_loadKeyProperties return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_validateSession (
	IN const pkcs11h_session_t pkcs11h_session
) {
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_validateSession entry pkcs11h_session=%p",
		(void *)pkcs11h_session
	);

	if (
		pkcs11h_session->timePINExpire != (time_t)0 &&
		pkcs11h_session->timePINExpire < time (NULL)
	) {
		_pkcs11h_logout (pkcs11h_session);
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_validateSession return"
	);

	return CKR_OK;
}

static
CK_RV
_pkcs11h_login (
	IN const pkcs11h_session_t pkcs11h_session
) {
	CK_RV rv = CKR_OK;


	PKCS11ASSERT (pkcs11h_session!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_login entry pkcs11h_session=%p",
		(void *)pkcs11h_session
	);

	_pkcs11h_logout (pkcs11h_session);

	if (rv == CKR_OK) {
		rv = _pkcs11h_resetSlot (pkcs11h_session);
	}

	if (rv == CKR_OK) {
		rv = pkcs11h_session->provider->f->C_OpenSession (
			pkcs11h_session->slot,
			CKF_SERIAL_SESSION,
			NULL_PTR,
			NULL_PTR,
			&pkcs11h_session->session
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
				!pkcs11h_session->fProtectedAuthentication
			) {
				if (
					!pkcs11h_data->hooks->pin_prompt (
						pkcs11h_data->hooks->pin_prompt_data,
						pkcs11h_session->szLabel,
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

			if (pkcs11h_data->nPINCachePeriod == -1) {
				pkcs11h_session->timePINExpire = 0;
			}
			else {
				pkcs11h_session->timePINExpire = (
					time (NULL) +
					(time_t)pkcs11h_data->nPINCachePeriod
				);
			}
			if (
				rv == CKR_OK &&
				(rv = pkcs11h_session->provider->f->C_Login (
					pkcs11h_session->session,
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
		pkcs11h_session->certificate_id != NULL
	) {
		rv = _pkcs11h_getObjectById (
			pkcs11h_session,
			CKO_PRIVATE_KEY,
			pkcs11h_session->certificate_id,
			pkcs11h_session->certificate_id_size,
			&pkcs11h_session->key
		);
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_login return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_logout (
	IN const pkcs11h_session_t pkcs11h_session
) {
	PKCS11ASSERT (pkcs11h_session!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_logout entry pkcs11h_session=%p",
		(void *)pkcs11h_session
	);

	if (pkcs11h_session->session != (CK_SESSION_HANDLE)-1) {
		pkcs11h_session->provider->f->C_Logout (pkcs11h_session->session);
		pkcs11h_session->provider->f->C_CloseSession (pkcs11h_session->session);
		pkcs11h_session->key = (CK_OBJECT_HANDLE)-1;
		pkcs11h_session->session = (CK_SESSION_HANDLE)-1;
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_logout return"
	);

	return CKR_OK;
}


/*=======================================
 * Simplified PKCS#11 functions
 */

static
bool
_pkcs11h_hooks_card_prompt_default (
	IN const void * pData,
	IN const char * const szLabel
) {
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_hooks_card_prompt_default pData=%p, szLabel=%s",
		pData,
		szLabel
	);

	return false;
}

static
bool
_pkcs11h_hooks_pin_prompt_default (
	IN const void * pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_hooks_pin_prompt_default pData=%p, szLabel=%s",
		pData,
		szLabel
	);
	
	return false;
}

CK_RV
pkcs11h_initialize () {

	CK_RV rv = CKR_OK;

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_initialize entry"
	);

	pkcs11h_terminate ();

	if (
		rv == CKR_OK &&
		(pkcs11h_data = (pkcs11h_data_t)malloc (sizeof (struct pkcs11h_data_s))) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}

	if (rv == CKR_OK) {
		memset (pkcs11h_data, 0, sizeof (struct pkcs11h_data_s));
	}
	
	if (
		rv == CKR_OK &&
		(pkcs11h_data->hooks = (pkcs11h_hooks_t)malloc (sizeof (struct pkcs11h_hooks_s))) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}

	if (rv == CKR_OK) {
		memset (pkcs11h_data->hooks, 0, sizeof (struct pkcs11h_hooks_s));
	
		pkcs11h_data->fInitialized = true;
		pkcs11h_data->nPINCachePeriod = -1;
	
		pkcs11h_setCardPromptHook (_pkcs11h_hooks_card_prompt_default, NULL);
		pkcs11h_setPINPromptHook (_pkcs11h_hooks_pin_prompt_default, NULL);
	}
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_initialize return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_terminate () {

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_terminate entry"
	);

	if (pkcs11h_data != NULL) {
		pkcs11h_provider_t last = NULL;

		for (
			;
			pkcs11h_data->providers != NULL;
			pkcs11h_data->providers = pkcs11h_data->providers->next
		) {
			if (last != NULL) {
				free (last);
			}
			last = pkcs11h_data->providers;
		
			if (pkcs11h_data->providers->szSignMode != NULL) {
				free (pkcs11h_data->providers->szSignMode);
				pkcs11h_data->providers->szSignMode = NULL;
			}
	
			if (pkcs11h_data->providers->fShouldFinalize) {
				pkcs11h_data->providers->f->C_Finalize (NULL);
				pkcs11h_data->providers->fShouldFinalize = false;
			}

			if (pkcs11h_data->providers->f != NULL) {
				pkcs11h_data->providers->f = NULL;
			}
	
			if (pkcs11h_data->providers->hLibrary != NULL) {
#if defined(WIN32)
				FreeLibrary (pkcs11h_data->providers->hLibrary);
#else
				dlclose (pkcs11h_data->providers->hLibrary);
#endif
				pkcs11h_data->providers->hLibrary = NULL;
			}
		}

		if (last != NULL) {
			free (last);
		}

		if (pkcs11h_data->hooks != NULL) {
			free (pkcs11h_data->hooks);
			pkcs11h_data->hooks = NULL;
		}

		free (pkcs11h_data);
		pkcs11h_data = NULL;
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_terminate return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_setPINPromptHook (
	IN const pkcs11h_hook_pin_prompt_t hook,
	IN void * const pData
) {
	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);

	pkcs11h_data->hooks->pin_prompt = hook;
	pkcs11h_data->hooks->pin_prompt_data = pData;

	return CKR_OK;
}

CK_RV
pkcs11h_setCardPromptHook (
	IN const pkcs11h_hook_card_prompt_t hook,
	IN void * const pData
) {
	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);

	pkcs11h_data->hooks->card_prompt = hook;
	pkcs11h_data->hooks->card_prompt_data = pData;

	return CKR_OK;
}

CK_RV
pkcs11h_setPINCachePeriod (
	IN const int nPINCachePeriod
) {
	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);

	pkcs11h_data->nPINCachePeriod = nPINCachePeriod;

	return CKR_OK;
}

CK_RV
pkcs11h_addProvider (
	IN const char * const szProvider,
	IN const char * const szSignMode
) {
	pkcs11h_provider_t provider = NULL;
	CK_C_GetFunctionList gfl = NULL;
	CK_RV rv = CKR_OK;

	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);
	PKCS11ASSERT (szProvider!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_addProvider entry pid=%d, szProvider=%s, szSignMode=%s",
#if defined(WIN32)
		0,
#else
		getpid (),
#endif		
		szProvider,
		szSignMode
	);

	if (
		rv == CKR_OK &&
		(provider = (pkcs11h_provider_t)malloc (sizeof (struct pkcs11h_provider_s))) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}

	if (rv == CKR_OK) {
		memset (provider, 0, sizeof (struct pkcs11h_provider_s));
		provider->szName = strdup (szProvider);
		
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
		if (pkcs11h_data->providers == NULL) {
			pkcs11h_data->providers = provider;
		}
		else {
			pkcs11h_provider_t last = NULL;
	
			for (
				last = pkcs11h_data->providers;
				last->next != NULL;
				last = last->next
			);
			last->next = provider;
		}
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_addProvider return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_forkFixup () {

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup entry pid=%d",
#if defined(WIN32)
		0
#else
		getpid ()
#endif		
	);

	if (pkcs11h_data != NULL && pkcs11h_data->fInitialized) {

		pkcs11h_provider_t current;

		for (
			current = pkcs11h_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->fEnabled) {
				current->f->C_Initialize (NULL);
			}
		}
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup return"
	);

	return CKR_OK;
}
	
CK_RV
pkcs11h_createSession (
	IN const char * const szSlotType,
	IN const char * const szSlot,
	IN const char * const szIdType,
	IN const char * const szId,
	IN const bool fProtectedAuthentication,
	OUT pkcs11h_session_t * const p_pkcs11h_session
) {
	pkcs11h_session_t pkcs11h_session;
	CK_RV rv = CKR_OK;

	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);
	PKCS11ASSERT (szSlotType!=NULL);
	PKCS11ASSERT (szSlot!=NULL);
	PKCS11ASSERT (szIdType!=NULL);
	PKCS11ASSERT (szId!=NULL);
	PKCS11ASSERT (p_pkcs11h_session!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_createSession entry szSlotType=%s, szSlot=%s, szIdType=%s, szId=%s, fProtectedAuthentication=%d, p_pkcs11h_session=%p",
		szSlotType,
		szSlot,
		szIdType,
		szId,
		fProtectedAuthentication ? 1 : 0,
		(void *)p_pkcs11h_session
	);

	if (
		rv == CKR_OK &&
		(pkcs11h_session = (pkcs11h_session_t)malloc (sizeof (struct pkcs11h_session_s))) == NULL
	) {
		rv = CKR_HOST_MEMORY;
	}

	if (rv == CKR_OK) {
		*p_pkcs11h_session = pkcs11h_session;
		memset (pkcs11h_session, 0, sizeof (struct pkcs11h_session_s));
	}
	
	if (rv == CKR_OK) {
		pkcs11h_session->key = (CK_OBJECT_HANDLE)-1;
		pkcs11h_session->session = (CK_SESSION_HANDLE)-1;
		pkcs11h_session->fProtectedAuthentication = fProtectedAuthentication;
	}

	if (rv == CKR_OK) {
		bool fCancel = false;

		do {
			if (!strcmp (szSlotType, "id")) {
				rv = _pkcs11h_getSlotById (pkcs11h_session, szSlot);
			}
			else if (!strcmp (szSlotType, "name")) {
				rv = _pkcs11h_getSlotByName (pkcs11h_session, szSlot);
			}
			else if (!strcmp (szSlotType, "label")) {
				rv = _pkcs11h_getSlotByLabel (pkcs11h_session, szSlot);
			}
			else {
				rv = CKR_ARGUMENTS_BAD;
			}

			if (rv == CKR_SLOT_ID_INVALID) {
				char szLabel[1024];
				strcpy (szLabel, "SLOT(");
				strncat (szLabel, szSlotType, sizeof (szLabel)-1);
				strncat (szLabel, "=", sizeof (szLabel)-1);
				strncat (szLabel, szSlot, sizeof (szLabel)-1);
				strncat (szLabel, ")", sizeof (szLabel)-1);
				szLabel[sizeof (szLabel)-1] = 0;
				fCancel = !pkcs11h_data->hooks->card_prompt (
					pkcs11h_data->hooks->card_prompt_data,
					szLabel
				);
			}
		} while (rv == CKR_SLOT_ID_INVALID && !fCancel);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_setSessionTokenInfo (pkcs11h_session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_login (
			pkcs11h_session
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_loadCertificate (
			pkcs11h_session,
			szIdType,
			szId
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_loadKeyProperties (
			pkcs11h_session
		);
	}
	
	/*
	 * Complete missing login process
	 */
	if (rv == CKR_OK) {
		rv = _pkcs11h_getObjectById (
			pkcs11h_session,
			CKO_PRIVATE_KEY,
			pkcs11h_session->certificate_id,
			pkcs11h_session->certificate_id_size,
			&pkcs11h_session->key
		);
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_createSession return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_freeSession (
	IN const pkcs11h_session_t pkcs11h_session
) {
	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeSession entry pkcs11h_session=%p",
		(void *)pkcs11h_session
	);

	if (pkcs11h_session != NULL) {
		_pkcs11h_logout (pkcs11h_session);

		if (pkcs11h_session->certificate != NULL) {
			free (pkcs11h_session->certificate);
		}
		if (pkcs11h_session->certificate_id != NULL) {
			free (pkcs11h_session->certificate_id);
		}

		free (pkcs11h_session);
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeSession return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_sign (
	IN const pkcs11h_session_t pkcs11h_session,
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

	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);
	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (source!=NULL);
	PKCS11ASSERT (target_size!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_sign entry pkcs11h_session=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, target_size=%p",
		(void *)pkcs11h_session,
		mech_type,
		source,
		source_size,
		target,
		(void *)target_size
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (pkcs11h_session);
	}

	while (rv == CKR_OK && !fOpSuccess) {
		rv = pkcs11h_session->provider->f->C_SignInit (
			pkcs11h_session->session,
			&mech,
			pkcs11h_session->key
		);

		if (rv == CKR_OK) {
			fOpSuccess = true;
		}
		else {
			if (!fLogonRetry) {
				fLogonRetry = true;
				rv = _pkcs11h_login (pkcs11h_session);
			}
		}
	}

	if (rv == CKR_OK) {
		CK_ULONG size = *target_size;
		rv = pkcs11h_session->provider->f->C_Sign (
			pkcs11h_session->session,
			(CK_BYTE_PTR)source,
			source_size,
			(CK_BYTE_PTR)target,
			&size
		);

		*target_size = (int)size;
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_sign return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_signRecover (
	IN const pkcs11h_session_t pkcs11h_session,
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

	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);
	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (source!=NULL);
	PKCS11ASSERT (target_size!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_signRecover entry pkcs11h_session=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, target_size=%p",
		(void *)pkcs11h_session,
		mech_type,
		source,
		source_size,
		target,
		(void *)target_size
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (pkcs11h_session);
	}

	while (rv == CKR_OK && !fOpSuccess) {
		rv = pkcs11h_session->provider->f->C_SignRecoverInit (
			pkcs11h_session->session,
			&mech,
			pkcs11h_session->key
		);

		if (rv == CKR_OK) {
			fOpSuccess = true;
		}
		else {
			if (!fLogonRetry) {
				fLogonRetry = true;
				rv = _pkcs11h_login (pkcs11h_session);
			}
		}
	}

	if (rv == CKR_OK) {
		CK_ULONG size = *target_size;
		rv = pkcs11h_session->provider->f->C_SignRecover (
			pkcs11h_session->session,
			(CK_BYTE_PTR)source,
			source_size,
			(CK_BYTE_PTR)target,
			&size
		);

		*target_size = (int)size;
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_signRecover return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_decrypt (
	IN const pkcs11h_session_t pkcs11h_session,
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

	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);
	PKCS11ASSERT (pkcs11h_session!=NULL);
	PKCS11ASSERT (source!=NULL);
	PKCS11ASSERT (target_size!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt entry pkcs11h_session=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, target_size=%p",
		(void *)pkcs11h_session,
		mech_type,
		source,
		source_size,
		target,
		(void *)target_size
	);

	if (rv != CKR_OK) {
		rv = _pkcs11h_validateSession (pkcs11h_session);
	}

	while (rv == CKR_OK && !fOpSuccess) {
		rv = pkcs11h_session->provider->f->C_DecryptInit (
			pkcs11h_session->session,
			&mech,
			pkcs11h_session->key
		);

		if (rv == CKR_OK) {
			fOpSuccess = true;
		}
		else {
			if (!fLogonRetry) {
				fLogonRetry = true;
				rv = _pkcs11h_login (pkcs11h_session);
			}
		}
	}

	if (rv == CKR_OK) {
		size = *target_size;
		rv = pkcs11h_session->provider->f->C_Decrypt (
			pkcs11h_session->session,
			(CK_BYTE_PTR)source,
			source_size,
			(CK_BYTE_PTR)target,
			&size
		);

		*target_size = (int)size;
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_getCertificate (
	IN const pkcs11h_session_t pkcs11h_session,
	OUT unsigned char * const certificate,
	IN OUT size_t * const certificate_size
) {
	CK_RV rv = CKR_OK;
	
	PKCS11ASSERT (pkcs11h_data!=NULL);
	PKCS11ASSERT (pkcs11h_data->fInitialized);
	PKCS11ASSERT (certificate_size!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_getCertificate entry pkcs11h_session=%p, certificate=%p, certificate_size=%p",
		(void *)pkcs11h_session,
		certificate,
		(void *)certificate_size
	);

	*certificate_size = pkcs11h_session->certificate_size;

	if (certificate != NULL) {
		if (
			rv == CKR_OK &&
			*certificate_size > pkcs11h_session->certificate_size
		) {
			rv = CKR_BUFFER_TOO_SMALL;
		}
	
		if (rv == CKR_OK) {
			memmove (certificate, pkcs11h_session->certificate, *certificate_size);	
		}
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_getCertificate return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return CKR_OK;
}

char *
pkcs11h_getMessage (
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

static
pkcs11h_openssl_session_t
_pkcs11h_openssl_get_pkcs11h_openssl_session (
	IN OUT const RSA *rsa
) {
	pkcs11h_openssl_session_t session;
		
	PKCS11ASSERT (rsa!=NULL);
	session = (pkcs11h_openssl_session_t)RSA_get_app_data (rsa);
	PKCS11ASSERT (session!=NULL);

	return session;
}

static
pkcs11h_session_t
_pkcs11h_openssl_get_pkcs11h_session (
	IN OUT const RSA *rsa
) {
	pkcs11h_openssl_session_t session;
	
	PKCS11ASSERT (rsa!=NULL);
	session = (pkcs11h_openssl_session_t)RSA_get_app_data (rsa);
	PKCS11ASSERT (session!=NULL);
	PKCS11ASSERT (session->pkcs11h_session!=NULL);

	return session->pkcs11h_session;
}

static
int
_pkcs11h_openssl_priv_enc (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
	PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Private key encryption not supported");
	return -1;
}

static
int
_pkcs11h_openssl_priv_dec (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
	pkcs11h_session_t pkcs11h_session = _pkcs11h_openssl_get_pkcs11h_session (rsa);
	CK_RV rv = CKR_OK;

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_priv_dec entered - flen=%d, from=%p, to=%p, rsa=%p, padding=%d",
		flen,
		from,
		to,
		(void *)rsa,
		padding
	);

	PKCS11ASSERT (from!=NULL);
	PKCS11ASSERT (to!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG1,	
		"PKCS#11: Performing decryption using private key"
	);

	if (padding != RSA_PKCS1_PADDING) {
		rv = CKR_ARGUMENTS_BAD;
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_decrypt (
			pkcs11h_session,
			CKM_RSA_PKCS,
			from,
			flen,
			to,
			(size_t *)&flen
		)) != CKR_OK
	) {
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot decrypt using private key %ld:'%s'", rv, pkcs11h_getMessage (rv));
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_priv_dec - return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv == CKR_OK ? 1 : -1; 
}

static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN const unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT const RSA *rsa
) {
	pkcs11h_openssl_session_t pkcs11h_openssl_session = _pkcs11h_openssl_get_pkcs11h_openssl_session (rsa);
	pkcs11h_session_t pkcs11h_session = _pkcs11h_openssl_get_pkcs11h_session (rsa);
	CK_RV rv = CKR_OK;

	int myrsa_size = 0;
	
	unsigned char *enc_alloc = NULL;
	unsigned char *enc;
	int enc_len = 0;
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_sign entered - type=%d, m=%p, m_len=%u, signret=%p, signlen=%p, rsa=%p",
		type,
		m,
		m_len,
		sigret,
		(void *)siglen,
		(void *)rsa
	);

	PKCS11ASSERT (m!=NULL);
	PKCS11ASSERT (sigret!=NULL);
	PKCS11ASSERT (siglen!=NULL);

	if (rv == CKR_OK) {
		myrsa_size=RSA_size(rsa);
	}

	if (pkcs11h_openssl_session->fShouldPadSign) {
		X509_SIG sig;
		ASN1_TYPE parameter;
		X509_ALGOR algor;
		ASN1_OCTET_STRING digest;

		if (
			rv == CKR_OK &&
			(enc=enc_alloc=(unsigned char *)malloc ((unsigned int)myrsa_size+1)) == NULL
		) {
			rv = CKR_HOST_MEMORY;
		}
		
		if (rv == CKR_OK) {
			sig.algor= &algor;
		}

		if (
			rv == CKR_OK &&
			(sig.algor->algorithm=OBJ_nid2obj(type)) == NULL
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	
		if (
			rv == CKR_OK &&
			sig.algor->algorithm->length == 0
		) {
			rv = CKR_KEY_SIZE_RANGE;
		}
	
		if (rv == CKR_OK) {
			parameter.type=V_ASN1_NULL;
			parameter.value.ptr=NULL;
	
			sig.algor->parameter= &parameter;

			sig.digest=&digest;
			sig.digest->data=(unsigned char *)m;
			sig.digest->length=m_len;
		}
	
		if (
			rv == CKR_OK &&
			(enc_len=i2d_X509_SIG(&sig,NULL)) < 0
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	
		if (
			rv == CKR_OK &&
			enc_len > (myrsa_size-RSA_PKCS1_PADDING_SIZE)
		) {
			rv = CKR_KEY_SIZE_RANGE;
		}
	
		if (rv == CKR_OK) {
			unsigned char *p=enc;
			i2d_X509_SIG(&sig,&p);
		}
	}
	else {
		if (rv == CKR_OK) {
			enc = (unsigned char *)m;
			enc_len = m_len;
		}
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG1,
		"PKCS#11: Performing signature"
	);

	*siglen = myrsa_size;

	if (pkcs11h_session->fKeySignRecover) {
		if (
			(rv = pkcs11h_signRecover (
				pkcs11h_session,
				CKM_RSA_PKCS,
				enc,
				enc_len,
				sigret,
				siglen
			)) != CKR_OK
		) {
			PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot perform signature-recover %ld:'%s'", rv, pkcs11h_getMessage (rv));
		}
	}
	else {
		if (
			(rv = pkcs11h_sign (
				pkcs11h_session,
				CKM_RSA_PKCS,
				enc,
				enc_len,
				sigret,
				siglen
			)) != CKR_OK
		) {
			PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		}
	}
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_sign - return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	if (enc_alloc != NULL) {
		free (enc_alloc);
	}
	
	return rv == CKR_OK ? 1 : -1; 
}

static
int
_pkcs11h_openssl_finish (
	IN OUT RSA *rsa
) {
	pkcs11h_openssl_session_t pkcs11h_openssl_session = _pkcs11h_openssl_get_pkcs11h_openssl_session (rsa);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_finish - entered rsa=%p",
		(void *)rsa
	);

	RSA_set_app_data (rsa, NULL);
	
	if (pkcs11h_openssl_session->orig_finish != NULL) {
		pkcs11h_openssl_session->orig_finish (rsa);

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

	pkcs11h_openssl_freeSession (pkcs11h_openssl_session);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_finish - return"
	);
	
	return 1;
}

pkcs11h_openssl_session_t
pkcs11h_openssl_createSession (
	IN const bool fShouldPadSign
) {
	pkcs11h_openssl_session_t pkcs11h_openssl_session = NULL;
	bool fOK = true;

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - entry fShouldPadSign=%d",
		fShouldPadSign ? 1 : 0
	);

	if (
		fOK &&
		(pkcs11h_openssl_session = (pkcs11h_openssl_session_t)malloc (sizeof (struct pkcs11h_openssl_session_s))) == NULL
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot allocate memory");
	}

	if (fOK) {
		memset (pkcs11h_openssl_session, 0, sizeof (struct pkcs11h_openssl_session_s));
	}

	if (fOK) {
		pkcs11h_openssl_session->fShouldPadSign = fShouldPadSign;
		pkcs11h_openssl_session->nReferenceCount = 1;
	}

	if (!fOK) {
		free (pkcs11h_openssl_session);
		pkcs11h_openssl_session = NULL;
	}
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - return pkcs11h_openssl_session=%p",
		(void *)pkcs11h_openssl_session
	);

	return pkcs11h_openssl_session;
}

void
pkcs11h_openssl_freeSession (
	IN const pkcs11h_openssl_session_t pkcs11h_openssl_session
) {
	PKCS11ASSERT (pkcs11h_openssl_session!=NULL);
	PKCS11ASSERT (pkcs11h_openssl_session->nReferenceCount>0);
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - entry pkcs11h_openssl_session=%p, count=%d",
		(void *)pkcs11h_openssl_session,
		pkcs11h_openssl_session->nReferenceCount
	);

	pkcs11h_openssl_session->nReferenceCount--;
	
	if (pkcs11h_openssl_session->nReferenceCount == 0) {
		if (pkcs11h_openssl_session->x509) {
			X509_free (pkcs11h_openssl_session->x509);
			pkcs11h_openssl_session->x509 = NULL;
		}
		if (pkcs11h_openssl_session->pkcs11h_session != NULL) {
			pkcs11h_freeSession (pkcs11h_openssl_session->pkcs11h_session);
			pkcs11h_openssl_session->pkcs11h_session = NULL;
		}
		
		free (pkcs11h_openssl_session);
	}

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - return"
	);
}

RSA *
pkcs11h_openssl_getRSA (
	IN const pkcs11h_openssl_session_t pkcs11h_openssl_session
) {
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pubkey = NULL;
	CK_RV rv = CKR_OK;

	unsigned char certificate[10*1024];
	size_t certificate_size;
	unsigned char *p;
	bool fOK = true;

	PKCS11ASSERT (pkcs11h_openssl_session!=NULL);
	PKCS11ASSERT (!pkcs11h_openssl_session->fInitialized);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getRSA - entry pkcs11h_openssl_session=%p",
		(void *)pkcs11h_openssl_session
	);

	if (
		fOK &&
		(x509 = X509_new ()) == NULL
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Unable to allocate certificate object");
	}

	certificate_size = sizeof (certificate);
	if (
		fOK &&
		(rv = pkcs11h_getCertificate (
			pkcs11h_openssl_session->pkcs11h_session,
			certificate,
			&certificate_size
		)) != CKR_OK
	) { 
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot read X.509 certificate from token %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	p = certificate;
	if (
		fOK &&
		!d2i_X509 (&x509, &p, certificate_size)
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Unable to parse X.509 certificate");
	}

	if (
		fOK &&
		(pubkey = X509_get_pubkey (x509)) == NULL
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot get public key");
	}
	
	if (
		fOK &&
		pubkey->type != EVP_PKEY_RSA
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Invalid public key algorithm");
	}

	if (
		fOK &&
		(rsa = EVP_PKEY_get1_RSA (pubkey)) == NULL
	) {
		fOK = false;
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: Cannot get RSA key");
	}

 	if (fOK) {
		const RSA_METHOD *def = RSA_get_default_method();

		memmove (&pkcs11h_openssl_session->smart_rsa, def, sizeof(RSA_METHOD));

		pkcs11h_openssl_session->orig_finish = def->finish;

		pkcs11h_openssl_session->smart_rsa.name = "pkcs11";
		pkcs11h_openssl_session->smart_rsa.rsa_priv_enc = _pkcs11h_openssl_priv_enc;
		pkcs11h_openssl_session->smart_rsa.rsa_priv_dec = _pkcs11h_openssl_priv_dec;
		pkcs11h_openssl_session->smart_rsa.rsa_sign = _pkcs11h_openssl_sign;
		pkcs11h_openssl_session->smart_rsa.finish = _pkcs11h_openssl_finish;
		pkcs11h_openssl_session->smart_rsa.flags  = RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY;

		RSA_set_method (rsa, &pkcs11h_openssl_session->smart_rsa);
		RSA_set_app_data (rsa, pkcs11h_openssl_session);
		pkcs11h_openssl_session->nReferenceCount++;
	}
	
#ifdef BROKEN_OPENSSL_ENGINE
	if (fOK) {
		if (!rsa->engine)
			rsa->engine = ENGINE_get_default_RSA();

		ENGINE_set_RSA(ENGINE_get_default_RSA(), &pkcs11h_openssl_session->smart_rsa);
		PKCS11LOG (PKCS11_LOG_WARN, "PKCS#11: OpenSSL engine support is broken! Workaround enabled");
	}
#endif
		
	if (fOK) {
		/*
			So that it won't hold RSA
		*/
		pkcs11h_openssl_session->x509 = X509_dup (x509);
		rsa->flags |= RSA_FLAG_SIGN_VER;
		pkcs11h_openssl_session->fInitialized = true;
	}
	else {
		if (rsa != NULL) {
			RSA_free (rsa);
			rsa = NULL;
		}
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
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getRSA - return rsa=%p",
		(void *)rsa
	);

	return rsa;
}

X509 *
pkcs11h_openssl_getX509 (
	IN const pkcs11h_openssl_session_t pkcs11h_openssl_session
) {
	X509 *x509 = NULL;
	
	PKCS11ASSERT (pkcs11h_openssl_session!=NULL);

	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - entry pkcs11h_openssl_session=%p",
		(void *)pkcs11h_openssl_session
	);

	if (pkcs11h_openssl_session->x509 != NULL) {
		x509 = X509_dup (pkcs11h_openssl_session->x509);
	}
	
	PKCS11LOG (
		PKCS11_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - return x509=%p",
		(void *)x509
	);

	return x509;
}


void
pkcs11h_standalone_dump_slots (
	IN const pkcs11h_output_print_t my_output,
	IN const void *pData,
	IN const char * const provider
) {
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t pkcs11h_provider;

	PKCS11ASSERT (provider!=NULL);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot initialize interface %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (provider, NULL)) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = pkcs11h_data->providers;
		if (pkcs11h_provider == NULL || !pkcs11h_provider->fEnabled) {
			my_output (pData, "PKCS#11: Cannot get provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		CK_INFO info;
		
		if ((rv = pkcs11h_provider->f->C_GetInfo (&info)) != CKR_OK) {
			my_output (pData, "PKCS#11: Cannot get PKCS#11 provider information %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_OK;
		}
		else {
			char szManufacturerID[sizeof (info.manufacturerID)+1];
	
			_pkcs11h_fixupFixedString (
				(char *)info.manufacturerID,
				szManufacturerID,
				sizeof (info.manufacturerID)
			);
	
			my_output (
				pData,
				(
					"Provider Information:\n"
					"\tcryptokiVersion:\t%u.%u\n"
					"\tmanufacturerID:\t\t%s\n"
					"\tflags:\t\t\t%d\n"
					"\n"
				),
				info.cryptokiVersion.major,
				info.cryptokiVersion.minor,
				szManufacturerID,
				(unsigned)info.flags
			);
		}
	}
	
	if (rv == CKR_OK) {
		CK_SLOT_ID slots[1024];
		CK_ULONG slotnum;
		CK_SLOT_ID s;
		
		slotnum = sizeof (slots) / sizeof (CK_SLOT_ID);
		if (
			(rv = pkcs11h_provider->f->C_GetSlotList (
				FALSE,
				slots,
				&slotnum
			)) != CKR_OK
		) {
			my_output (pData, "PKCS#11: Cannot get slot list %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
		}
		else {
			my_output (
				pData,
				(
					"The following slots are available for use with this provider.\n"
					"Each slot shown below may be used as a parameter to a\n"
					"%s and %s options.\n"
					"\n"
					"Slots: (id - name)\n"
				),
				PKCS11_PRM_SLOT_TYPE,
				PKCS11_PRM_SLOT_ID
			);
			for (s=0;s<slotnum;s++) {
				CK_SLOT_INFO info;
	
				if (
					(rv = pkcs11h_provider->f->C_GetSlotInfo (
						slots[s],
						&info
					)) == CKR_OK
				) {
					char szCurrentName[sizeof (info.slotDescription)+1];
				
					_pkcs11h_fixupFixedString (
						(char *)info.slotDescription,
						szCurrentName,
						sizeof (info.slotDescription)
					);
	
					my_output (pData, "\t%lu - %s\n", slots[s], szCurrentName);
				}
			}
		}
	}
	
	pkcs11h_terminate ();
}

static
bool
_pkcs11h_standalone_dump_objects_pin_prompt (
	IN const void *pData,
	IN const char * const szLabel,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	strncpy (szPIN, (char *)pData, nMaxPIN);
	return true;
}

void
pkcs11h_standalone_dump_objects (
	IN const pkcs11h_output_print_t my_output,
	IN const void *pData,
	IN const char * const provider,
	IN const char * const slot,
	IN const char * const pin
) {
	CK_SLOT_ID s;
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t pkcs11h_provider;

	PKCS11ASSERT (provider!=NULL);
	PKCS11ASSERT (slot!=NULL);
	PKCS11ASSERT (pin!=NULL);

	s = atoi (slot);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot initialize interface %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setPINPromptHook (_pkcs11h_standalone_dump_objects_pin_prompt, (void *)pin)) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot set hooks %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (provider, NULL)) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

  	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = pkcs11h_data->providers;
		if (pkcs11h_provider == NULL || !pkcs11h_provider->fEnabled) {
			my_output (pData, "PKCS#11: Cannot get provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		CK_TOKEN_INFO info;
		
		if (
			(rv = pkcs11h_provider->f->C_GetTokenInfo (
				s,
				&info
			)) != CKR_OK
		) {
			my_output (pData, "PKCS#11: Cannot get token information for slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));
			rv = CKR_OK;
		}
		else {
			char szLabel[sizeof (info.label)+1];
			char szManufacturerID[sizeof (info.manufacturerID)+1];
			char szModel[sizeof (info.model)+1];
			char szSerialNumber[sizeof (info.serialNumber)+1];
			
			_pkcs11h_fixupFixedString (
				(char *)info.label,
				szLabel,
				sizeof (info.label)
			);
			_pkcs11h_fixupFixedString (
				(char *)info.manufacturerID,
				szManufacturerID,
				sizeof (info.manufacturerID)
			);
			_pkcs11h_fixupFixedString (
				(char *)info.model,
				szModel,
				sizeof (info.model)
			);
			_pkcs11h_fixupFixedString (
				(char *)info.serialNumber,
				szSerialNumber,
				sizeof (info.serialNumber)
			);
	
			my_output (
				pData,
				(
					"Token Information:\n"
					"\tlabel:\t\t%s\n"
					"\tmanufacturerID:\t%s\n"
					"\tmodel:\t\t%s\n"
					"\tserialNumber:\t%s\n"
					"\tflags:\t\t%08x\n"
					"\n"
					"You can access this token using\n"
					"%s \"label\" %s \"%s\" options.\n"
					"\n"
				),
				szLabel,
				szManufacturerID,
				szModel,
				szSerialNumber,
				(unsigned)info.flags,
				PKCS11_PRM_SLOT_TYPE,
				PKCS11_PRM_SLOT_ID,
				szLabel
			);
		}
	}

	if (rv == CKR_OK) {
		CK_SESSION_HANDLE session;
		
		if (
			(rv = pkcs11h_provider->f->C_OpenSession (
				s,
				CKF_SERIAL_SESSION,
				NULL_PTR,
				NULL_PTR,
				&session
			)) != CKR_OK
		) {
			my_output (pData, "PKCS#11: Cannot open session to slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));
			rv = CKR_OK;
		}
		else {
			CK_OBJECT_HANDLE objects[10];
			CK_ULONG objects_found;
	
			if (
				(rv = pkcs11h_provider->f->C_Login (
					session,
					CKU_USER,
					(CK_CHAR_PTR)pin,
					(CK_ULONG)strlen (pin)
				)) != CKR_OK &&
				rv != CKR_USER_ALREADY_LOGGED_IN
			) {
				my_output (pData, "PKCS#11: Cannot login to token on slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));
			}
		
			if (
				(rv = pkcs11h_provider->f->C_FindObjectsInit (
					session,
					NULL,
					0
				)) != CKR_OK
			) {
				my_output (pData, "PKCS#11: Cannot query objects for token on slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));
			}
		
			my_output (
				pData,
				(
					"The following objects are available for use with this token.\n"
					"Each object shown below may be used as a parameter to\n"
					"%s and %s options.\n"
					"\n"
				),
				PKCS11_PRM_OBJ_TYPE,
				PKCS11_PRM_OBJ_ID
			);
		
			while (
				(rv = pkcs11h_provider->f->C_FindObjects (
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
					unsigned char attrs_id[PKCS11H_MAX_ATTRIBUTE_SIZE];
					unsigned char attrs_label[PKCS11H_MAX_ATTRIBUTE_SIZE];
					CK_ATTRIBUTE attrs[] = {
						{CKA_CLASS, &attrs_class, sizeof (attrs_class)},
						{CKA_ID, attrs_id, sizeof (attrs_id)},
						{CKA_LABEL, attrs_label, sizeof (attrs_label)-1}
					};
			
					if (
						pkcs11h_provider->f->C_GetAttributeValue (
							session,
							objects[i],
							attrs,
							sizeof (attrs) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK
					) {
						int id_len = attrs[1].ulValueLen;
						int j;
							
						attrs_label[attrs[2].ulValueLen] = 0;
		
						my_output (
							pData,
							(
								"Object\n"
								"\tLabel:\t\t%s\n"
								"\tId:\n"
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
		
							my_output (pData, "\t\t%s\n", szLine);
						}
		
						if (attrs_class == CKO_CERTIFICATE) {
							unsigned char certificate[PKCS11H_MAX_ATTRIBUTE_SIZE];
							CK_ATTRIBUTE attrs_cert[] = {
								{CKA_VALUE, certificate, sizeof (certificate)}
							};
		
							my_output (pData, "\tType:\t\tCertificate\n");
		
							if (
								pkcs11h_provider->f->C_GetAttributeValue (
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
									my_output (pData, "Cannot create x509 context\n");
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
									my_output (pData, "Cannot create BIO context\n");
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
		
								my_output (
									pData,
									(
										"\tsubject:\t%s\n"
										"\tserialNumber:\t%s\n"
										"\tnotBefore:\t%s\n"
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
		
							my_output (pData, "\tType:\t\tPrivate Key\n");
		
							if (
								pkcs11h_provider->f->C_GetAttributeValue (
									session,
									objects[i],
									attrs_key,
									sizeof (attrs_key) / sizeof (CK_ATTRIBUTE)
								) == CKR_OK
							) {
								my_output (
									pData,
									(
										"\tSign:\t\t%s\n"
										"\tSign Recover:\t%s\n"
									),
									sign ? "TRUE" : "FALSE",
									sign_recover ? "TRUE" : "FALSE"
								);
							}
						}
						else {
							my_output (pData, "\tType:\t\tUnsupported\n");
						}
					}
				}
			
				pkcs11h_provider->f->C_FindObjectsFinal (session);
				pkcs11h_provider->f->C_Logout (session);
				pkcs11h_provider->f->C_CloseSession (session);
			}
		}
	}
	
	pkcs11h_terminate ();
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

#else
static void dummy (void) {}
#endif /* PKCS11_HELPER_ENABLE */
