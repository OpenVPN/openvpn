/*
 * Copyright (c) 2005-2006 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the OpenIB.org BSD license.
 *
 * GNU General Public License (GPL) Version 2
 * ===========================================
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
 *  along with this program (see the file COPYING[.GPL2] included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * OpenIB.org BSD license
 * =======================
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

/*
 * Changelog
 *
 * 2006.06.26
 * 	- (alonbl) Fix handling mutiple providers.
 * 	- (alonbl) Release 01.01.
 *
 * 2006.05.14
 * 	- (alonbl) First stable release.
 * 	- (alonbl) Release 01.00.
 *
 */

#include "pkcs11-helper-config.h"

#if defined(ENABLE_PKCS11H_HELPER)

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

#if OPENSSL_VERSION_NUMBER < 0x00907000L
#if !defined(RSA_PKCS1_PADDING_SIZE)
#define RSA_PKCS1_PADDING_SIZE 11
#endif
#endif

#define PKCS11H_INVALID_SLOT_ID		((CK_SLOT_ID)-1)
#define PKCS11H_INVALID_SESSION_HANDLE	((CK_SESSION_HANDLE)-1)
#define PKCS11H_INVALID_OBJECT_HANDLE	((CK_OBJECT_HANDLE)-1)

#define PKCS11H_DEFAULT_SLOTEVENT_POLL		5000
#define PKCS11H_DEFAULT_MAX_LOGIN_RETRY		3
#define PKCS11H_DEFAULT_PIN_CACHE_PERIOD	PKCS11H_PIN_CACHE_INFINITE

enum _pkcs11h_private_op_e {
	_pkcs11h_private_op_sign=0,
	_pkcs11h_private_op_sign_recover,
	_pkcs11h_private_op_decrypt
};

/*===========================================
 * Macros
 */

#define PKCS11H_MSG_LEVEL_TEST(flags) (((unsigned int)flags) <= s_pkcs11h_loglevel)

#if defined(HAVE_CPP_VARARG_MACRO_ISO) && !defined(__LCLINT__)
# define PKCS11H_LOG(flags, ...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), __VA_ARGS__); } while (FALSE)
# ifdef ENABLE_PKCS11H_DEBUG
#  define PKCS11H_DEBUG(flags, ...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), __VA_ARGS__); } while (FALSE)
# else
#  define PKCS11H_DEBUG(flags, ...)
# endif
#elif defined(HAVE_CPP_VARARG_MACRO_GCC) && !defined(__LCLINT__)
# define PKCS11H_LOG(flags, args...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), args); } while (FALSE)
# ifdef ENABLE_PKCS11H_DEBUG
#  define PKCS11H_DEBUG(flags, args...) do { if (PKCS11H_MSG_LEVEL_TEST(flags)) _pkcs11h_log((flags), args); } while (FALSE)
# else
#  define PKCS11H_DEBUG(flags, args...)
# endif
#else
# define PKCS11H_LOG _pkcs11h_log
# define PKCS11H_DEBUG _pkcs11h_log
#endif

/*===========================================
 * Types
 */

struct pkcs11h_provider_s;
struct pkcs11h_session_s;
struct pkcs11h_data_s;
typedef struct pkcs11h_provider_s *pkcs11h_provider_t;
typedef struct pkcs11h_session_s *pkcs11h_session_t;
typedef struct pkcs11h_data_s *pkcs11h_data_t;

#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *pkcs11_openssl_d2i_t;
#else
typedef const unsigned char *pkcs11_openssl_d2i_t;
#endif

#if defined(ENABLE_PKCS11H_THREADING)

#define PKCS11H_COND_INFINITE	0xffffffff

#if defined(WIN32)
#define PKCS11H_THREAD_NULL	NULL
typedef HANDLE pkcs11h_cond_t;
typedef HANDLE pkcs11h_mutex_t;
typedef HANDLE pkcs11h_thread_t;
#else
#define PKCS11H_THREAD_NULL	0l
typedef pthread_mutex_t pkcs11h_mutex_t;
typedef pthread_t pkcs11h_thread_t;

typedef struct {
	pthread_cond_t cond;
	pthread_mutex_t mut;
} pkcs11h_cond_t;

typedef struct __pkcs11h_mutex_entry_s {
	struct __pkcs11h_mutex_entry_s *next;
	pkcs11h_mutex_t *p_mutex;
	PKCS11H_BOOL fLocked;
} *__pkcs11h_mutex_entry_t;
#endif

typedef void * (*pkcs11h_thread_start_t)(void *);

typedef struct {
	pkcs11h_thread_start_t start;
	void *data;
} __pkcs11h_thread_data_t;

#endif				/* ENABLE_PKCS11H_THREADING */

struct pkcs11h_provider_s {
	pkcs11h_provider_t next;

	PKCS11H_BOOL fEnabled;
	char szReferenceName[1024];
	char manufacturerID[sizeof (((CK_TOKEN_INFO *)NULL)->manufacturerID)+1];
	
#if defined(WIN32)
	HANDLE hLibrary;
#else
	void *hLibrary;
#endif

	CK_FUNCTION_LIST_PTR f;
	PKCS11H_BOOL fShouldFinalize;
	PKCS11H_BOOL fProtectedAuthentication;
	PKCS11H_BOOL fCertIsPrivate;
	unsigned maskSignMode;
	int nSlotEventMethod;
	int nSlotEventPollInterval;

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	pkcs11h_thread_t threadSlotEvent;
#endif
};

struct pkcs11h_session_s {
	pkcs11h_session_t next;

	int nReferenceCount;
	PKCS11H_BOOL fValid;

	pkcs11h_provider_t provider;

	pkcs11h_token_id_t token_id;

	CK_SESSION_HANDLE hSession;

	PKCS11H_BOOL fProtectedAuthenticationSupported;
	int nPINCachePeriod;
	time_t timePINExpire;

#if defined(ENABLE_PKCS11H_ENUM)
#if defined(ENABLE_PKCS11H_CERTIFICATE)
	pkcs11h_certificate_id_list_t cached_certs;
	PKCS11H_BOOL fTouch;
#endif
#endif

#if defined(ENABLE_PKCS11H_THREADING)
	pkcs11h_mutex_t mutexSession;
#endif
};

#if defined (ENABLE_PKCS11H_CERTIFICATE)

struct pkcs11h_certificate_s {

	pkcs11h_certificate_id_t id;
	int nPINCachePeriod;

	unsigned maskSignMode;

	pkcs11h_session_t session;
	CK_OBJECT_HANDLE hKey;

	PKCS11H_BOOL fOperationActive;

#if defined(ENABLE_PKCS11H_THREADING)
	pkcs11h_mutex_t mutexCertificate;
#endif
};

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

struct pkcs11h_data_s {
	PKCS11H_BOOL fInitialized;
	int nPINCachePeriod;

	pkcs11h_provider_t providers;
	pkcs11h_session_t sessions;

	struct {
		void *log_data;
		void *slotevent_data;
		void *token_prompt_data;
		void *pin_prompt_data;
		pkcs11h_hook_log_t log;
		pkcs11h_hook_slotevent_t slotevent;
		pkcs11h_hook_token_prompt_t token_prompt;
		pkcs11h_hook_pin_prompt_t pin_prompt;
	} hooks;

	PKCS11H_BOOL fProtectedAuthentication;
	unsigned nMaxLoginRetries;

#if defined(ENABLE_PKCS11H_THREADING)
	pkcs11h_mutex_t mutexGlobal;
	pkcs11h_mutex_t mutexSession;
	pkcs11h_mutex_t mutexCache;
#endif

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	PKCS11H_BOOL fSlotEventInitialized;
	PKCS11H_BOOL fSlotEventShouldTerminate;
	PKCS11H_BOOL fSlotEventSkipEvent;
	pkcs11h_cond_t condSlotEvent;
	pkcs11h_thread_t threadSlotEvent;
#endif
};

#if defined(ENABLE_PKCS11H_OPENSSL)
struct pkcs11h_openssl_session_s {
	int nReferenceCount;
	PKCS11H_BOOL fInitialized;
	X509 *x509;
	RSA_METHOD smart_rsa;
	int (*orig_finish)(RSA *rsa);
	pkcs11h_certificate_t certificate;
};
#endif

/*======================================================================*
 * MEMORY INTERFACE
 *======================================================================*/

static
CK_RV
_pkcs11h_malloc (
	OUT const void ** const p,
	IN const size_t s
);
static
CK_RV
_pkcs11h_free (
	IN const void ** const p
);
static
CK_RV
_pkcs11h_dupmem (
	OUT const void ** const dest,
	OUT size_t * const dest_size,
	IN const void * const src,
	IN const size_t mem_size
);

#if defined(ENABLE_PKCS11H_THREADING)
/*======================================================================*
 * THREADING INTERFACE
 *======================================================================*/

static
void
_pkcs11h_sleep (
	IN const unsigned milli
);
static
CK_RV
_pkcs11h_mutexInit (
	OUT pkcs11h_mutex_t * const mutex
);
static
CK_RV
_pkcs11h_mutexLock (
	IN OUT pkcs11h_mutex_t *const mutex
);
static
CK_RV
_pkcs11h_mutexRelease (
	IN OUT pkcs11h_mutex_t *const mutex
);
static
CK_RV
_pkcs11h_mutexFree (
	IN OUT pkcs11h_mutex_t *const mutex
);
#if !defined(WIN32)
static
void
__pkcs1h_mutexLockAll ();
static
void
__pkcs1h_mutexReleaseAll ();
#endif
static
CK_RV
_pkcs11h_condSignal (
	IN OUT pkcs11h_cond_t *const cond
);
static
CK_RV
_pkcs11h_condInit (
	OUT pkcs11h_cond_t * const cond
);
static
CK_RV
_pkcs11h_condWait (
	IN OUT pkcs11h_cond_t *const cond,
	IN const unsigned milli
);
static
CK_RV
_pkcs11h_condFree (
	IN OUT pkcs11h_cond_t *const cond
);
static
CK_RV
_pkcs11h_threadStart (
	OUT pkcs11h_thread_t * const thread,
	IN pkcs11h_thread_start_t const start,
	IN void * data
);
static
CK_RV
_pkcs11h_threadJoin (
	IN pkcs11h_thread_t * const thread
);
#endif				/* ENABLE_PKCS11H_THREADING */

/*======================================================================*
 * COMMON INTERNAL INTERFACE
 *======================================================================*/

static
void
_pkcs11h_fixupFixedString (
	OUT char * const szTarget,			/* MUST BE >= nLength+1 */
	IN const char * const szSource,
	IN const size_t nLength				/* FIXED STRING LENGTH */
);
static
void
_pkcs11h_log (
	IN const unsigned flags,
	IN const char * const szFormat,
	IN ...
)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

static
CK_RV
_pkcs11h_getSlotList (
	IN const pkcs11h_provider_t provider,
	IN const CK_BBOOL tokenPresent,
	OUT CK_SLOT_ID_PTR * const pSlotList,
	OUT CK_ULONG_PTR pulCount
);
static
CK_RV
_pkcs11h_getObjectAttributes (
	IN const pkcs11h_session_t session,
	IN const CK_OBJECT_HANDLE object,
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
);
static
CK_RV
_pkcs11h_freeObjectAttributes (
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
);
static
CK_RV
_pkcs11h_findObjects (
	IN const pkcs11h_session_t session,
	IN const CK_ATTRIBUTE * const filter,
	IN const CK_ULONG filter_attrs,
	OUT CK_OBJECT_HANDLE **const p_objects,
	OUT CK_ULONG *p_objects_found
);
static
CK_RV
_pkcs11h_getTokenId (
	IN const CK_TOKEN_INFO_PTR info,
	OUT pkcs11h_token_id_t * const p_token_id
);
static
CK_RV
_pkcs11h_newTokenId (
	OUT pkcs11h_token_id_t * const token_id
);
static
CK_RV
_pkcs11h_getSessionByTokenId (
	IN const pkcs11h_token_id_t token_id,
	OUT pkcs11h_session_t * const p_session
);
static
CK_RV
_pkcs11h_releaseSession (
	IN const pkcs11h_session_t session
);
static
CK_RV
_pkcs11h_resetSession (
	IN const pkcs11h_session_t session,
	IN const unsigned maskPrompt,
	OUT CK_SLOT_ID * const p_slot
);
static
CK_RV
_pkcs11h_getObjectById (
	IN const pkcs11h_session_t certificate,
	IN const CK_OBJECT_CLASS class,
	IN const CK_BYTE_PTR id,
	IN const size_t id_size,
	OUT CK_OBJECT_HANDLE * const p_handle
);
static
CK_RV
_pkcs11h_validateSession (
	IN const pkcs11h_session_t session
);
static
CK_RV
_pkcs11h_login (
	IN const pkcs11h_session_t session,
	IN const PKCS11H_BOOL fPublicOnly,
	IN const PKCS11H_BOOL fReadOnly,
	IN const unsigned maskPrompt
);
static
CK_RV
_pkcs11h_logout (
	IN const pkcs11h_session_t session
);

static
void
_pkcs11h_hooks_default_log (
	IN const void * pData,
	IN const unsigned flags,
	IN const char * const szFormat,
	IN va_list args
);

static
PKCS11H_BOOL
_pkcs11h_hooks_default_token_prompt (
	IN const void * pData,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
);

static
PKCS11H_BOOL
_pkcs11h_hooks_default_pin_prompt (
	IN const void * pData,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
);

#if !defined(WIN32)
#if defined(ENABLE_PKCS11H_THREADING)
static
void
__pkcs11h_atfork_prepare  ();
static
void
__pkcs11h_atfork_parent ();
static
void
__pkcs11h_atfork_child ();
#endif
static
CK_RV
_pkcs11h_forkFixup ();
#endif

#if defined(ENABLE_PKCS11H_CERTIFICATE)
/*======================================================================*
 * CERTIFICATE INTERFACE
 *======================================================================*/

static
void
_pkcs11h_isBetterCertificate_getExpiration (
	IN const unsigned char * const pCertificate,
	IN const size_t nCertificateSize,
	OUT char * const szNotBefore,
	IN const int nNotBeforeSize
);
static
PKCS11H_BOOL
_pkcs11h_isBetterCertificate (
	IN const unsigned char * const pCurrent,
	IN const size_t nCurrentSize,
	IN const unsigned char * const pNew,
	IN const size_t nNewSize
);
static
CK_RV
_pkcs11h_newCertificateId (
	OUT pkcs11h_certificate_id_t * const certificate_id
);
static
CK_RV
_pkcs11h_loadCertificate (
	IN const pkcs11h_certificate_t certificate
);
static
CK_RV
_pkcs11h_updateCertificateIdDescription (
	IN OUT pkcs11h_certificate_id_t certificate_id
);
static
CK_RV
_pkcs11h_ensureCertificateBlob (
	IN const pkcs11h_certificate_t certificate
);
static
CK_RV
_pkcs11h_getCertificateKeyAttributes (
	IN const pkcs11h_certificate_t certificate
);
static
CK_RV
_pkcs11h_validateCertificateSession (
	IN const pkcs11h_certificate_t certificate
);
static
CK_RV
_pkcs11h_resetCertificateSession (
	IN const pkcs11h_certificate_t certificate,
	IN const PKCS11H_BOOL fPublicOnly,
	IN const unsigned maskPrompt
);
static
CK_RV
_pkcs11h_certificate_private_op (
	IN const pkcs11h_certificate_t certificate,
	IN const enum _pkcs11h_private_op_e op,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
);
#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_LOCATE)
/*======================================================================*
 * LOCATE INTERFACE
 *======================================================================*/

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotId (
	IN const char * const szSlot,
	OUT pkcs11h_token_id_t * const p_token_id
);
static
CK_RV
_pkcs11h_locate_getTokenIdBySlotName (
	IN const char * const szName,
	OUT pkcs11h_token_id_t * const p_token_id
);
static
CK_RV
_pkcs11h_locate_getTokenIdByLabel (
	IN const char * const szLabel,
	OUT pkcs11h_token_id_t * const p_token_id
);

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
void
_pkcs11h_locate_hexToBinary (
	OUT unsigned char * const target,
	IN const char * const szSource,
	IN OUT size_t * const p_target_size
);
static
CK_RV
_pkcs11h_locate_getCertificateIdByLabel (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const szLabel
);
static
CK_RV
_pkcs11h_locate_getCertificateIdBySubject (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const szSubject
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */
#endif				/* ENABLE_PKCS11H_LOCATE */

#if defined(ENABLE_PKCS11H_ENUM)
/*======================================================================*
 * ENUM INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_enum_getSessionCertificates (
	IN const pkcs11h_session_t session
);
static
CK_RV
_pkcs11h_enum_splitCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_all,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_ENUM */

#if defined(ENABLE_PKCS11H_SLOTEVENT)
/*======================================================================*
 * SLOTEVENT INTERFACE
 *======================================================================*/

static
unsigned long
_pkcs11h_slotevent_checksum (
	IN const unsigned char * const p,
	IN const size_t s
);
static
void *
_pkcs11h_slotevent_provider (
	IN void *p
);
static
void *
_pkcs11h_slotevent_manager (
	IN void *p
);
static
CK_RV
_pkcs11h_slotevent_init ();
static
CK_RV
_pkcs11h_slotevent_notify ();
static
CK_RV
_pkcs11h_slotevent_terminate ();

#endif				/* ENABLE_PKCS11H_SLOTEVENT */

#if defined(ENABLE_PKCS11H_OPENSSL)
/*======================================================================*
 * OPENSSL INTERFACE
 *======================================================================*/

static
int
_pkcs11h_openssl_finish (
	IN OUT RSA *rsa
);
#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
);
static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT RSA *rsa
);
#else
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
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
#endif
static
pkcs11h_openssl_session_t
_pkcs11h_openssl_get_openssl_session (
	IN OUT const RSA *rsa
);  
static
pkcs11h_certificate_t
_pkcs11h_openssl_get_pkcs11h_certificate (
	IN OUT const RSA *rsa
);  
#endif				/* ENABLE_PKCS11H_OPENSSL */

/*==========================================
 * Static data
 */

#if defined(ENABLE_PKCS11H_THREADING)
#if !defined(WIN32)
static struct {
	pkcs11h_mutex_t mutex;
	__pkcs11h_mutex_entry_t head;
} __s_pkcs11h_mutex_list = {
	PTHREAD_MUTEX_INITIALIZER,
	NULL
};
#endif
#endif

pkcs11h_data_t s_pkcs11h_data = NULL;
unsigned int s_pkcs11h_loglevel = PKCS11H_LOG_INFO;

/*======================================================================*
 * PUBLIC INTERFACE
 *======================================================================*/

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

CK_RV
pkcs11h_initialize () {

#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_initialize entry"
	);

	pkcs11h_terminate ();

	if (rv == CKR_OK) {
		rv = _pkcs11h_malloc ((void*)&s_pkcs11h_data, sizeof (struct pkcs11h_data_s));
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (rv == CKR_OK) {
		rv = _pkcs11h_mutexInit (&s_pkcs11h_data->mutexGlobal); 
	}
	if (rv == CKR_OK) {
		rv = _pkcs11h_mutexInit (&s_pkcs11h_data->mutexSession); 
	}
	if (rv == CKR_OK) {
		rv = _pkcs11h_mutexInit (&s_pkcs11h_data->mutexCache); 
	}
#if !defined(WIN32)
	if (
		rv == CKR_OK &&
		pthread_atfork (
			__pkcs11h_atfork_prepare,
			__pkcs11h_atfork_parent,
			__pkcs11h_atfork_child
		)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		s_pkcs11h_data->nMaxLoginRetries = PKCS11H_DEFAULT_MAX_LOGIN_RETRY;
		s_pkcs11h_data->fProtectedAuthentication = TRUE;
		s_pkcs11h_data->nPINCachePeriod = PKCS11H_DEFAULT_PIN_CACHE_PERIOD;
		s_pkcs11h_data->fInitialized = TRUE;
	}

	if (rv == CKR_OK) {
		pkcs11h_setLogHook (_pkcs11h_hooks_default_log, NULL);
		pkcs11h_setTokenPromptHook (_pkcs11h_hooks_default_token_prompt, NULL);
		pkcs11h_setPINPromptHook (_pkcs11h_hooks_default_pin_prompt, NULL);
	}
	
#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_initialize return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_terminate () {

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_terminate entry"
	);

	if (s_pkcs11h_data != NULL) {
		pkcs11h_provider_t current_provider = NULL;

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Removing providers"
		);

		for (
			current_provider = s_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			pkcs11h_removeProvider (current_provider->szReferenceName);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_mutexLock (&s_pkcs11h_data->mutexCache);
		_pkcs11h_mutexLock (&s_pkcs11h_data->mutexSession);
		_pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal);
#endif

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Releasing sessions"
		);

		while (s_pkcs11h_data->sessions != NULL) {
			pkcs11h_session_t current = s_pkcs11h_data->sessions;
			s_pkcs11h_data->sessions = s_pkcs11h_data->sessions->next;

#if defined(ENABLE_PKCS11H_THREADING)
			_pkcs11h_mutexLock (&current->mutexSession);
#endif

			current->fValid = FALSE;

			if (current->nReferenceCount != 0) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Warning: Found session with references"
				);
			}

			if (current->token_id != NULL) {
				pkcs11h_freeTokenId (current->token_id);
				current->token_id = NULL;
			}

#if defined(ENABLE_PKCS11H_ENUM)
#if defined(ENABLE_PKCS11H_CERTIFICATE)
			pkcs11h_freeCertificateIdList (current->cached_certs);
#endif
#endif

			current->provider = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
			_pkcs11h_mutexFree (&current->mutexSession);
#endif

			_pkcs11h_free ((void *)&current);
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Terminating slotevent"
		);

		_pkcs11h_slotevent_terminate ();
#endif
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Marking as uninitialized"
		);
		
		s_pkcs11h_data->fInitialized = FALSE;

		while (s_pkcs11h_data->providers != NULL) {
			pkcs11h_provider_t current = s_pkcs11h_data->providers;
			s_pkcs11h_data->providers = s_pkcs11h_data->providers->next;

			_pkcs11h_free ((void *)&current);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_mutexFree (&s_pkcs11h_data->mutexCache);
		_pkcs11h_mutexFree (&s_pkcs11h_data->mutexGlobal); 
		_pkcs11h_mutexFree (&s_pkcs11h_data->mutexSession); 
#endif

		_pkcs11h_free ((void *)&s_pkcs11h_data);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_terminate return"
	);

	return CKR_OK;
}

void
pkcs11h_setLogLevel (
	IN const unsigned flags
) {
	s_pkcs11h_loglevel = flags;
}

unsigned
pkcs11h_getLogLevel () {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);

	return s_pkcs11h_loglevel;
}

CK_RV
pkcs11h_setLogHook (
	IN const pkcs11h_hook_log_t hook,
	IN void * const pData
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (hook!=NULL);

	s_pkcs11h_data->hooks.log = hook;
	s_pkcs11h_data->hooks.log_data = pData;

	return CKR_OK;
}

CK_RV
pkcs11h_setSlotEventHook (
	IN const pkcs11h_hook_slotevent_t hook,
	IN void * const pData
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (hook!=NULL);

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	s_pkcs11h_data->hooks.slotevent = hook;
	s_pkcs11h_data->hooks.slotevent_data = pData;

	return _pkcs11h_slotevent_init ();
#else
	return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

CK_RV
pkcs11h_setPINPromptHook (
	IN const pkcs11h_hook_pin_prompt_t hook,
	IN void * const pData
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (hook!=NULL);

	s_pkcs11h_data->hooks.pin_prompt = hook;
	s_pkcs11h_data->hooks.pin_prompt_data = pData;

	return CKR_OK;
}

CK_RV
pkcs11h_setTokenPromptHook (
	IN const pkcs11h_hook_token_prompt_t hook,
	IN void * const pData
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (hook!=NULL);

	s_pkcs11h_data->hooks.token_prompt = hook;
	s_pkcs11h_data->hooks.token_prompt_data = pData;

	return CKR_OK;
}

CK_RV
pkcs11h_setPINCachePeriod (
	IN const int nPINCachePeriod
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);

	s_pkcs11h_data->nPINCachePeriod = nPINCachePeriod;

	return CKR_OK;
}

CK_RV
pkcs11h_setMaxLoginRetries (
	IN const unsigned nMaxLoginRetries
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);

	s_pkcs11h_data->nMaxLoginRetries = nMaxLoginRetries;

	return CKR_OK;
}

CK_RV
pkcs11h_setProtectedAuthentication (
	IN const PKCS11H_BOOL fProtectedAuthentication
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);

	s_pkcs11h_data->fProtectedAuthentication = fProtectedAuthentication;

	return CKR_OK;
}

CK_RV
pkcs11h_addProvider (
	IN const char * const szReferenceName,
	IN const char * const szProvider,
	IN const PKCS11H_BOOL fProtectedAuthentication,
	IN const unsigned maskSignMode,
	IN const int nSlotEventMethod,
	IN const int nSlotEventPollInterval,
	IN const PKCS11H_BOOL fCertIsPrivate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
#if defined(WIN32)
	int mypid = 0;
#else
	pid_t mypid = getpid ();
#endif
	pkcs11h_provider_t provider = NULL;
	CK_C_GetFunctionList gfl = NULL;
	CK_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (szProvider!=NULL);
	/*PKCS11H_ASSERT (szSignMode!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_addProvider entry pid=%d, szReferenceName=%s, szProvider='%s', fProtectedAuthentication=%d, maskSignMode=%08x, fCertIsPrivate=%d",
		mypid,
		szReferenceName,
		szProvider,
		fProtectedAuthentication ? 1 : 0,
		maskSignMode,
		fCertIsPrivate ? 1 : 0
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Adding provider '%s'-'%s'",
		szReferenceName,
		szProvider
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_malloc ((void *)&provider, sizeof (struct pkcs11h_provider_s))) == CKR_OK
	) {
		strncpy (
			provider->szReferenceName,
			szReferenceName,
			sizeof (provider->szReferenceName)-1
		);
		provider->szReferenceName[sizeof (provider->szReferenceName)-1] = '\x0';
		strncpy (
			provider->manufacturerID,
			(
			 	strlen (szProvider) < sizeof (provider->manufacturerID) ?
				szProvider :
				szProvider+strlen (szProvider)-sizeof (provider->manufacturerID)+1
			),
			sizeof (provider->manufacturerID)-1
		);
		provider->manufacturerID[sizeof (provider->manufacturerID)-1] = '\x0';
		provider->fProtectedAuthentication = fProtectedAuthentication;
		provider->maskSignMode = maskSignMode;
		provider->nSlotEventMethod = nSlotEventMethod;
		provider->nSlotEventPollInterval = nSlotEventPollInterval;
		provider->fCertIsPrivate = fCertIsPrivate;
	}
		
	if (rv == CKR_OK) {
#if defined(WIN32)
		provider->hLibrary = LoadLibraryA (szProvider);
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
			provider->fShouldFinalize = TRUE;
		}
	}

	if (
		rv == CKR_OK &&
		(rv = provider->f->C_GetInfo (&info)) == CKR_OK
	) {
		_pkcs11h_fixupFixedString (
			provider->manufacturerID,
			(char *)info.manufacturerID,
			sizeof (info.manufacturerID)
		);
	}

	if (rv == CKR_OK) {
		provider->fEnabled = TRUE;
	}

	if (provider != NULL) {
		if (s_pkcs11h_data->providers == NULL) {
			s_pkcs11h_data->providers = provider;
		}
		else {
			pkcs11h_provider_t last = NULL;
	
			for (
				last = s_pkcs11h_data->providers;
				last->next != NULL;
				last = last->next
			);
			last->next = provider;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
		fMutexLocked = FALSE;
	}
#endif

#if defined(ENABLE_PKCS11H_SLOTEVENT)
	_pkcs11h_slotevent_notify ();
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Provider '%s' added rv=%ld-'%s'",
		szReferenceName,
		rv,
		pkcs11h_getMessage (rv)
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_addProvider return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_removeProvider (
	IN const char * const szReferenceName
) {
#if defined(ENABLE_PKCS11H_THREADING)
	pkcs11h_session_t current_session = NULL;
#endif
	pkcs11h_provider_t provider = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (szReferenceName!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_removeProvider entry szReferenceName='%s'",
		szReferenceName
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Removing provider '%s'",
		szReferenceName
	);

#if defined(ENABLE_PKCS11H_THREADING)
	_pkcs11h_mutexLock (&s_pkcs11h_data->mutexCache);
	_pkcs11h_mutexLock (&s_pkcs11h_data->mutexSession);
	_pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal);

	for (
		current_session = s_pkcs11h_data->sessions;
		current_session != NULL;
		current_session = current_session->next
	) {
		_pkcs11h_mutexLock (&current_session->mutexSession);
	}
#endif

	provider = s_pkcs11h_data->providers;
	while (
		rv == CKR_OK &&
		provider != NULL &&
		strcmp (szReferenceName, provider->szReferenceName)
	) {
		provider = provider->next;
	}

	if (rv == CKR_OK && provider == NULL) {
		rv = CKR_OBJECT_HANDLE_INVALID;
	}

	if (rv == CKR_OK) {
		provider->fEnabled = FALSE;
		provider->szReferenceName[0] = '\0';

		if (provider->fShouldFinalize) {
			provider->f->C_Finalize (NULL);
			provider->fShouldFinalize = FALSE;
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		_pkcs11h_slotevent_notify ();
		
		/*
		 * Wait until manager join this thread
		 * this happens saldom so I can poll
		 */
		while (provider->threadSlotEvent != PKCS11H_THREAD_NULL) {
			_pkcs11h_sleep (500);
		}
#endif

		if (provider->f != NULL) {
			provider->f = NULL;
		}

		if (provider->hLibrary != NULL) {
#if defined(WIN32)
			FreeLibrary (provider->hLibrary);
#else
			dlclose (provider->hLibrary);
#endif
			provider->hLibrary = NULL;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	for (
		current_session = s_pkcs11h_data->sessions;
		current_session != NULL;
		current_session = current_session->next
	) {
		_pkcs11h_mutexRelease (&current_session->mutexSession);
	}

	_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexCache);
	_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexSession);
	_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
#endif
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_removeProvider return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_forkFixup () {
#if defined(WIN32)
	return CKR_OK;
#else
#if defined(ENABLE_PKCS11H_THREADING)
	return CKR_OK;
#else
	return _pkcs11h_forkFixup ();
#endif
#endif
}

CK_RV
pkcs11h_plugAndPlay () {
#if defined(WIN32)
	int mypid = 0;
#else
	pid_t mypid = getpid ();
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup entry pid=%d",
		mypid
	);

	if (s_pkcs11h_data != NULL && s_pkcs11h_data->fInitialized) {
		pkcs11h_provider_t current;
#if defined(ENABLE_PKCS11H_SLOTEVENT)
		PKCS11H_BOOL fSlotEventActive = FALSE;
#endif

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal);
#endif
		for (
			current = s_pkcs11h_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->fEnabled) {
				current->f->C_Finalize (NULL);
			}
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		if (s_pkcs11h_data->fSlotEventInitialized) {
			fSlotEventActive = TRUE;
			_pkcs11h_slotevent_terminate ();
		}
#endif

		for (
			current = s_pkcs11h_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->fEnabled) {
				current->f->C_Initialize (NULL);
			}
		}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
		if (fSlotEventActive) {
			_pkcs11h_slotevent_init ();
		}
#endif

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
#endif
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_freeTokenId (
	IN pkcs11h_token_id_t token_id
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeTokenId entry certificate_id=%p",
		(void *)token_id
	);

	_pkcs11h_free ((void *)&token_id);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeTokenId return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_duplicateTokenId (
	OUT pkcs11h_token_id_t * const to,
	IN const pkcs11h_token_id_t from
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (to!=NULL);
	PKCS11H_ASSERT (from!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_duplicateTokenId entry to=%p form=%p",
		(void *)to,
		(void *)from
	);

	*to = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_dupmem (
			(void*)to,
			NULL,
			from,
			sizeof (struct pkcs11h_token_id_s)
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_duplicateTokenId return rv=%ld-'%s', *to=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*to
	);
	
	return rv;
}

PKCS11H_BOOL
pkcs11h_sameTokenId (
	IN const pkcs11h_token_id_t a,
	IN const pkcs11h_token_id_t b
) {
	PKCS11H_ASSERT (a!=NULL);
	PKCS11H_ASSERT (b!=NULL);

	return (
		!strcmp (a->manufacturerID, b->manufacturerID) &&
		!strcmp (a->model, b->model) &&
		!strcmp (a->serialNumber, b->serialNumber)
	);
}

/*======================================================================*
 * MEMORY INTERFACE
 *======================================================================*/

static
CK_RV
_pkcs11h_malloc (
	OUT const void ** const p,
	IN const size_t s
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (p!=NULL);
	PKCS11H_ASSERT (s!=0);

	*p = NULL;

	if (s > 0) {
		if (
			(*p = (void *)malloc (s)) == NULL
		) {
			rv = CKR_HOST_MEMORY;
		}
		else {
			memset ((void *)*p, 0, s);
		}
	}

	return rv;
}

static
CK_RV
_pkcs11h_free (
	IN const void ** const p
) {
	PKCS11H_ASSERT (p!=NULL);

	free ((void *)*p);
	*p = NULL;

	return CKR_OK;
}

static
CK_RV
_pkcs11h_dupmem (
	OUT const void ** const dest,
	OUT size_t * const p_dest_size,
	IN const void * const src,
	IN const size_t mem_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (dest!=NULL);
	/*PKCS11H_ASSERT (dest_size!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (!(mem_size!=0&&src==NULL));

	*dest = NULL;
	if (p_dest_size != NULL) {
		*p_dest_size = 0;
	}

	if (src != NULL) {
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_malloc (dest, mem_size)) == CKR_OK
		) {
			if (p_dest_size != NULL) {
				*p_dest_size = mem_size;
			}
			memmove ((void*)*dest, src, mem_size);
		}
	}

	return rv;
}

#if defined(ENABLE_PKCS11H_THREADING)
/*======================================================================*
 * THREADING INTERFACE
 *======================================================================*/

static
void
_pkcs11h_sleep (
	IN const unsigned milli
) {
#if defined(WIN32)
	Sleep (milli);
#else
	usleep (milli*1000);
#endif
}

static
CK_RV
_pkcs11h_mutexInit (
	OUT pkcs11h_mutex_t * const mutex
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		(*mutex = CreateMutex (NULL, FALSE, NULL)) == NULL
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	{
		__pkcs11h_mutex_entry_t entry = NULL;
		PKCS11H_BOOL fMutexLocked = FALSE;

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&__s_pkcs11h_mutex_list.mutex)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
		
		if (rv == CKR_OK) {
			rv = _pkcs11h_malloc (
				(void *)&entry,
				sizeof (struct __pkcs11h_mutex_entry_s)
			);
		}

		if (
			rv == CKR_OK &&
			pthread_mutex_init (mutex, NULL)
		) {
			rv = CKR_FUNCTION_FAILED;
		}

		if (rv == CKR_OK) {
			entry->p_mutex = mutex;
			entry->next = __s_pkcs11h_mutex_list.head;
			__s_pkcs11h_mutex_list.head = entry;
			entry = NULL;
		}

		if (entry != NULL) {
			_pkcs11h_free ((void *)&entry);
		}

		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&__s_pkcs11h_mutex_list.mutex);
			fMutexLocked = FALSE;
		}
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_mutexLock (
	IN OUT pkcs11h_mutex_t *const mutex
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		WaitForSingleObject (*mutex, INFINITE) == WAIT_FAILED
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		pthread_mutex_lock (mutex)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_mutexRelease (
	IN OUT pkcs11h_mutex_t *const mutex
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		!ReleaseMutex (*mutex)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		pthread_mutex_unlock (mutex)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_mutexFree (
	IN OUT pkcs11h_mutex_t *const mutex
) {
#if defined(WIN32)
	if (*mutex != NULL) {
		CloseHandle (*mutex);
		*mutex = NULL;
	}
#else
	{
		__pkcs11h_mutex_entry_t last = NULL;
		__pkcs11h_mutex_entry_t entry = NULL;
		PKCS11H_BOOL fMutexLocked = FALSE;

		if (_pkcs11h_mutexLock (&__s_pkcs11h_mutex_list.mutex) == CKR_OK) {
			fMutexLocked = TRUE;
		}

		entry =  __s_pkcs11h_mutex_list.head;
		while (
			entry != NULL &&
			entry->p_mutex != mutex
		) {
			last = entry;
			entry = entry->next;
		}

		if (entry != NULL) {
			if (last == NULL) {
				__s_pkcs11h_mutex_list.head = entry->next;
			}
			else {
				last->next = entry->next;
			}
			_pkcs11h_free ((void *)&entry);
		}

		pthread_mutex_destroy (mutex);

		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&__s_pkcs11h_mutex_list.mutex);
			fMutexLocked = FALSE;
		}
	}
#endif
	return CKR_OK;
}

#if !defined(WIN32)
/*
 * This function is required in order
 * to lock all mutexes before fork is called,
 * and to avoid dedlocks.
 * The loop is required because there is no
 * way to lock all mutex in one system call...
 */
static
void
__pkcs1h_mutexLockAll () {
	__pkcs11h_mutex_entry_t entry = NULL;
	PKCS11H_BOOL fMutexLocked = FALSE;
	PKCS11H_BOOL fAllLocked = FALSE;

	if (_pkcs11h_mutexLock (&__s_pkcs11h_mutex_list.mutex) == CKR_OK) {
		fMutexLocked = TRUE;
	}

	for (
		entry = __s_pkcs11h_mutex_list.head;
		entry != NULL;
		entry = entry->next
	) {
		entry->fLocked = FALSE;
	}

	while (!fAllLocked) {
		PKCS11H_BOOL fOK = TRUE;
		
		for (
			entry = __s_pkcs11h_mutex_list.head;
			entry != NULL && fOK;
			entry = entry->next
		) {
			if (!pthread_mutex_trylock (entry->p_mutex)) {
				entry->fLocked = TRUE;
			}
			else {
				fOK = FALSE;
			}
		}

		if (!fOK) {
			for (
				entry = __s_pkcs11h_mutex_list.head;
				entry != NULL;
				entry = entry->next
			) {
				if (entry->fLocked == TRUE) {
					pthread_mutex_unlock (entry->p_mutex);
					entry->fLocked = FALSE;
				}
			}

			_pkcs11h_mutexRelease (&__s_pkcs11h_mutex_list.mutex);
			_pkcs11h_sleep (1000);
			_pkcs11h_mutexLock (&__s_pkcs11h_mutex_list.mutex);
		}
		else {
			fAllLocked  = TRUE;
		}
	}

	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&__s_pkcs11h_mutex_list.mutex);
		fMutexLocked = FALSE;
	}
}

static
void
__pkcs1h_mutexReleaseAll () {
	__pkcs11h_mutex_entry_t entry = NULL;
	PKCS11H_BOOL fMutexLocked = FALSE;

	if (_pkcs11h_mutexLock (&__s_pkcs11h_mutex_list.mutex) == CKR_OK) {
		fMutexLocked = TRUE;
	}

	for (
		entry = __s_pkcs11h_mutex_list.head;
		entry != NULL;
		entry = entry->next
	) {
		pthread_mutex_unlock (entry->p_mutex);
		entry->fLocked = FALSE;
	}

	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&__s_pkcs11h_mutex_list.mutex);
		fMutexLocked = FALSE;
	}
}
#endif

CK_RV
_pkcs11h_condSignal (
	IN OUT pkcs11h_cond_t *const cond
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		!SetEvent (*cond)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		(
			pthread_mutex_lock (&cond->mut) ||
			pthread_cond_signal (&cond->cond) ||
			pthread_mutex_unlock (&cond->mut)
		)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif

	return rv;
}

static
CK_RV
_pkcs11h_condInit (
	OUT pkcs11h_cond_t * const cond
) {
	CK_RV rv = CKR_OK;
#if defined(WIN32)
	if (
		rv == CKR_OK &&
		(*cond = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (
		rv == CKR_OK &&
		(
			pthread_mutex_init (&cond->mut, NULL) ||
			pthread_cond_init (&cond->cond, NULL) ||
			pthread_mutex_lock (&cond->mut)
		)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_condWait (
	IN OUT pkcs11h_cond_t *const cond,
	IN const unsigned milli
) {
	CK_RV rv = CKR_OK;

#if defined(WIN32)
	DWORD dwMilli;

	if (milli == PKCS11H_COND_INFINITE) {
		dwMilli = INFINITE;
	}
	else {
		dwMilli = milli;
	}

	if (
		rv == CKR_OK &&
		WaitForSingleObject (*cond, dwMilli) == WAIT_FAILED
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#else
	if (milli == PKCS11H_COND_INFINITE) {
		if (
			rv == CKR_OK &&
			pthread_cond_wait (&cond->cond, &cond->mut)
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	}
	else {
		struct timeval now;
		struct timespec timeout;

		if (
			rv == CKR_OK &&
			gettimeofday (&now, NULL)
		) {
			rv = CKR_FUNCTION_FAILED;
		}
		
		if (rv == CKR_OK) {
			timeout.tv_sec = now.tv_sec + milli/1000;
			timeout.tv_nsec = now.tv_usec*1000 + milli%1000;
		}
		
		if (
			rv == CKR_OK &&
			pthread_cond_timedwait (&cond->cond, &cond->mut, &timeout)
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_condFree (
	IN OUT pkcs11h_cond_t *const cond
) {
#if defined(WIN32)
	CloseHandle (*cond);
	*cond = NULL;
#else
	pthread_mutex_unlock (&cond->mut);
#endif
	return CKR_OK;
}

#if defined(WIN32)
static
unsigned
__stdcall
__pkcs11h_thread_start (void *p) {
	__pkcs11h_thread_data_t *_data = (__pkcs11h_thread_data_t *)p;
	unsigned ret;

	ret = (unsigned)_data->start (_data->data);

	_pkcs11h_free ((void *)&_data);

	return ret;
}
#else
static
void *
__pkcs11h_thread_start (void *p) {
	__pkcs11h_thread_data_t *_data = (__pkcs11h_thread_data_t *)p;
	void *ret;
	int i;

	/*
	 * Ignore any signal in
	 * this thread
	 */
	for (i=1;i<16;i++) {
		signal (i, SIG_IGN);
	}

	ret = _data->start (_data->data);

	_pkcs11h_free ((void *)&_data);

	return ret;
}
#endif

static
CK_RV
_pkcs11h_threadStart (
	OUT pkcs11h_thread_t * const thread,
	IN pkcs11h_thread_start_t const start,
	IN void * data
) {
	__pkcs11h_thread_data_t *_data = NULL;
	CK_RV rv = CKR_OK;

	if (rv == CKR_OK) {
		rv = _pkcs11h_malloc (
			(void *)&_data,
			sizeof (__pkcs11h_thread_data_t)
		);
	}

	if (rv == CKR_OK) {
		_data->start = start;
		_data->data = data;
	}

#if defined(WIN32)
	{
		unsigned tmp;

		if (
			rv == CKR_OK &&
			(*thread = (HANDLE)_beginthreadex (
				NULL,
				0,
				__pkcs11h_thread_start,
				_data,
				0,
				&tmp
			)) == NULL
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	}
#else
	if (
		rv == CKR_OK &&
		pthread_create (thread, NULL, __pkcs11h_thread_start, _data)
	) {
		rv = CKR_FUNCTION_FAILED;
	}
#endif
	return rv;
}

static
CK_RV
_pkcs11h_threadJoin (
	IN pkcs11h_thread_t * const thread
) {
#if defined(WIN32)
	WaitForSingleObject (*thread, INFINITE);
	CloseHandle (*thread);
	*thread = NULL;
#else
	pthread_join (*thread, NULL);
	*thread = 0l;
#endif
	return CKR_OK;
}

#endif		/* ENABLE_PKCS11H_THREADING */

/*======================================================================*
 * COMMON INTERNAL INTERFACE
 *======================================================================*/

static
void
_pkcs11h_fixupFixedString (
	OUT char * const szTarget,			/* MUST BE >= nLength+1 */
	IN const char * const szSource,
	IN const size_t nLength				/* FIXED STRING LENGTH */
) {
	char *p;

	PKCS11H_ASSERT (szSource!=NULL);
	PKCS11H_ASSERT (szTarget!=NULL);
	
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
_pkcs11h_log (
	IN const unsigned flags,
	IN const char * const szFormat,
	IN ...
) {
	va_list args;

	PKCS11H_ASSERT (szFormat!=NULL);

	va_start (args, szFormat);

	if (
		s_pkcs11h_data != NULL &&
		s_pkcs11h_data->fInitialized
	) { 
		if (PKCS11H_MSG_LEVEL_TEST (flags)) {
			if (s_pkcs11h_data->hooks.log == NULL) {
				_pkcs11h_hooks_default_log (
					NULL,
					flags,
					szFormat,
					args
				);
			}
			else {
				s_pkcs11h_data->hooks.log (
					s_pkcs11h_data->hooks.log_data,
					flags,
					szFormat,
					args
				);
			}
		}
	}

	va_end (args);
}

static
CK_RV
_pkcs11h_getSlotList (
	IN const pkcs11h_provider_t provider,
	IN const CK_BBOOL tokenPresent,
	OUT CK_SLOT_ID_PTR * const pSlotList,
	OUT CK_ULONG_PTR pulCount
) {
	CK_SLOT_ID_PTR _slots = NULL;
	CK_ULONG _slotnum = 0;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (provider!=NULL);
	PKCS11H_ASSERT (pSlotList!=NULL);
	PKCS11H_ASSERT (pulCount!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSlotList entry provider=%p, tokenPresent=%d, pSlotList=%p, pulCount=%p",
		(void *)provider,
		tokenPresent,
		(void *)pSlotList,
		(void *)pulCount
	);

	*pSlotList = NULL;
	*pulCount = 0;

	if (
		rv == CKR_OK &&
		!provider->fEnabled
	) {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (rv == CKR_OK) {
		rv = provider->f->C_GetSlotList (
			tokenPresent,
			NULL_PTR,
			&_slotnum
		);
	}

	if (rv == CKR_OK && _slotnum > 0) {
		rv = _pkcs11h_malloc ((void *)&_slots, _slotnum * sizeof (CK_SLOT_ID));
	}

	if (rv == CKR_OK && _slotnum > 0) {
		rv = provider->f->C_GetSlotList (
			tokenPresent,
			_slots,
			&_slotnum
		);
	}

	if (rv == CKR_OK) {
		*pSlotList = _slots;
		_slots = NULL;
		*pulCount = _slotnum;
	}

	if (_slots != NULL) {
		_pkcs11h_free ((void *)&_slots);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSlotList return rv=%ld-'%s' *pulCount=%ld",
		rv,
		pkcs11h_getMessage (rv),
		*pulCount
	);

	return rv;
}

static
CK_RV
_pkcs11h_getObjectAttributes (
	IN const pkcs11h_session_t session,
	IN const CK_OBJECT_HANDLE object,
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (attrs!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getObjectAttributes entry session=%p, object=%ld, attrs=%p, count=%d",
		(void *)session,
		object,
		(void *)attrs,
		count
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = session->provider->f->C_GetAttributeValue (
			session->hSession,
			object,
			attrs,
			count
		)) == CKR_OK
	) {
		unsigned i;
		for (i=0;rv == CKR_OK && i<count;i++) {
			if (attrs[i].ulValueLen == (CK_ULONG)-1) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else if (attrs[i].ulValueLen == 0) {
				attrs[i].pValue = NULL;
			}
			else {
				rv = _pkcs11h_malloc (
					(void *)&attrs[i].pValue,
					attrs[i].ulValueLen
				);
			}
		}
	}

	if (rv == CKR_OK) {
		rv = session->provider->f->C_GetAttributeValue (
			session->hSession,
			object,
			attrs,
			count
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&session->mutexSession);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getObjectAttributes return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_freeObjectAttributes (
	IN OUT const CK_ATTRIBUTE_PTR attrs,
	IN const unsigned count
) {
	unsigned i;

	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (attrs!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_freeObjectAttributes entry attrs=%p, count=%d",
		(void *)attrs,
		count
	);

	for (i=0;i<count;i++) {
		if (attrs[i].pValue != NULL) {
			_pkcs11h_free ((void *)&attrs[i].pValue);
			attrs[i].pValue = NULL;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_freeObjectAttributes return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_findObjects (
	IN const pkcs11h_session_t session,
	IN const CK_ATTRIBUTE * const filter,
	IN const CK_ULONG filter_attrs,
	OUT CK_OBJECT_HANDLE **const p_objects,
	OUT CK_ULONG *p_objects_found
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	PKCS11H_BOOL fShouldFindObjectFinal = FALSE;

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_size = 0;
	CK_OBJECT_HANDLE objects_buffer[100];
	CK_ULONG objects_found;
	CK_OBJECT_HANDLE oLast = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (!(filter==NULL && filter_attrs!=0) || filter!=NULL);
	PKCS11H_ASSERT (p_objects!=NULL);
	PKCS11H_ASSERT (p_objects_found!=NULL);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_findObjects entry session=%p, filter=%p, filter_attrs=%ld, p_objects=%p, p_objects_found=%p",
		(void *)session,
		(void *)filter,
		filter_attrs,
		(void *)p_objects,
		(void *)p_objects_found
	);

	*p_objects = NULL;
	*p_objects_found = 0;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = session->provider->f->C_FindObjectsInit (
			session->hSession,
			(CK_ATTRIBUTE *)filter,
			filter_attrs
		)) == CKR_OK
	) {
		fShouldFindObjectFinal = TRUE;
	}

	while (
		rv == CKR_OK &&
		(rv = session->provider->f->C_FindObjects (
			session->hSession,
			objects_buffer,
			sizeof (objects_buffer) / sizeof (CK_OBJECT_HANDLE),
			&objects_found
		)) == CKR_OK &&
		objects_found > 0
	) { 
		CK_OBJECT_HANDLE *temp = NULL;
		
		/*
		 * Begin workaround
		 *
		 * Workaround iKey bug
		 * It returns the same objects over and over
		 */
		if (oLast == objects_buffer[0]) {
			PKCS11H_LOG (
				PKCS11H_LOG_WARN,
				"PKCS#11: Bad PKCS#11 C_FindObjects implementation detected, workaround applied"
			);
			break;
		}
		oLast = objects_buffer[0];
		/* End workaround */
		
		if (
			(rv = _pkcs11h_malloc (
				(void *)&temp,
				(objects_size+objects_found) * sizeof (CK_OBJECT_HANDLE)
			)) == CKR_OK
		) {
			if (objects != NULL) {
				memmove (
					temp,
					objects,
					objects_size * sizeof (CK_OBJECT_HANDLE)
				);
			}
			memmove (
				temp + objects_size,
				objects_buffer,
				objects_found * sizeof (CK_OBJECT_HANDLE)
			);
		}

		if (rv == CKR_OK) {
			_pkcs11h_free ((void *)&objects);
			objects = temp;
			objects_size += objects_found;
			temp = NULL;
		}

		if (temp != NULL) {
			_pkcs11h_free ((void *)&temp);
			temp = NULL;
		}
	}

	if (fShouldFindObjectFinal) {
		session->provider->f->C_FindObjectsFinal (
			session->hSession
		);
		fShouldFindObjectFinal = FALSE;
	}
	
#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&session->mutexSession);
		fMutexLocked = FALSE;
	}
#endif

	if (rv == CKR_OK) {
		*p_objects = objects;
		*p_objects_found = objects_size;
		objects = NULL;
		objects_size = 0;
	}

	if (objects != NULL) {
		_pkcs11h_free ((void *)&objects);
		objects = NULL;
		objects_size = 0;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_findObjects return rv=%ld-'%s', *p_objects_found=%ld",
		rv,
		pkcs11h_getMessage (rv),
		*p_objects_found
	);

	return rv;
}

static
CK_RV
_pkcs11h_getTokenId (
	IN const CK_TOKEN_INFO_PTR info,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_token_id_t token_id;
	CK_RV rv = CKR_OK;
	
	PKCS11H_ASSERT (info!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getTokenId entry p_token_id=%p",
		(void *)p_token_id
	);

	*p_token_id = NULL;

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_newTokenId (&token_id)) == CKR_OK
	) {
		_pkcs11h_fixupFixedString (
			token_id->label,
			(char *)info->label,
			sizeof (info->label)
		);
		_pkcs11h_fixupFixedString (
			token_id->manufacturerID,
			(char *)info->manufacturerID,
			sizeof (info->manufacturerID)
		);
		_pkcs11h_fixupFixedString (
			token_id->model,
			(char *)info->model,
			sizeof (info->model)
		);
		_pkcs11h_fixupFixedString (
			token_id->serialNumber,
			(char *)info->serialNumber,
			sizeof (info->serialNumber)
		);
	}

	if (rv == CKR_OK) {
		*p_token_id = token_id;
		token_id = NULL;
	}

	if (token_id != NULL) {
		_pkcs11h_free ((void *)&token_id);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getTokenId return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_newTokenId (
	OUT pkcs11h_token_id_t * const p_token_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_newTokenId entry p_token_id=%p",
		(void *)p_token_id
	);

	*p_token_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_malloc ((void *)p_token_id, sizeof (struct pkcs11h_token_id_s));
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_newTokenId return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_getSessionByTokenId (
	IN const pkcs11h_token_id_t token_id,
	OUT pkcs11h_session_t * const p_session
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL fNewSession = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (p_session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSessionByTokenId entry token_id=%p, p_session=%p",
		(void *)token_id,
		(void *)p_session
	);

	*p_session = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexSession)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		pkcs11h_session_t current_session;

		for (
			current_session = s_pkcs11h_data->sessions;
			current_session != NULL && session == NULL;
			current_session = current_session->next
		) {
			if (
				pkcs11h_sameTokenId (
					current_session->token_id,
					token_id
				)
			) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Using cached session"
				);
				session = current_session;
				session->nReferenceCount++;
			}
		}
	}

	if (
		rv == CKR_OK &&
		session == NULL
	) {
		fNewSession = TRUE;
	}

	if (fNewSession) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Creating a new session"
		);

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_malloc ((void *)&session, sizeof (struct pkcs11h_session_s))) == CKR_OK
		) {
			session->nReferenceCount = 1;
			session->hSession = PKCS11H_INVALID_SESSION_HANDLE;
			
			session->nPINCachePeriod = s_pkcs11h_data->nPINCachePeriod;

		}

		if (rv == CKR_OK) {
			rv = pkcs11h_duplicateTokenId (
				&session->token_id,
				token_id
			);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (rv == CKR_OK) {
			rv = _pkcs11h_mutexInit (&session->mutexSession);
		}
#endif

		if (rv == CKR_OK) {
			session->fValid = TRUE;
			session->next = s_pkcs11h_data->sessions;
			s_pkcs11h_data->sessions = session;
		}
		else {
#if defined(ENABLE_PKCS11H_THREADING)
			_pkcs11h_mutexFree (&session->mutexSession);
#endif
			_pkcs11h_free ((void *)&session);
		}
	}

	if (rv == CKR_OK) {
		*p_session = session;
		session = NULL;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexSession);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getSessionByTokenId return rv=%ld-'%s', *p_session=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_session
	);

	return rv;
}

static
CK_RV
_pkcs11h_releaseSession (
	IN const pkcs11h_session_t session
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (session->nReferenceCount>=0);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_releaseSession entry session=%p",
		(void *)session
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	/*
	 * Never logout for now
	 */
	if (rv == CKR_OK) {
		if (session->nReferenceCount > 0) {
			session->nReferenceCount--;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&session->mutexSession);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_releaseSession return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_resetSession (
	IN const pkcs11h_session_t session,
	IN const unsigned maskPrompt,
	OUT CK_SLOT_ID * const p_slot
) {
	/*
	 * This function MUST NOT touch session
	 */
	PKCS11H_BOOL fFound = FALSE;

	CK_RV rv = CKR_OK;

	unsigned nRetry = 0;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (p_slot!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_resetSession entry session=%p, maskPrompt=%08x, p_slot=%p",
		(void *)session,
		maskPrompt,
		(void *)p_slot
	);

	*p_slot = PKCS11H_INVALID_SLOT_ID;

	while (
		rv == CKR_OK &&
		!fFound
	) {
		pkcs11h_provider_t current_provider = NULL;
#if defined(ENABLE_PKCS11H_THREADING)
		PKCS11H_BOOL fMutexLocked = FALSE;
#endif

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		for (
			current_provider = s_pkcs11h_data->providers;
			(
				rv == CKR_OK &&
				current_provider != NULL &&
				!fFound
			);
			current_provider = current_provider->next
		) {
			CK_SLOT_ID_PTR slots = NULL;
			CK_ULONG slotnum;
			CK_SLOT_ID slot_index;

			/*
			 * Skip all other providers,
			 * if one was set in the past
			 */
			if (
				session->provider != NULL &&
				session->provider != current_provider
			) {
				rv = CKR_CANCEL;
			}
		
			if (rv == CKR_OK) {
				rv = _pkcs11h_getSlotList (
					current_provider,
					CK_TRUE,
					&slots,
					&slotnum
				);
			}

			for (
				slot_index=0;
				(
					slot_index < slotnum &&
					rv == CKR_OK && 
					!fFound
				);
				slot_index++
			) {
				pkcs11h_token_id_t token_id = NULL;
				CK_TOKEN_INFO info;

				if (rv == CKR_OK) {
					rv = current_provider->f->C_GetTokenInfo (
						slots[slot_index],
						&info
					);
				}

				if (
					rv == CKR_OK &&
					(rv = _pkcs11h_getTokenId (
						&info,
						&token_id
					)) == CKR_OK &&
					pkcs11h_sameTokenId (
						session->token_id,
						token_id
					)
				) {
					fFound = TRUE;
					*p_slot = slots[slot_index];
					if (session->provider == NULL) {
						session->provider = current_provider;
						_pkcs11h_fixupFixedString (
							token_id->label,
							(char *)info.label,
							sizeof (info.label)
						);
						session->fProtectedAuthenticationSupported = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0;
					}
				}

				if (rv != CKR_OK) {
					PKCS11H_DEBUG (
						PKCS11H_LOG_DEBUG1,
						"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%ld-'%s'",
						current_provider->manufacturerID,
						slots[slot_index],
						rv,
						pkcs11h_getMessage (rv)
					);

					/*
					 * Ignore error
					 */
					rv = CKR_OK;
				}

				if (token_id != NULL) {
					pkcs11h_freeTokenId (token_id);
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
					current_provider->manufacturerID,
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}

			if (slots != NULL) {
				_pkcs11h_free ((void *)&slots);
				slots = NULL;
			}
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&session->mutexSession);
			fMutexLocked = FALSE;
		}
#endif

		if (
			rv == CKR_OK &&
			!fFound
		) {
			if ((maskPrompt & PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT) != 0) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Calling token_prompt hook for '%s'",
					session->token_id->label
				);
		
				if (
					!s_pkcs11h_data->hooks.token_prompt (
						s_pkcs11h_data->hooks.token_prompt_data,
						session->token_id,
						nRetry++
					)
				) {
					rv = CKR_CANCEL;
				}

				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: token_prompt returned %ld",
					rv
				);
			}
			else {
				rv = CKR_TOKEN_NOT_PRESENT;
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_resetSession return rv=%ld-'%s', *p_slot=%ld",
		rv,
		pkcs11h_getMessage (rv),
		*p_slot
	);

	return rv;
}

static
CK_RV
_pkcs11h_getObjectById (
	IN const pkcs11h_session_t session,
	IN const CK_OBJECT_CLASS class,
	IN const CK_BYTE_PTR id,
	IN const size_t id_size,
	OUT CK_OBJECT_HANDLE * const p_handle
) {
	CK_ATTRIBUTE filter[] = {
		{CKA_CLASS, (void *)&class, sizeof (class)},
		{CKA_ID, (void *)id, id_size}
	};
	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;
	
	/*PKCS11H_ASSERT (session!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (id!=NULL);
	PKCS11H_ASSERT (p_handle!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getObjectById entry session=%p, class=%ld, id=%p, id_size=%u, p_handle=%p",
		(void *)session,
		class,
		id,
		id_size,
		(void *)p_handle
	);

	*p_handle = PKCS11H_INVALID_OBJECT_HANDLE;

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (session);
	}

	if (rv == CKR_OK) { 
		rv = _pkcs11h_findObjects (
			session,
			filter,
			sizeof (filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	if (
		rv == CKR_OK &&
		objects_found == 0
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	if (rv == CKR_OK) {
		*p_handle = objects[0];
	}

	if (objects != NULL) {
		_pkcs11h_free ((void *)&objects);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getObjectById return rv=%ld-'%s', *p_handle=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_handle
	);

	return rv;
}

static
CK_RV
_pkcs11h_validateSession (
	IN const pkcs11h_session_t session
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	/*PKCS11H_ASSERT (session!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_validateSession entry session=%p",
		(void *)session
	);

	if (
		rv == CKR_OK &&
		session == NULL
	) {
		rv = CKR_SESSION_HANDLE_INVALID;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(
			session->provider == NULL ||
			!session->provider->fEnabled ||
			session->hSession == PKCS11H_INVALID_SESSION_HANDLE
		)
	) {
		rv = CKR_SESSION_HANDLE_INVALID;
	}

	if (
		rv == CKR_OK &&
		session->timePINExpire != (time_t)0 &&
		session->timePINExpire < PKCS11H_TIME (NULL)
	) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Forcing logout due to pin timeout"
		);
		_pkcs11h_logout (session);
		rv = CKR_SESSION_HANDLE_INVALID;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&session->mutexSession);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_validateSession return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_login (
	IN const pkcs11h_session_t session,
	IN const PKCS11H_BOOL fPublicOnly,
	IN const PKCS11H_BOOL fReadOnly,
	IN const unsigned maskPrompt
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	CK_SLOT_ID slot = PKCS11H_INVALID_SLOT_ID;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_login entry session=%p, fPublicOnly=%d, fReadOnly=%d, maskPrompt=%08x",
		(void *)session,
		fPublicOnly ? 1 : 0,
		fReadOnly ? 1 : 0,
		maskPrompt
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_logout (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_resetSession (session, maskPrompt, &slot);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = session->provider->f->C_OpenSession (
			slot,
			(
				CKF_SERIAL_SESSION |
				(fReadOnly ? 0 : CKF_RW_SESSION)
			),
			NULL_PTR,
			NULL_PTR,
			&session->hSession
		);
	}

	if (
		rv == CKR_OK &&
	   	(
			!fPublicOnly ||
			session->provider->fCertIsPrivate
		)
	) {
		PKCS11H_BOOL fSuccessLogin = FALSE;
		unsigned nRetryCount = 0;

		if ((maskPrompt & PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT) == 0) {
			rv = CKR_USER_NOT_LOGGED_IN;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling pin_prompt hook denied because of prompt mask"
			);
		}

		while (
			rv == CKR_OK &&
			!fSuccessLogin &&
			nRetryCount < s_pkcs11h_data->nMaxLoginRetries 
		) {
			CK_UTF8CHAR_PTR utfPIN = NULL;
			CK_ULONG lPINLength = 0;
			char szPIN[1024];

			if (
				rv == CKR_OK &&
				!(
					s_pkcs11h_data->fProtectedAuthentication  &&
					session->provider->fProtectedAuthentication &&
					session->fProtectedAuthenticationSupported
				)
			) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Calling pin_prompt hook for '%s'",
					session->token_id->label
				);

				if (
					!s_pkcs11h_data->hooks.pin_prompt (
						s_pkcs11h_data->hooks.pin_prompt_data,
						session->token_id,
						nRetryCount,
						szPIN,
						sizeof (szPIN)
					)
				) {
					rv = CKR_CANCEL;
				}
				else {
					utfPIN = (CK_UTF8CHAR_PTR)szPIN;
					lPINLength = strlen (szPIN);
				}

				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: pin_prompt hook return rv=%ld",
					rv
				);
			}

			if (rv == CKR_OK) {
				if (session->nPINCachePeriod == PKCS11H_PIN_CACHE_INFINITE) {
					session->timePINExpire = 0;
				}
				else {
					session->timePINExpire = (
						PKCS11H_TIME (NULL) +
						(time_t)session->nPINCachePeriod
					);
				}
			}

			if (
				rv == CKR_OK &&
				(rv = session->provider->f->C_Login (
					session->hSession,
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

			if (rv == CKR_OK) {
				fSuccessLogin = TRUE;
			}
			else if (
				rv == CKR_PIN_INCORRECT ||
				rv == CKR_PIN_INVALID
			) {
				/*
				 * Ignore these errors
				 * so retry can be performed
				 */
				rv = CKR_OK;
			}

			nRetryCount++;
		}

		/*
		 * Retry limit
		 */
		if (!fSuccessLogin && rv == CKR_OK) {
			rv = CKR_PIN_INCORRECT;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&session->mutexSession);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_login return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_logout (
	IN const pkcs11h_session_t session
) {
	/*PKCS11H_ASSERT (session!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_logout entry session=%p",
		(void *)session
	);

	if (
		session != NULL &&
		session->hSession != PKCS11H_INVALID_SESSION_HANDLE
	) {
#if defined(ENABLE_PKCS11H_THREADING)
		PKCS11H_BOOL fMutexLocked = FALSE;
#endif
		CK_RV rv = CKR_OK;

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		if (rv == CKR_OK) {
			if (session->provider != NULL) {
				session->provider->f->C_Logout (session->hSession);
				session->provider->f->C_CloseSession (session->hSession);
			}
			session->hSession = PKCS11H_INVALID_SESSION_HANDLE;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&session->mutexSession);
			fMutexLocked = FALSE;
		}
#endif
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_logout return"
	);

	return CKR_OK;
}

static
void
_pkcs11h_hooks_default_log (
	IN const void * pData,
	IN const unsigned flags,
	IN const char * const szFormat,
	IN va_list args
) {
	(void)pData;
	(void)flags;
	(void)szFormat;
	(void)args;
}

static
PKCS11H_BOOL
_pkcs11h_hooks_default_token_prompt (
	IN const void * pData,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
) {
	PKCS11H_ASSERT (token!=NULL);

	(void)pData;
	(void)retry;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_hooks_default_token_prompt pData=%p, szLabel='%s'",
		pData,
		token->label
	);

	return FALSE;
}

static
PKCS11H_BOOL
_pkcs11h_hooks_default_pin_prompt (
	IN const void * pData,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	PKCS11H_ASSERT (token!=NULL);

	(void)pData;
	(void)retry;
	(void)szPIN;
	(void)nMaxPIN;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_hooks_default_pin_prompt pData=%p, szLabel='%s'",
		pData,
		token->label
	);
	
	return FALSE;
}

#if !defined(WIN32)
#if defined(ENABLE_PKCS11H_THREADING)

static
void
__pkcs11h_atfork_prepare  () {
	__pkcs1h_mutexLockAll ();
}
static
void
__pkcs11h_atfork_parent () {
	__pkcs1h_mutexReleaseAll ();
}
static
void
__pkcs11h_atfork_child () {
	__pkcs1h_mutexReleaseAll ();
	_pkcs11h_forkFixup ();
}

#endif				/* ENABLE_PKCS11H_THREADING */

static
CK_RV
_pkcs11h_forkFixup () {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	pid_t mypid = getpid ();

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup entry pid=%d",
		mypid
	);

	if (s_pkcs11h_data != NULL && s_pkcs11h_data->fInitialized) {
		pkcs11h_provider_t current;

#if defined(ENABLE_PKCS11H_THREADING)
		if (_pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal) == CKR_OK) {
			fMutexLocked = TRUE;
		}
#endif

		for (
			current = s_pkcs11h_data->providers;
			current != NULL;
			current = current->next
		) {
			if (current->fEnabled) {
				current->f->C_Initialize (NULL);
			}

#if defined(ENABLE_PKCS11H_SLOTEVENT)
			/*
			 * After fork we have no threads...
			 * So just initialized.
			 */
			if (s_pkcs11h_data->fSlotEventInitialized) {
				s_pkcs11h_data->fSlotEventInitialized = FALSE;
				_pkcs11h_slotevent_init ();
			}
#endif
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_forkFixup return"
	);

	return CKR_OK;
}

#endif				/* !WIN32 */

#if defined(ENABLE_PKCS11H_TOKEN)
/*======================================================================*
 * TOKEN INTERFACE
 *======================================================================*/

CK_RV
pkcs11h_token_ensureAccess (
	IN const pkcs11h_token_id_t token_id,
	IN const unsigned maskPrompt
) {
	pkcs11h_session_t session = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_ensureAccess entry token_id=%p, maskPrompt=%08x",
		(void *)token_id,
		maskPrompt
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_getSessionByTokenId (
			token_id,
			&session
		);
	}

	if (rv == CKR_OK) {
		CK_SLOT_ID slot;

		rv = _pkcs11h_resetSession (
			session,
			maskPrompt,
			&slot
		);
	}

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_ensureAccess return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

#endif				/* ENABLE_PKCS11H_TOKEN */

#if defined(ENABLE_PKCS11H_DATA)
/*======================================================================*
 * DATA INTERFACE
 *======================================================================*/

static
CK_RV
_pkcs11h_data_getObject (
	IN const pkcs11h_session_t session,
	IN const char * const szApplication,
	IN const char * const szLabel,
	OUT CK_OBJECT_HANDLE * const p_handle
) {
	CK_OBJECT_CLASS class = CKO_DATA;
	CK_ATTRIBUTE filter[] = {
		{CKA_CLASS, (void *)&class, sizeof (class)},
		{CKA_APPLICATION, (void *)szApplication, szApplication == NULL ? 0 : strlen (szApplication)},
		{CKA_LABEL, (void *)szLabel, szLabel == NULL ? 0 : strlen (szLabel)}
	};
	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;
	
	/*PKCS11H_ASSERT (session!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (szApplication!=NULL);
	PKCS11H_ASSERT (szLabel!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_data_getObject entry session=%p, szApplication='%s', szLabel='%s', p_handle=%p",
		(void *)session,
		szApplication,
		szLabel,
		(void *)p_handle
	);

	*p_handle = PKCS11H_INVALID_OBJECT_HANDLE;

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_findObjects (
			session,
			filter,
			sizeof (filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	if (
		rv == CKR_OK &&
		objects_found == 0
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	if (rv == CKR_OK) {
		*p_handle = objects[0];
	}

	if (objects != NULL) {
		_pkcs11h_free ((void *)&objects);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_data_getObject return rv=%ld-'%s', *p_handle=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_handle
	);

	return rv;
}

CK_RV
pkcs11h_data_get (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic,
	IN const char * const szApplication,
	IN const char * const szLabel,
	OUT char * const blob,
	IN OUT size_t * const p_blob_size
) {
	CK_ATTRIBUTE attrs[] = {
		{CKA_VALUE, NULL, 0}
	};
	CK_OBJECT_HANDLE handle = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

	pkcs11h_session_t session = NULL;
	size_t blob_size_max;
	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;
	PKCS11H_BOOL fMutexLocked = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (szApplication!=NULL);
	PKCS11H_ASSERT (szLabel!=NULL);
	/*PKCS11H_ASSERT (blob!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_blob_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_get entry token_id=%p, szApplication='%s', szLabel='%s', blob=%p, p_blob_size=%p",
		(void *)token_id,
		szApplication,
		szLabel,
		blob,
		(void *)p_blob_size
	);

	blob_size_max = *p_blob_size;
	*p_blob_size = 0;

	if (rv == CKR_OK) {
		rv = _pkcs11h_getSessionByTokenId (
			token_id,
			&session
		);
	}

	while (rv == CKR_OK && !fOpSuccess) {

		if (rv == CKR_OK) {
			rv = _pkcs11h_validateSession (session);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		if (rv == CKR_OK) {
			rv = _pkcs11h_data_getObject (
				session,
				szApplication,
				szLabel,
				&handle
			);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_getObjectAttributes (
				session,
				handle,
				attrs,
				sizeof (attrs)/sizeof (CK_ATTRIBUTE)
			);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&session->mutexSession);
			fMutexLocked = FALSE;
		}
#endif

		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Read data object failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				fLoginRetry = TRUE;
				rv = _pkcs11h_login (
					session,
					fPublic,
					TRUE,
					(
						PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
						PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
					)
				);
			}
		}
	}

	if (rv == CKR_OK) {
		*p_blob_size = attrs[0].ulValueLen;
	}

	if (rv == CKR_OK) {
		if (blob != NULL) {
			if (*p_blob_size > blob_size_max) {
				rv = CKR_BUFFER_TOO_SMALL;
			}
			else {
				memmove (blob, attrs[0].pValue, *p_blob_size);
			}
		}
	}

	_pkcs11h_freeObjectAttributes (
		attrs,
		sizeof (attrs)/sizeof (CK_ATTRIBUTE)
	);

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_get return rv=%ld-'%s', *p_blob_size=%d",
		rv,
		pkcs11h_getMessage (rv),
		*p_blob_size
	);

	return rv;
}

CK_RV
pkcs11h_data_put (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic,
	IN const char * const szApplication,
	IN const char * const szLabel,
	OUT char * const blob,
	IN const size_t blob_size
) {
	CK_OBJECT_CLASS class = CKO_DATA;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;

	CK_ATTRIBUTE attrs[] = {
		{CKA_CLASS, &class, sizeof (class)},
		{CKA_TOKEN, &ck_true, sizeof (ck_true)},
		{CKA_PRIVATE, fPublic ? &ck_false : &ck_true, sizeof (CK_BBOOL)},
		{CKA_APPLICATION, (void *)szApplication, strlen (szApplication)},
		{CKA_LABEL, (void *)szLabel, strlen (szLabel)},
		{CKA_VALUE, blob, blob_size}
	};

	CK_OBJECT_HANDLE handle = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;
	PKCS11H_BOOL fMutexLocked = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (szApplication!=NULL);
	PKCS11H_ASSERT (szLabel!=NULL);
	PKCS11H_ASSERT (blob!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_put entry token_id=%p, szApplication='%s', szLabel='%s', blob=%p, blob_size=%d",
		(void *)token_id,
		szApplication,
		szLabel,
		blob,
		blob_size
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_getSessionByTokenId (
			token_id,
			&session
		);
	}

	while (rv == CKR_OK && !fOpSuccess) {

		if (rv == CKR_OK) {
			rv = _pkcs11h_validateSession (session);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		if (rv == CKR_OK) {
			rv = session->provider->f->C_CreateObject (
				session->hSession,
				attrs,
				sizeof (attrs)/sizeof (CK_ATTRIBUTE),
				&handle
			);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&session->mutexSession);
			fMutexLocked = FALSE;
		}
#endif

		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Write data object failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				fLoginRetry = TRUE;
				rv = _pkcs11h_login (
					session,
					fPublic,
					FALSE,
					(
						PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
						PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
					)
				);
			}
		}
	}

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_put return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_data_del (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic,
	IN const char * const szApplication,
	IN const char * const szLabel
) {
	CK_OBJECT_HANDLE handle = PKCS11H_INVALID_OBJECT_HANDLE;
	CK_RV rv = CKR_OK;

	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;
	PKCS11H_BOOL fMutexLocked = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (token_id!=NULL);
	PKCS11H_ASSERT (szApplication!=NULL);
	PKCS11H_ASSERT (szLabel!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_del entry token_id=%p, szApplication='%s', szLabel='%s'",
		(void *)token_id,
		szApplication,
		szLabel
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_getSessionByTokenId (
			token_id,
			&session
		);
	}

	while (rv == CKR_OK && !fOpSuccess) {

		if (rv == CKR_OK) {
			rv = _pkcs11h_validateSession (session);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_data_getObject (
				session,
				szApplication,
				szLabel,
				&handle
			);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		if (rv == CKR_OK) {
			rv = session->provider->f->C_DestroyObject (
				session->hSession,
				handle
			);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&session->mutexSession);
			fMutexLocked = FALSE;
		}
#endif

		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Remove data object failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				fLoginRetry = TRUE;
				rv = _pkcs11h_login (
					session,
					fPublic,
					FALSE,
					(
						PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
						PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
					)
				);
			}
		}
	}

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_del return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)
/*======================================================================*
 * CERTIFICATE INTERFACE
 *======================================================================*/

static
void
_pkcs11h_isBetterCertificate_getExpiration (
	IN const unsigned char * const pCertificate,
	IN const size_t nCertificateSize,
	OUT char * const szNotBefore,
	IN const int nNotBeforeSize
) {
	/*
	 * This function compare the notBefore
	 * and select the most recent certificate
	 * it does not deal with timezones...
	 * When openssl will have ASN1_TIME compare function
	 * it should be used.
	 */

	X509 *x509 = NULL;

	PKCS11H_ASSERT (pCertificate!=NULL);
	PKCS11H_ASSERT (szNotBefore!=NULL);
	PKCS11H_ASSERT (nNotBeforeSize>0);

	szNotBefore[0] = '\0';

	x509 = X509_new ();

	if (x509 != NULL) {
		pkcs11_openssl_d2i_t d2i = (pkcs11_openssl_d2i_t)pCertificate;

		if (
			d2i_X509 (&x509, &d2i, nCertificateSize)
		) {
			ASN1_TIME *notBefore = X509_get_notBefore (x509);
			ASN1_TIME *notAfter = X509_get_notAfter (x509);

			if (
				notBefore != NULL &&
				X509_cmp_current_time (notBefore) <= 0 &&
				X509_cmp_current_time (notAfter) >= 0 &&
				notBefore->length < nNotBeforeSize - 1
			) {
				memmove (szNotBefore, notBefore->data, notBefore->length);
				szNotBefore[notBefore->length] = '\0';
			}
		}
	}

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}
}

static
PKCS11H_BOOL
_pkcs11h_isBetterCertificate (
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

	PKCS11H_BOOL fBetter = FALSE;

	/*PKCS11H_ASSERT (pCurrent!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (pNew!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_isBetterCertificate entry pCurrent=%p, nCurrentSize=%u, pNew=%p, nNewSize=%u",
		pCurrent,
		nCurrentSize,
		pNew,
		nNewSize
	);

	/*
	 * First certificae
	 * always select
	 */
	if (nCurrentSize == 0 || pCurrent == NULL) {
		fBetter = TRUE;
	}
	else {
		char szNotBeforeCurrent[1024], szNotBeforeNew[1024];

		_pkcs11h_isBetterCertificate_getExpiration (
			pCurrent,
			nCurrentSize,
			szNotBeforeCurrent,
			sizeof (szNotBeforeCurrent)
		);
		_pkcs11h_isBetterCertificate_getExpiration (
			pNew,
			nNewSize,
			szNotBeforeNew,
			sizeof (szNotBeforeNew)
		);

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: _pkcs11h_isBetterCertificate szNotBeforeCurrent='%s', szNotBeforeNew='%s'",
			szNotBeforeCurrent,
			szNotBeforeNew
		);

		fBetter = strcmp (szNotBeforeCurrent, szNotBeforeNew) < 0;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_isBetterCertificate return fBetter=%d",
		fBetter ? 1 : 0
	);
	
	return fBetter;
}

static
CK_RV
_pkcs11h_newCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_newCertificateId entry p_certificate_id=%p",
		(void *)p_certificate_id
	);

	*p_certificate_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_malloc ((void *)p_certificate_id, sizeof (struct pkcs11h_certificate_id_s));
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_newCertificateId return rv=%ld-'%s', *p_certificate_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_loadCertificate (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{CKA_ID, NULL, 0}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (certificate->id!=NULL);
	
	/* Must be after assert */
	cert_filter[1].pValue = certificate->id->attrCKA_ID;
	cert_filter[1].ulValueLen = certificate->id->attrCKA_ID_size;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_loadCertificate entry certificate=%p",
		(void *)certificate
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (certificate->session);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&certificate->mutexCertificate)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_findObjects (
			certificate->session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_VALUE, NULL, 0}
		};

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_getObjectAttributes (
				certificate->session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			)) == CKR_OK
		) {
			if (
				_pkcs11h_isBetterCertificate (
					certificate->id->certificate_blob,
					certificate->id->certificate_blob_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				)
			) {
				if (certificate->id->certificate_blob != NULL) {
					_pkcs11h_free ((void *)&certificate->id->certificate_blob);
				}

				rv = _pkcs11h_dupmem (
					(void*)&certificate->id->certificate_blob,
					&certificate->id->certificate_blob_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				);
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				certificate->session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
	if (
		rv == CKR_OK &&
		certificate->id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_free ((void *)&objects);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&certificate->mutexCertificate);
		fMutexLocked = FALSE;
	}
#endif

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_loadCertificate return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_updateCertificateIdDescription (
	IN OUT pkcs11h_certificate_id_t certificate_id
) {
	static const char * szSeparator = " on ";
	static const char * szUnknown = "UNKNOWN";
	X509 *x509 = NULL;
	pkcs11_openssl_d2i_t d2i1;

	PKCS11H_ASSERT (certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_updateCertificateIdDescription entry certificate_id=%p",
		(void *)certificate_id
	);

	x509 = X509_new ();

	d2i1 = (pkcs11_openssl_d2i_t)certificate_id->certificate_blob;
	if (d2i_X509 (&x509, &d2i1, certificate_id->certificate_blob_size)) {
		X509_NAME_oneline (
			X509_get_subject_name (x509),
			certificate_id->displayName,
			sizeof (certificate_id->displayName)
		);
	}
	else {
		strncpy (
			certificate_id->displayName,
			szUnknown,
			sizeof (certificate_id->displayName)-1
		);
	}

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}

	/*
	 * Try to avoid using snprintf,
	 * may be unavailable
	 */
	strncat (
		certificate_id->displayName,
		szSeparator,
		sizeof (certificate_id->displayName)-1-strlen (certificate_id->displayName)
	);
	strncat (
		certificate_id->displayName,
		certificate_id->token_id->label,
		sizeof (certificate_id->displayName)-1-strlen (certificate_id->displayName)
	);
	certificate_id->displayName[sizeof (certificate_id->displayName) - 1] = '\0';

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_updateCertificateIdDescription return displayName=%s",
		certificate_id->displayName
	);

	return CKR_OK;
}

static
CK_RV
_pkcs11h_ensureCertificateBlob (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;

	CK_RV rv = CKR_OK;
	
	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_ensureCertificateBlob entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&certificate->mutexCertificate)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (certificate->id->certificate_blob == NULL) {
		fOpSuccess = FALSE;
		fLoginRetry = FALSE;
		while (rv == CKR_OK && !fOpSuccess) {
			if (rv == CKR_OK) {
				rv = _pkcs11h_loadCertificate (certificate);
			}

			if (rv == CKR_OK) {
				fOpSuccess = TRUE;
			}
			else {
				if (!fLoginRetry) {
					fLoginRetry = TRUE;
					rv = _pkcs11h_resetCertificateSession (
						certificate,
						TRUE,
						(
							PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
							PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
						)
					);
				}
			}
		}
	}
	
	if (
		rv == CKR_OK &&
		certificate->id->certificate_blob == NULL
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	if (rv == CKR_OK) {
		_pkcs11h_updateCertificateIdDescription (certificate->id);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&certificate->mutexCertificate);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_ensureCertificateBlob return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_getCertificateKeyAttributes (
	IN const pkcs11h_certificate_t certificate
) {
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;

	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getCertificateKeyAttributes entry certificate=%p",
		(void *)certificate
	);

	certificate->maskSignMode = 0;

	while (rv == CKR_OK && !fOpSuccess) {
#if defined(ENABLE_PKCS11H_THREADING)
		PKCS11H_BOOL fMutexLocked = FALSE;
#endif
		CK_ATTRIBUTE key_attrs[] = {
			{CKA_SIGN, NULL, 0},
			{CKA_SIGN_RECOVER, NULL, 0}
		};

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&certificate->mutexCertificate)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		/*
		 * Don't try invalid object
		 */
		if (
			rv == CKR_OK &&
			certificate->hKey == PKCS11H_INVALID_OBJECT_HANDLE
		) {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}

		if (rv == CKR_OK) {
			if (certificate->session->provider->maskSignMode != 0) {
				certificate->maskSignMode = certificate->session->provider->maskSignMode;
				fOpSuccess = TRUE;
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Key attributes enforced by provider (%08x)",
					certificate->maskSignMode
				);
			}
		}

		if (rv == CKR_OK && !fOpSuccess) {
			rv = _pkcs11h_getObjectAttributes (
				certificate->session,
				certificate->hKey,
				key_attrs,
				sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (rv == CKR_OK && !fOpSuccess) {
			CK_BBOOL *key_attrs_sign = (CK_BBOOL *)key_attrs[0].pValue;
			CK_BBOOL *key_attrs_sign_recover = (CK_BBOOL *)key_attrs[1].pValue;

			if (key_attrs_sign != NULL && *key_attrs_sign != CK_FALSE) {
				certificate->maskSignMode |= PKCS11H_SIGNMODE_MASK_SIGN;
			}
			if (key_attrs_sign_recover != NULL && *key_attrs_sign_recover != CK_FALSE) {
				certificate->maskSignMode |= PKCS11H_SIGNMODE_MASK_RECOVER;
			}
			if (certificate->maskSignMode == 0) {
				rv = CKR_KEY_TYPE_INCONSISTENT;
			}
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Key attributes loaded (%08x)",
				certificate->maskSignMode
			);
		}

		_pkcs11h_freeObjectAttributes (
			key_attrs,
			sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
		);

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&certificate->mutexCertificate);
			fMutexLocked = FALSE;
		}
#endif
	
		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get private key attributes failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_resetCertificateSession (
					certificate,
					FALSE,
					(
						PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
						PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
					)
				);

				fLoginRetry = TRUE;
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_getCertificateKeyAttributes return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_validateCertificateSession (
	IN const pkcs11h_certificate_t certificate
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_validateCertificateSession entry certificate=%p",
		(void *)certificate
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (certificate->session);
	}

	if (rv == CKR_OK) {
		if (certificate->hKey == PKCS11H_INVALID_OBJECT_HANDLE) {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_validateCertificateSession return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
_pkcs11h_resetCertificateSession (
	IN const pkcs11h_certificate_t certificate,
	IN const PKCS11H_BOOL fPublicOnly,
	IN const unsigned maskPrompt
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	PKCS11H_BOOL fKeyValid = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (certificate!=NULL);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_resetCertificateSession entry certificate=%p, fPublicOnly=%d, maskPrompt=%08x",
		(void *)certificate,
		fPublicOnly ? 1 : 0,
		maskPrompt
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&certificate->mutexCertificate)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (
		!fKeyValid &&
		rv == CKR_OK &&
		certificate->session == NULL &&
		(rv = _pkcs11h_getSessionByTokenId (certificate->id->token_id, &certificate->session)) == CKR_OK
	) {
		if (certificate->nPINCachePeriod != PKCS11H_PIN_CACHE_INFINITE) {
			if (certificate->session->nPINCachePeriod != PKCS11H_PIN_CACHE_INFINITE) {
				if (certificate->session->nPINCachePeriod > certificate->nPINCachePeriod) {
					certificate->session->timePINExpire = (
						certificate->session->timePINExpire -
						(time_t)certificate->session->nPINCachePeriod +
						(time_t)certificate->nPINCachePeriod
					);
					certificate->session->nPINCachePeriod = certificate->nPINCachePeriod;
				}
			}
			else {
				certificate->session->timePINExpire = (
					PKCS11H_TIME (NULL) +
					(time_t)certificate->nPINCachePeriod
				);
				certificate->session->nPINCachePeriod = certificate->nPINCachePeriod;
			}
		}	
	}

	/*
	 * First, if session seems to be valid
	 * and key handle is invalid (hard-set),
	 * try to fetch key handle,
	 * maybe the token is already logged in
	 */
	if (rv == CKR_OK) {
		if (
			certificate->session->hSession != PKCS11H_INVALID_SESSION_HANDLE && 
			certificate->hKey == PKCS11H_INVALID_OBJECT_HANDLE &&
			!fPublicOnly
		) {
			if (
				(rv = _pkcs11h_getObjectById (
					certificate->session,
					CKO_PRIVATE_KEY,
					certificate->id->attrCKA_ID,
					certificate->id->attrCKA_ID_size,
					&certificate->hKey
				)) == CKR_OK
			) {
				fKeyValid = TRUE;
			}
			else {
				/*
				 * Ignore error
				 */
				rv = CKR_OK;
				certificate->hKey = PKCS11H_INVALID_OBJECT_HANDLE;
			}
		}
	}

	if (
		!fKeyValid &&
		rv == CKR_OK &&
		(rv = _pkcs11h_login (
			certificate->session,
			fPublicOnly,
			TRUE,
			maskPrompt
		)) == CKR_OK
	) {
		rv = _pkcs11h_updateCertificateIdDescription (certificate->id);
	}

	if (
		!fKeyValid &&
		rv == CKR_OK &&
		!fPublicOnly &&
		(rv = _pkcs11h_getObjectById (
			certificate->session,
			CKO_PRIVATE_KEY,
			certificate->id->attrCKA_ID,
			certificate->id->attrCKA_ID_size,
			&certificate->hKey
		)) == CKR_OK
	) {
		fKeyValid = TRUE;
	}

	if (
		rv == CKR_OK &&
		!fPublicOnly &&
		!fKeyValid
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&certificate->mutexCertificate);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_resetCertificateSession return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_certificate_private_op (
	IN const pkcs11h_certificate_t certificate,
	IN const enum _pkcs11h_private_op_e op,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_MECHANISM mech = {
		mech_type, NULL, 0
	};
	
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL fLoginRetry = FALSE;
	PKCS11H_BOOL fOpSuccess = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_private_op entry certificate=%p, op=%d, mech_type=%ld, source=%p, source_size=%u, target=%p, p_target_size=%p",
		(void *)certificate,
		op,
		mech_type,
		source,
		source_size,
		target,
		(void *)p_target_size
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	while (rv == CKR_OK && !fOpSuccess) {
#if defined(ENABLE_PKCS11H_THREADING)
		PKCS11H_BOOL fMutexLocked = FALSE;
#endif

		if (rv == CKR_OK && !certificate->fOperationActive) {
			rv = _pkcs11h_validateCertificateSession (certificate);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&certificate->session->mutexSession)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		if (rv == CKR_OK && !certificate->fOperationActive) {
			switch (op) {
				case _pkcs11h_private_op_sign:
					rv = certificate->session->provider->f->C_SignInit (
						certificate->session->hSession,
						&mech,
						certificate->hKey
					);
				break;
				case _pkcs11h_private_op_sign_recover:
					rv = certificate->session->provider->f->C_SignRecoverInit (
						certificate->session->hSession,
						&mech,
						certificate->hKey
					);
				break;
				case _pkcs11h_private_op_decrypt:
					rv = certificate->session->provider->f->C_DecryptInit (
						certificate->session->hSession,
						&mech,
						certificate->hKey
					);
				break;
				default:
					rv = CKR_ARGUMENTS_BAD;
				break;
			}
		}

		if (rv == CKR_OK) {
			CK_ULONG size = *p_target_size;

			switch (op) {
				case _pkcs11h_private_op_sign:
					rv = certificate->session->provider->f->C_Sign (
						certificate->session->hSession,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				case _pkcs11h_private_op_sign_recover:
					rv = certificate->session->provider->f->C_SignRecover (
						certificate->session->hSession,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				case _pkcs11h_private_op_decrypt:
					rv = certificate->session->provider->f->C_Decrypt (
						certificate->session->hSession,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				default:
					rv = CKR_ARGUMENTS_BAD;
				break;
			}

			*p_target_size = size;
		}
		
		if (
			target == NULL &&
			(
				rv == CKR_BUFFER_TOO_SMALL ||
				rv == CKR_OK
			)
		) {
			certificate->fOperationActive = TRUE;
			rv = CKR_OK;
		}
		else {
			certificate->fOperationActive = FALSE;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&certificate->session->mutexSession);
			fMutexLocked = FALSE;
		}
#endif

		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			/*
			 * OpenSC workaround
			 * It still allows C_FindObjectsInit when
			 * token is removed/inserted but fails
			 * private key operation.
			 * So we force logout.
			 * bug#108 at OpenSC trac
			 */
			if (fLoginRetry && rv == CKR_DEVICE_REMOVED) {
				fLoginRetry = FALSE;
				_pkcs11h_logout (certificate->session);
			}

			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Private key operation failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				fLoginRetry = TRUE;
				rv = _pkcs11h_resetCertificateSession (
					certificate,
					FALSE,
					(
						PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
						PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
					)
				);
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_private_op return rv=%ld-'%s', *p_target_size=%d",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);
	
	return rv;
}

CK_RV
pkcs11h_freeCertificateId (
	IN pkcs11h_certificate_id_t certificate_id
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeCertificateId entry certificate_id=%p",
		(void *)certificate_id
	);

	if (certificate_id->attrCKA_ID != NULL) {
		_pkcs11h_free ((void *)&certificate_id->attrCKA_ID);
	}
	if (certificate_id->certificate_blob != NULL) {
		_pkcs11h_free ((void *)&certificate_id->certificate_blob);
	}
	if (certificate_id->token_id != NULL) {
		pkcs11h_freeTokenId (certificate_id->token_id);
		certificate_id->token_id = NULL;
	}
	_pkcs11h_free ((void *)&certificate_id);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeCertificateId return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_duplicateCertificateId (
	OUT pkcs11h_certificate_id_t * const to,
	IN const pkcs11h_certificate_id_t from
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (to!=NULL);
	PKCS11H_ASSERT (from!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_duplicateCertificateId entry to=%p form=%p",
		(void *)to,
		(void *)from
	);

	*to = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_dupmem (
			(void*)to,
			NULL,
			from,
			sizeof (struct pkcs11h_certificate_id_s)
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_dupmem (
			(void*)&(*to)->token_id,
			NULL,
			from->token_id,
			sizeof (struct pkcs11h_token_id_s)
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_dupmem (
			(void*)&(*to)->attrCKA_ID,
			&(*to)->attrCKA_ID_size,
			from->attrCKA_ID,
			from->attrCKA_ID_size
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_dupmem (
			(void*)&(*to)->certificate_blob,
			&(*to)->certificate_blob_size,
			from->certificate_blob,
			from->certificate_blob_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_duplicateCertificateId return rv=%ld-'%s', *to=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*to
	);
	
	return rv;
}

CK_RV
pkcs11h_freeCertificate (
	IN pkcs11h_certificate_t certificate
) {
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeCertificate entry certificate=%p",
		(void *)certificate
	);

	if (certificate != NULL) {
		if (certificate->session != NULL) {
			_pkcs11h_releaseSession (certificate->session);
		}
		pkcs11h_freeCertificateId (certificate->id);
		certificate->id = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_mutexFree (&certificate->mutexCertificate);
#endif

		_pkcs11h_free ((void *)&certificate);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeCertificate return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_certificate_sign (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_sign entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, p_target_size=%p",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		(void *)p_target_size
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_private_op (
			certificate,
			_pkcs11h_private_op_sign,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_sign return rv=%ld-'%s', *p_target_size=%d",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_signRecover (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signRecover entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, p_target_size=%p",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		(void *)p_target_size
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_private_op (
			certificate,
			_pkcs11h_private_op_sign_recover,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signRecover return rv=%ld-'%s', *p_target_size=%d",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_signAny (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL fSigned = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signAny entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, p_target_size=%p",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		(void *)p_target_size
	);

	if (
		rv == CKR_OK &&
		certificate->maskSignMode == 0
	) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Getting key attributes"
		);
		rv = _pkcs11h_getCertificateKeyAttributes (certificate);
	}

	if (
		rv == CKR_OK &&
		!fSigned &&
		(certificate->maskSignMode & PKCS11H_SIGNMODE_MASK_SIGN) != 0
	) {
		rv = pkcs11h_certificate_sign (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			fSigned = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED
		) {
			certificate->maskSignMode &= ~PKCS11H_SIGNMODE_MASK_SIGN;
			rv = CKR_OK;
		}
	}
	
	if (
		rv == CKR_OK &&
		!fSigned &&
		(certificate->maskSignMode & PKCS11H_SIGNMODE_MASK_RECOVER) != 0
	) {
		rv = pkcs11h_certificate_signRecover (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			fSigned = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED
		) {
			certificate->maskSignMode &= ~PKCS11H_SIGNMODE_MASK_RECOVER;
			rv = CKR_OK;
		}
	}

	if (rv == CKR_OK && !fSigned) {
		rv = CKR_FUNCTION_FAILED;
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signAny return rv=%ld-'%s', *p_target_size=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_decrypt (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, p_target_size=%p",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		(void *)p_target_size
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_private_op (
			certificate,
			_pkcs11h_private_op_decrypt,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt return rv=%ld-'%s', *p_target_size=%d",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_create (
	IN const pkcs11h_certificate_id_t certificate_id,
	IN const int nPINCachePeriod,
	OUT pkcs11h_certificate_t * const p_certificate
) {
	pkcs11h_certificate_t certificate = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (p_certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_create entry certificate_id=%p, nPINCachePeriod=%d, p_certificate=%p",
		(void *)certificate_id,
		nPINCachePeriod,
		(void *)p_certificate
	);

	*p_certificate = NULL;

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_malloc ((void*)&certificate, sizeof (struct pkcs11h_certificate_s))) == CKR_OK
	) {
		certificate->hKey = PKCS11H_INVALID_OBJECT_HANDLE;
		certificate->nPINCachePeriod = nPINCachePeriod;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (rv == CKR_OK) {
		rv = _pkcs11h_mutexInit (&certificate->mutexCertificate);
	}
#endif

	if (rv == CKR_OK) {
		rv = pkcs11h_duplicateCertificateId (&certificate->id, certificate_id);
	}

	if (rv == CKR_OK) {
		*p_certificate = certificate;
		certificate = NULL;
	}

	if (certificate != NULL) {
#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_mutexFree (&certificate->mutexCertificate);
#endif
		_pkcs11h_free ((void *)&certificate);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_create return rv=%ld-'%s' *p_certificate=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_getCertificateId (
	IN const pkcs11h_certificate_t certificate,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateId entry certificate=%p, certificate_id=%p",
		(void *)certificate,
		(void *)p_certificate_id
	);

	if (rv == CKR_OK) {
		rv = pkcs11h_duplicateCertificateId (
			p_certificate_id,
			certificate->id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateId return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_certificate_getCertificateBlob (
	IN const pkcs11h_certificate_t certificate,
	OUT unsigned char * const certificate_blob,
	IN OUT size_t * const p_certificate_blob_size
) {
	size_t certifiate_blob_size_max = 0;

	CK_RV rv = CKR_OK;
	
	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);
	/*PKCS11H_ASSERT (certificate_blob!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (p_certificate_blob_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateBlob entry certificate=%p, certificate_blob=%p, p_certificate_blob_size=%p",
		(void *)certificate,
		certificate_blob,
		(void *)p_certificate_blob_size
	);

	certifiate_blob_size_max = *p_certificate_blob_size;
	*p_certificate_blob_size = 0;

	if (rv == CKR_OK) {
		rv = _pkcs11h_ensureCertificateBlob (certificate);
	}

	if (rv == CKR_OK) {
		*p_certificate_blob_size = certificate->id->certificate_blob_size;
	}

	if (certificate_blob != NULL) {
		if (
			rv == CKR_OK &&
			certifiate_blob_size_max < certificate->id->certificate_blob_size
		) {
			rv = CKR_BUFFER_TOO_SMALL;
		}
	
		if (rv == CKR_OK) {
			memmove (
				certificate_blob,
				certificate->id->certificate_blob,
				*p_certificate_blob_size
			);
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateBlob return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_certificate_ensureCertificateAccess (
	IN const pkcs11h_certificate_t certificate,
	IN const unsigned maskPrompt
) {
	PKCS11H_BOOL fValidCert = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureCertificateAccess entry certificate=%p, maskPrompt=%08x",
		(void *)certificate,
		maskPrompt
	);

	if (!fValidCert && rv == CKR_OK) {
		CK_OBJECT_HANDLE h = PKCS11H_INVALID_OBJECT_HANDLE;

		if (
			(rv = _pkcs11h_getObjectById (
				certificate->session,
				CKO_CERTIFICATE,
				certificate->id->attrCKA_ID,
				certificate->id->attrCKA_ID_size,
				&h
			)) == CKR_OK
		) {
			fValidCert = TRUE;
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot access existing object rv=%ld-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}
	}

	if (!fValidCert && rv == CKR_OK) {
		if (
			(rv = _pkcs11h_resetCertificateSession (
				certificate,
				TRUE,
				maskPrompt
			)) == CKR_OK
		) {
			fValidCert = TRUE;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureCertificateAccess return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_ensureKeyAccess (
	IN const pkcs11h_certificate_t certificate,
	IN const unsigned maskPrompt
) {
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL fValidKey = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureKeyAccess entry certificate=%p, maskPrompt=%08x",
		(void *)certificate,
		maskPrompt
	);

	if (!fValidKey && rv == CKR_OK) {
		if (
			(rv = _pkcs11h_getObjectById (
				certificate->session,
				CKO_PRIVATE_KEY,
				certificate->id->attrCKA_ID,
				certificate->id->attrCKA_ID_size,
				&certificate->hKey
			)) == CKR_OK
		) {
			fValidKey = TRUE;
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot access existing object rv=%ld-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
			certificate->hKey = PKCS11H_INVALID_OBJECT_HANDLE;
		}
	}

	if (!fValidKey && rv == CKR_OK) {
		if (
			(rv = _pkcs11h_resetCertificateSession (
				certificate,
				FALSE,
				maskPrompt
			)) == CKR_OK
		) {
			fValidKey = TRUE;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureKeyAccess return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_LOCATE)
/*======================================================================*
 * LOCATE INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_TOKEN) || defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotId (
	IN const char * const szSlot,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;
	char szReferenceName[sizeof (((pkcs11h_provider_t)NULL)->szReferenceName)];

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (szSlot!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotId entry szSlot='%s', p_token_id=%p",
		szSlot,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	if (rv == CKR_OK) {
		if (strchr (szSlot, ':') == NULL) {
			szReferenceName[0] = '\0';
			selected_slot = atol (szSlot);
		}
		else {
			char *p;

			strncpy (szReferenceName, szSlot, sizeof (szReferenceName));
			szReferenceName[sizeof (szReferenceName)-1] = '\0';

			p = strchr (szReferenceName, ':');

			*p = '\0';
			p++;
			selected_slot = atol (p);
		}
	}
	
	if (rv == CKR_OK) {
		current_provider=s_pkcs11h_data->providers;
		while (
			current_provider != NULL &&
			szReferenceName[0] != '\0' &&		/* So first provider will be selected */
			strcmp (current_provider->szReferenceName, szReferenceName)
		) {
			current_provider = current_provider->next;
		}
	
		if (
			current_provider == NULL ||
			(
				current_provider != NULL &&
				!current_provider->fEnabled
			)
		) {
			rv = CKR_SLOT_ID_INVALID;
		}
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotId return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotName (
	IN const char * const szName,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL fFound = FALSE;

	PKCS11H_ASSERT (szName!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotName entry szName='%s', p_token_id=%p",
		szName,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	current_provider = s_pkcs11h_data->providers;
	while (
		current_provider != NULL &&
		rv == CKR_OK &&
		!fFound
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->fEnabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK &&
				!fFound
			);
			slot_index++
		) {
			CK_SLOT_INFO info;

			if (
				(rv = current_provider->f->C_GetSlotInfo (
					slots[slot_index],
					&info
				)) == CKR_OK
			) {
				char szCurrentName[sizeof (info.slotDescription)+1];

				_pkcs11h_fixupFixedString (
					szCurrentName,
					(char *)info.slotDescription,
					sizeof (info.slotDescription)
				);

				if (!strcmp (szCurrentName, szName)) {
					fFound = TRUE;
					selected_slot = slots[slot_index];
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get slot information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_free ((void *)&slots);
			slots = NULL;
		}

		if (!fFound) {
			current_provider = current_provider->next;
		}
	}

	if (rv == CKR_OK && !fFound) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotName return rv=%ld-'%s' *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv; 
}

static
CK_RV
_pkcs11h_locate_getTokenIdByLabel (
	IN const char * const szLabel,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL fFound = FALSE;

	PKCS11H_ASSERT (szLabel!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdByLabel entry szLabel='%s', p_token_id=%p",
		szLabel,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	current_provider = s_pkcs11h_data->providers;
	while (
		current_provider != NULL &&
		rv == CKR_OK &&
		!fFound
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->fEnabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK &&
				!fFound
			);
			slot_index++
		) {
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (rv == CKR_OK) {
				char szCurrentLabel[sizeof (info.label)+1];
		
				_pkcs11h_fixupFixedString (
					szCurrentLabel,
					(char *)info.label,
					sizeof (info.label)
				);

				if (!strcmp (szCurrentLabel, szLabel)) {
					fFound = TRUE;
					selected_slot = slots[slot_index];
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_free ((void *)&slots);
			slots = NULL;
		}

		if (!fFound) {
			current_provider = current_provider->next;
		}
	}

	if (rv == CKR_OK && !fFound) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdByLabel return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

CK_RV
pkcs11h_locate_token (
	IN const char * const szSlotType,
	IN const char * const szSlot,
	OUT pkcs11h_token_id_t * const p_token_id
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif

	pkcs11h_token_id_t dummy_token_id = NULL;
	pkcs11h_token_id_t token_id = NULL;
	PKCS11H_BOOL fFound = FALSE;
	
	CK_RV rv = CKR_OK;

	unsigned nRetry = 0;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (szSlotType!=NULL);
	PKCS11H_ASSERT (szSlot!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locate_token entry szSlotType='%s', szSlot='%s', p_token_id=%p",
		szSlotType,
		szSlot,
		(void *)p_token_id
	);

	*p_token_id = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_newTokenId (&dummy_token_id)) == CKR_OK
	) {
		/*
		 * Temperary slot id
		 */
		strcpy (dummy_token_id->label, "SLOT(");
		strncat (dummy_token_id->label, szSlotType, sizeof (dummy_token_id->label)-1-strlen (dummy_token_id->label));
		strncat (dummy_token_id->label, "=", sizeof (dummy_token_id->label)-1-strlen (dummy_token_id->label));
		strncat (dummy_token_id->label, szSlot, sizeof (dummy_token_id->label)-1-strlen (dummy_token_id->label));
		strncat (dummy_token_id->label, ")", sizeof (dummy_token_id->label)-1-strlen (dummy_token_id->label));
		dummy_token_id->label[sizeof (dummy_token_id->label)-1] = 0;
	}

	while (rv == CKR_OK && !fFound) {
		if (!strcmp (szSlotType, "id")) {
			rv = _pkcs11h_locate_getTokenIdBySlotId (
				szSlot,
				&token_id
			);
		}
		else if (!strcmp (szSlotType, "name")) {
			rv = _pkcs11h_locate_getTokenIdBySlotName (
				szSlot,
				&token_id
			);
		}
		else if (!strcmp (szSlotType, "label")) {
			rv = _pkcs11h_locate_getTokenIdByLabel (
				szSlot,
				&token_id
			);
		}
		else {
			rv = CKR_ARGUMENTS_BAD;
		}

		if (rv == CKR_OK) {
			fFound = TRUE;
		}

		if (!fFound && rv != CKR_ARGUMENTS_BAD) {

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: pkcs11h_locate_token failed rv=%ld-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling token_prompt hook for '%s'",
				dummy_token_id->label
			);
	
			if (
				!s_pkcs11h_data->hooks.token_prompt (
					s_pkcs11h_data->hooks.token_prompt_data,
					dummy_token_id,
					nRetry++
				)
			) {
				rv = CKR_CANCEL;
			}

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: token_prompt returned %ld",
				rv
			);
		}
	}

	if (rv == CKR_OK && !fFound) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (rv == CKR_OK) {
		*p_token_id = token_id;
		token_id = NULL;
	}

	if (dummy_token_id != NULL) {
		pkcs11h_freeTokenId (dummy_token_id);
		dummy_token_id = NULL;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locate_token return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

#endif				/* ENABLE_PKCS11H_TOKEN || ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
void
_pkcs11h_locate_hexToBinary (
	OUT unsigned char * const target,
	IN const char * const szSource,
	IN OUT size_t * const p_target_size
) {
	size_t target_max_size;
	const char *p;
	char buf[3] = {'\0', '\0', '\0'};
	int i = 0;

	PKCS11H_ASSERT (szSource!=NULL);
	PKCS11H_ASSERT (target!=NULL);
	PKCS11H_ASSERT (p_target_size!=NULL);

	target_max_size = *p_target_size;
	p = szSource;
	*p_target_size = 0;

	while (*p != '\0' && *p_target_size < target_max_size) {
		if (isxdigit ((unsigned char)*p)) {
			buf[i%2] = *p;

			if ((i%2) == 1) {
				unsigned v;
				if (sscanf (buf, "%x", &v) != 1) {
					v = 0;
				}
				target[*p_target_size] = v & 0xff;
				(*p_target_size)++;
			}

			i++;
		}
		p++;
	}
}

static
CK_RV
_pkcs11h_locate_getCertificateIdByLabel (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const szLabel
) {
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{CKA_LABEL, (CK_BYTE_PTR)szLabel, strlen (szLabel)}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (szLabel!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdByLabel entry session=%p, certificate_id=%p, szLabel='%s'",
		(void *)session,
		(void *)certificate_id,
		szLabel
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_findObjects (
			session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_ID, NULL, 0},
			{CKA_VALUE, NULL, 0}
		};

		if (rv == CKR_OK) {
			rv = _pkcs11h_getObjectAttributes (
				session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (
			rv == CKR_OK &&
			_pkcs11h_isBetterCertificate (
				certificate_id->certificate_blob,
				certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			)
		) {
			if (certificate_id->attrCKA_ID != NULL) {
				_pkcs11h_free ((void *)&certificate_id->attrCKA_ID);
			}
			if (certificate_id->certificate_blob != NULL) {
				_pkcs11h_free ((void *)&certificate_id->certificate_blob);
			}
			rv = _pkcs11h_dupmem (
				(void *)&certificate_id->attrCKA_ID,
				&certificate_id->attrCKA_ID_size,
				attrs[0].pValue,
				attrs[0].ulValueLen
			);
			rv = _pkcs11h_dupmem (
				(void *)&certificate_id->certificate_blob,
				&certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			);
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
	if (
		rv == CKR_OK &&
		certificate_id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_free ((void *)&objects);
	}

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdByLabel return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_locate_getCertificateIdBySubject (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const szSubject
) {
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (szSubject!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdBySubject entry session=%p, certificate_id=%p, szSubject=%s",
		(void *)session,
		(void *)certificate_id,
		szSubject
	);

	if (rv == CKR_OK) {
		rv = _pkcs11h_validateSession (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_findObjects (
			session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_ID, NULL, 0},
			{CKA_VALUE, NULL, 0}
		};
		char szCurrentSubject[1024];
		szCurrentSubject[0] = '\0';

		if (rv == CKR_OK) {
			rv = _pkcs11h_getObjectAttributes (
				session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (rv == CKR_OK) {
			X509 *x509 = NULL;
			pkcs11_openssl_d2i_t d2i1;

			x509 = X509_new ();

			d2i1 = (pkcs11_openssl_d2i_t)attrs[1].pValue;
			if (d2i_X509 (&x509, &d2i1, attrs[1].ulValueLen)) {
				X509_NAME_oneline (
					X509_get_subject_name (x509),
					szCurrentSubject,
					sizeof (szCurrentSubject)
				);
				szCurrentSubject[sizeof (szCurrentSubject) - 1] = '\0';
			}

			if (x509 != NULL) {
				X509_free (x509);
				x509 = NULL;
			}
		}

		if (
			rv == CKR_OK &&
			!strcmp (szSubject, szCurrentSubject) &&
			_pkcs11h_isBetterCertificate (
				certificate_id->certificate_blob,
				certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			)
		) {
			if (certificate_id->attrCKA_ID != NULL) {
				_pkcs11h_free ((void *)&certificate_id->attrCKA_ID);
			}
			if (certificate_id->certificate_blob != NULL) {
				_pkcs11h_free ((void *)&certificate_id->certificate_blob);
			}
			rv = _pkcs11h_dupmem (
				(void *)&certificate_id->attrCKA_ID,
				&certificate_id->attrCKA_ID_size,
				attrs[0].pValue,
				attrs[0].ulValueLen
			);
			rv = _pkcs11h_dupmem (
				(void *)&certificate_id->certificate_blob,
				&certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			);
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
	if (
		rv == CKR_OK &&
		certificate_id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_free ((void *)&objects);
	}

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdBySubject return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_locate_certificate (
	IN const char * const szSlotType,
	IN const char * const szSlot,
	IN const char * const szIdType,
	IN const char * const szId,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;
	
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (szSlotType!=NULL);
	PKCS11H_ASSERT (szSlot!=NULL);
	PKCS11H_ASSERT (szIdType!=NULL);
	PKCS11H_ASSERT (szId!=NULL);
	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locateCertificate entry szSlotType='%s', szSlot='%s', szIdType='%s', szId='%s', p_certificate_id=%p",
		szSlotType,
		szSlot,
		szIdType,
		szId,
		(void *)p_certificate_id
	);

	*p_certificate_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_newCertificateId (&certificate_id);
	}

	if (rv == CKR_OK) {
		rv = pkcs11h_locate_token (
			szSlotType,
			szSlot,
			&certificate_id->token_id
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_getSessionByTokenId (
			certificate_id->token_id,
			&session
		);
	}

	while (rv == CKR_OK && !fOpSuccess) {
#if defined(ENABLE_PKCS11H_THREADING)
		PKCS11H_BOOL fMutexLocked = FALSE;
#endif

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		if (!strcmp (szIdType, "id")) {
			certificate_id->attrCKA_ID_size = strlen (szId)/2;

			if (certificate_id->attrCKA_ID_size == 0) {
				rv = CKR_FUNCTION_FAILED;
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_malloc (
					(void*)&certificate_id->attrCKA_ID,
					certificate_id->attrCKA_ID_size
				)) == CKR_OK
			) {
				_pkcs11h_locate_hexToBinary (
					certificate_id->attrCKA_ID,
					szId,
					&certificate_id->attrCKA_ID_size
				);
			}
		}
		else if (!strcmp (szIdType, "label")) {
			rv = _pkcs11h_locate_getCertificateIdByLabel (
				session,
				certificate_id,
				szId
			);
		}
		else if (!strcmp (szIdType, "subject")) {
			rv = _pkcs11h_locate_getCertificateIdBySubject (
				session,
				certificate_id,
				szId
			);
		}
		else {
			rv = CKR_ARGUMENTS_BAD;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
			fMutexLocked = FALSE;
		}
#endif

		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get certificate failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_login (
					session,
					TRUE,
					TRUE,
					(
						PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
						PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
					)
				);

				fLoginRetry = TRUE;
			}
		}
	}

	if (rv == CKR_OK) {
		*p_certificate_id = certificate_id;
		certificate_id = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locateCertificate return rv=%ld-'%s' *p_certificate_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate_id
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_LOCATE */

#if defined(ENABLE_PKCS11H_ENUM)
/*======================================================================*
 * ENUM INTERFACE
 *======================================================================*/

#if defined(ENABLE_PKCS11H_TOKEN)

CK_RV
pkcs11h_freeTokenIdList (
	IN const pkcs11h_token_id_list_t token_id_list
) {
	pkcs11h_token_id_list_t _id = token_id_list;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	/*PKCS11H_ASSERT (token_id_list!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeTokenIdList entry token_id_list=%p",
		(void *)token_id_list
	);

	while (_id != NULL) {
		pkcs11h_token_id_list_t x = _id;
		_id = _id->next;
		if (x->token_id != NULL) {
			pkcs11h_freeTokenId (x->token_id);
		}
		x->next = NULL;
		_pkcs11h_free ((void *)&x);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeTokenIdList return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_enum_getTokenIds (
	IN const int method,
	OUT pkcs11h_token_id_list_t * const p_token_id_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif

	pkcs11h_token_id_list_t token_id_list = NULL;
	pkcs11h_provider_t current_provider;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (p_token_id_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_enum_getTokenIds entry p_token_id_list=%p",
		(void *)p_token_id_list
	);

	*p_token_id_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexGlobal)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	for (
		current_provider = s_pkcs11h_data->providers;
		(
			current_provider != NULL &&
			rv == CKR_OK
		);
		current_provider = current_provider->next
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->fEnabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK
			);
			slot_index++
		) {
			pkcs11h_token_id_list_t entry = NULL;
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = _pkcs11h_malloc ((void *)&entry, sizeof (struct pkcs11h_token_id_list_s));
			}

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_getTokenId (
					&info,
					&entry->token_id
				);
			}

			if (rv == CKR_OK) {
				entry->next = token_id_list;
				token_id_list = entry;
				entry = NULL;
			}

			if (entry != NULL) {
				pkcs11h_freeTokenIdList (entry);
				entry = NULL;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_free ((void *)&slots);
			slots = NULL;
		}
	}

	if (rv == CKR_OK && method == PKCS11H_ENUM_METHOD_CACHE) {
		pkcs11h_session_t session = NULL;

		for (
			session = s_pkcs11h_data->sessions;
			session != NULL && rv == CKR_OK;
			session = session->next
		) {
			pkcs11h_token_id_list_t entry = NULL;
			PKCS11H_BOOL fFound = FALSE;

			for (
				entry = token_id_list;
				entry != NULL && !fFound;
				entry = entry->next
			) {
				if (
					pkcs11h_sameTokenId (
						session->token_id,
						entry->token_id
					)
				) {
					fFound = TRUE;
				}
			}

			if (!fFound) {
				entry = NULL;

				if (rv == CKR_OK) {
					rv = _pkcs11h_malloc (
						(void *)&entry,
						sizeof (struct pkcs11h_token_id_list_s)
					);
				}

				if (rv == CKR_OK) {
					rv = pkcs11h_duplicateTokenId (
						&entry->token_id,
						session->token_id
					);
				}

				if (rv == CKR_OK) {
					entry->next = token_id_list;
					token_id_list = entry;
					entry = NULL;
				}

				if (entry != NULL) {
					if (entry->token_id != NULL) {
						pkcs11h_freeTokenId (entry->token_id);
					}
					_pkcs11h_free ((void *)&entry);
				}
			}
		}
	}

	if (rv == CKR_OK) {
		*p_token_id_list = token_id_list;
		token_id_list = NULL;
	}

	if (token_id_list != NULL) {
		pkcs11h_freeTokenIdList (token_id_list);
		token_id_list = NULL;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		rv = _pkcs11h_mutexRelease (&s_pkcs11h_data->mutexGlobal);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_enum_getTokenIds return rv=%ld-'%s', *p_token_id_list=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)p_token_id_list
	);
	
	return rv;
}

#endif

#if defined(ENABLE_PKCS11H_DATA)

CK_RV
pkcs11h_freeDataIdList (
	IN const pkcs11h_data_id_list_t data_id_list
) {
	pkcs11h_data_id_list_t _id = data_id_list;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	/*PKCS11H_ASSERT (data_id_list!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeDataIdList entry token_id_list=%p",
		(void *)data_id_list
	);

	while (_id != NULL) {
		pkcs11h_data_id_list_t x = _id;
		_id = _id->next;

		if (x->application != NULL) {
			_pkcs11h_free ((void *)&x->application);
		}
		if (x->label != NULL) {
			_pkcs11h_free ((void *)&x->label);
		}
		_pkcs11h_free ((void *)&x);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeDataIdList return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_enumDataObjects (
	IN const pkcs11h_token_id_t token_id,
	IN const PKCS11H_BOOL fPublic,
	OUT pkcs11h_data_id_list_t * const p_data_id_list
) {
	pkcs11h_session_t session = NULL;
	pkcs11h_data_id_list_t data_id_list = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (p_data_id_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_enumDataObjects entry p_data_id_list=%p",
		(void *)p_data_id_list
	);

	*p_data_id_list = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_getSessionByTokenId (
			token_id,
			&session
		);
	}

	while (rv == CKR_OK && !fOpSuccess) {
#if defined(ENABLE_PKCS11H_THREADING)
		PKCS11H_BOOL fMutexLocked = FALSE;
#endif

		CK_OBJECT_CLASS class = CKO_DATA;
		CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, (void *)&class, sizeof (class)}
		};
		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;

		CK_ULONG i;

		if (rv == CKR_OK) {
			rv = _pkcs11h_validateSession (session);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_mutexLock (&session->mutexSession)) == CKR_OK
		) {
			fMutexLocked = TRUE;
		}
#endif

		if (rv == CKR_OK) {
			rv = _pkcs11h_findObjects (
				session,
				filter,
				sizeof (filter) / sizeof (CK_ATTRIBUTE),
				&objects,
				&objects_found
			);
		}

		for (i = 0;rv == CKR_OK && i < objects_found;i++) {
			pkcs11h_data_id_list_t entry = NULL;

			CK_ATTRIBUTE attrs[] = {
				{CKA_APPLICATION, NULL, 0},
				{CKA_LABEL, NULL, 0}
			};

			if (rv == CKR_OK) {
				rv = _pkcs11h_getObjectAttributes (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				);
			}
			
			if (rv == CKR_OK) {
				rv = _pkcs11h_malloc (
					(void *)&entry,
					sizeof (struct pkcs11h_data_id_list_s)
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_malloc (
					(void *)&entry->application,
					attrs[0].ulValueLen+1
				)) == CKR_OK
			) {
				memmove (entry->application, attrs[0].pValue, attrs[0].ulValueLen);
				entry->application[attrs[0].ulValueLen] = '\0';
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_malloc (
					(void *)&entry->label,
					attrs[1].ulValueLen+1
				)) == CKR_OK
			) {
				memmove (entry->label, attrs[1].pValue, attrs[1].ulValueLen);
				entry->label[attrs[1].ulValueLen] = '\0';
			}

			if (rv == CKR_OK) {
				entry->next = data_id_list;
				data_id_list = entry;
				entry = NULL;
			}

			_pkcs11h_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			if (entry != NULL) {
				if (entry->application != NULL) {
					_pkcs11h_free ((void *)&entry->application);
				}
				if (entry->label != NULL) {
					_pkcs11h_free ((void *)&entry->label);
				}
				_pkcs11h_free ((void *)&entry);
			}
		}

		if (objects != NULL) {
			_pkcs11h_free ((void *)&objects);
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (fMutexLocked) {
			_pkcs11h_mutexRelease (&session->mutexSession);
			fMutexLocked = FALSE;
		}
#endif

		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Enumerate data objects failed rv=%ld-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				fLoginRetry = TRUE;
				rv = _pkcs11h_login (
					session,
					fPublic,
					TRUE,
					(
						PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT |
						PKCS11H_PROMPT_MAST_ALLOW_CARD_PROMPT 
					)
				);
			}
		}
	}

	if (rv == CKR_OK) {
		*p_data_id_list = data_id_list;
		data_id_list = NULL;
	}

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
		session = NULL;
	}

	if (data_id_list != NULL) {
		pkcs11h_freeDataIdList (data_id_list);
		data_id_list = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_data_id_list_t return rv=%ld-'%s', *p_data_id_list=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_data_id_list
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_DATA */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_enum_getSessionCertificates (
	IN const pkcs11h_session_t session
) {
	PKCS11H_BOOL fOpSuccess = FALSE;
	PKCS11H_BOOL fLoginRetry = FALSE;

	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_enum_getSessionCertificates entry session=%p",
		(void *)session
	);
	
	/* THREADS: NO NEED TO LOCK, GLOBAL CACHE IS LOCKED */

	while (rv == CKR_OK && !fOpSuccess) {
		CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
		CK_ATTRIBUTE cert_filter[] = {
			{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)}
		};

		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;

		CK_ULONG i;

		if (rv == CKR_OK) {
			rv = _pkcs11h_validateSession (session);
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_findObjects (
				session,
				cert_filter,
				sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
				&objects,
				&objects_found
			);
		}
			
		for (i=0;rv == CKR_OK && i < objects_found;i++) {
			pkcs11h_certificate_id_t certificate_id = NULL;
			pkcs11h_certificate_id_list_t new_element = NULL;
			
			CK_ATTRIBUTE attrs[] = {
				{CKA_ID, NULL, 0},
				{CKA_VALUE, NULL, 0}
			};

			if (rv == CKR_OK) {
				rv = _pkcs11h_getObjectAttributes (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_newCertificateId (&certificate_id)) == CKR_OK
			) {
				rv = pkcs11h_duplicateTokenId (
					&certificate_id->token_id,
					session->token_id
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_dupmem (
					(void*)&certificate_id->attrCKA_ID,
					&certificate_id->attrCKA_ID_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_dupmem (
					(void*)&certificate_id->certificate_blob,
					&certificate_id->certificate_blob_size,
					attrs[1].pValue,
					attrs[1].ulValueLen
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_updateCertificateIdDescription (certificate_id);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_malloc (
					(void *)&new_element,
					sizeof (struct pkcs11h_certificate_id_list_s)
				)) == CKR_OK
			) {
				new_element->next = session->cached_certs;
				new_element->certificate_id = certificate_id;
				certificate_id = NULL;

				session->cached_certs = new_element;
				new_element = NULL;
			}

			if (certificate_id != NULL) {
				pkcs11h_freeCertificateId (certificate_id);
				certificate_id = NULL;
			}

			if (new_element != NULL) {
				_pkcs11h_free ((void *)&new_element);
				new_element = NULL;
			}

			_pkcs11h_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
					session->provider->manufacturerID,
					objects[i],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (objects != NULL) {
			_pkcs11h_free ((void *)&objects);
		}

		if (rv == CKR_OK) {
			fOpSuccess = TRUE;
		}
		else {
			if (!fLoginRetry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get certificate attributes failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_login (
					session,
					TRUE,
					TRUE,
					PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT
				);

				fLoginRetry = TRUE;
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_enum_getSessionCertificates return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_enum_splitCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_all,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
	typedef struct info_s {
		struct info_s *next;
		pkcs11h_certificate_id_t e;
		X509 *x509;
		PKCS11H_BOOL fIsIssuer;
	} *info_t;

	pkcs11h_certificate_id_list_t cert_id_issuers_list = NULL;
	pkcs11h_certificate_id_list_t cert_id_end_list = NULL;

	info_t head = NULL;
	info_t info = NULL;

	CK_RV rv = CKR_OK;

	/*PKCS11H_ASSERT (cert_id_all!=NULL); NOT NEEDED */
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_splitCertificateIdList entry cert_id_all=%p, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		(void *)cert_id_all,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

	OpenSSL_add_all_digests ();

	if (rv == CKR_OK) {
		pkcs11h_certificate_id_list_t entry = NULL;

		for (
			entry = cert_id_all;
			entry != NULL && rv == CKR_OK;
			entry = entry->next
		) {
			info_t new_info = NULL;

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_malloc ((void *)&new_info, sizeof (struct info_s))) == CKR_OK &&
				entry->certificate_id->certificate_blob != NULL
			) {
				pkcs11_openssl_d2i_t d2i = (pkcs11_openssl_d2i_t)entry->certificate_id->certificate_blob;
				new_info->next = head;
				new_info->e = entry->certificate_id;
				new_info->x509 = X509_new ();
				if (
					new_info->x509 != NULL &&
					!d2i_X509 (
						&new_info->x509,
						&d2i,
						entry->certificate_id->certificate_blob_size
					)
				) {
					X509_free (new_info->x509);
					new_info->x509 = NULL;
				}
				head = new_info;
				new_info = NULL;
			}
		}

	}

	if (rv == CKR_OK) {
		for (
			info = head;
			info != NULL;
			info = info->next
		) {
			info_t info2 = NULL;
			for (
				info2 = head;
				info2 != NULL && !info->fIsIssuer;
				info2 = info2->next
			) {
				EVP_PKEY *pub = NULL;

				pub = X509_get_pubkey (info->x509);

				if (
					info != info2 &&
					info->x509 != NULL &&
					info2->x509 != NULL &&
/* Some people get this wrong		!X509_NAME_cmp (
						X509_get_subject_name (info->x509),
						X509_get_issuer_name (info2->x509)
					) && */
					X509_verify (info2->x509, pub) == 1
				) {
					info->fIsIssuer = TRUE;
				}

				if (pub != NULL) {
					EVP_PKEY_free (pub);
					pub = NULL;
				}
			}
		}
	}

	if (rv == CKR_OK) {
		for (
			info = head;
			info != NULL && rv == CKR_OK;
			info = info->next
		) {
			pkcs11h_certificate_id_list_t new_entry = NULL;

			if (rv == CKR_OK) {
				rv = _pkcs11h_malloc (
					(void *)&new_entry,
					sizeof (struct pkcs11h_certificate_id_list_s)
				);
			}

			if (
				rv == CKR_OK &&
				(rv = pkcs11h_duplicateCertificateId (
					&new_entry->certificate_id,
					info->e
				)) == CKR_OK
			) {
				/*
				 * Should not free base list
				 */
				info->e = NULL;
			}

			if (rv == CKR_OK) {
				if (info->fIsIssuer) {
					new_entry->next = cert_id_issuers_list;
					cert_id_issuers_list = new_entry;
					new_entry = NULL;
				}
				else {
					new_entry->next = cert_id_end_list;
					cert_id_end_list = new_entry;
					new_entry = NULL;
				}
			}

			if (new_entry != NULL) {
				if (new_entry->certificate_id != NULL) {
					pkcs11h_freeCertificateId (new_entry->certificate_id);
				}
				_pkcs11h_free ((void *)&new_entry);
			}
		}
	}

	if (rv == CKR_OK) {
		while (head != NULL) {
			info_t entry = head;
			head = head->next;

			if (entry->x509 != NULL) {
				X509_free (entry->x509);
				entry->x509 = NULL;
			}
			_pkcs11h_free ((void *)&entry);
		}
	}

	if (rv == CKR_OK && p_cert_id_issuers_list != NULL ) {
		*p_cert_id_issuers_list = cert_id_issuers_list;
		cert_id_issuers_list = NULL;
	}

	if (rv == CKR_OK) {
		*p_cert_id_end_list = cert_id_end_list;
		cert_id_end_list = NULL;
	}

	if (cert_id_issuers_list != NULL) {
		pkcs11h_freeCertificateIdList (cert_id_issuers_list);
	}

	if (cert_id_end_list != NULL) {
		pkcs11h_freeCertificateIdList (cert_id_end_list);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_splitCertificateIdList return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_freeCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_list
) {
	pkcs11h_certificate_id_list_t _id = cert_id_list;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	/*PKCS11H_ASSERT (cert_id_list!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeCertificateIdList entry cert_id_list=%p",
		(void *)cert_id_list
	);

	while (_id != NULL) {
		pkcs11h_certificate_id_list_t x = _id;
		_id = _id->next;
		if (x->certificate_id != NULL) {
			pkcs11h_freeCertificateId (x->certificate_id);
		}
		x->next = NULL;
		_pkcs11h_free ((void *)&x);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_freeCertificateIdList return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_enum_getTokenCertificateIds (
	IN const pkcs11h_token_id_t token_id,
	IN const int method,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	PKCS11H_ASSERT (token_id!=NULL);
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_enum_getTokenCertificateIds entry token_id=%p, method=%d, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		(void *)token_id,
		method,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexCache)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_getSessionByTokenId (
			token_id,
			&session
		)) == CKR_OK
	) {
		if (method == PKCS11H_ENUM_METHOD_RELOAD) {
			pkcs11h_freeCertificateIdList (session->cached_certs);
			session->cached_certs = NULL;
		}

		if (session->cached_certs == NULL) {
			rv = _pkcs11h_enum_getSessionCertificates (session);
		}
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_enum_splitCertificateIdList (
			session->cached_certs,
			p_cert_id_issuers_list,
			p_cert_id_end_list
		);
	}

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexCache);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_enum_getTokenCertificateIds return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_enum_getCertificateIds (
	IN const int method,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL fMutexLocked = FALSE;
#endif
	pkcs11h_certificate_id_list_t cert_id_list = NULL;
	pkcs11h_provider_t current_provider;
	pkcs11h_session_t current_session;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (s_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (s_pkcs11h_data->fInitialized);
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_enum_getCertificateIds entry method=%d, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		method,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mutexLock (&s_pkcs11h_data->mutexCache)) == CKR_OK
	) {
		fMutexLocked = TRUE;
	}
#endif

	for (
		current_session = s_pkcs11h_data->sessions;
		current_session != NULL;
		current_session = current_session->next
	) {
		current_session->fTouch = FALSE;
		if (method == PKCS11H_ENUM_METHOD_RELOAD) {
			pkcs11h_freeCertificateIdList (current_session->cached_certs);
			current_session->cached_certs = NULL;
		}
	}

	for (
		current_provider = s_pkcs11h_data->providers;
		(
			current_provider != NULL &&
			rv == CKR_OK
		);
		current_provider = current_provider->next
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->fEnabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK
			);
			slot_index++
		) {
			pkcs11h_session_t session = NULL;
			pkcs11h_token_id_t token_id = NULL;
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_getTokenId (
					&info,
					&token_id
				)) == CKR_OK &&
				(rv = _pkcs11h_getSessionByTokenId (
					token_id,
					&session
				)) == CKR_OK
			) {
				session->fTouch = TRUE;

				if (session->cached_certs == NULL) {
					rv = _pkcs11h_enum_getSessionCertificates (session);
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}

			if (session != NULL) {
				_pkcs11h_releaseSession (session);
				session = NULL;
			}

			if (token_id != NULL) {
				pkcs11h_freeTokenId (token_id);
				token_id = NULL;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_free ((void *)&slots);
			slots = NULL;
		}
	}

	for (
		current_session = s_pkcs11h_data->sessions;
		(
			current_session != NULL &&
			rv == CKR_OK
		);
		current_session = current_session->next
	) {
		if (
			method == PKCS11H_ENUM_METHOD_CACHE ||
			(
				(
					method == PKCS11H_ENUM_METHOD_RELOAD ||
					method == PKCS11H_ENUM_METHOD_CACHE_EXIST
				) &&
				current_session->fTouch
			)
		) {
			pkcs11h_certificate_id_list_t entry = NULL;

			for (
				entry = current_session->cached_certs;
				(
					entry != NULL &&
					rv == CKR_OK
				);
				entry = entry->next
			) {
				pkcs11h_certificate_id_list_t new_entry = NULL;

				if (
					rv == CKR_OK &&
					(rv = _pkcs11h_malloc (
						(void *)&new_entry,
						sizeof (struct pkcs11h_certificate_id_list_s)
					)) == CKR_OK &&
					(rv = pkcs11h_duplicateCertificateId (
						&new_entry->certificate_id,
						entry->certificate_id
					)) == CKR_OK
				) {
					new_entry->next = cert_id_list;
					cert_id_list = new_entry;
					new_entry = NULL;
				}

				if (new_entry != NULL) {
					new_entry->next = NULL;
					pkcs11h_freeCertificateIdList (new_entry);
					new_entry = NULL;
				}
			}
		}
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_enum_splitCertificateIdList (
			cert_id_list,
			p_cert_id_issuers_list,
			p_cert_id_end_list
		);
	}

	if (cert_id_list != NULL) {
		pkcs11h_freeCertificateIdList (cert_id_list);
		cert_id_list = NULL;
	}


#if defined(ENABLE_PKCS11H_THREADING)
	if (fMutexLocked) {
		_pkcs11h_mutexRelease (&s_pkcs11h_data->mutexCache);
		fMutexLocked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_enum_getCertificateIds return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_ENUM */

#if defined(ENABLE_PKCS11H_SLOTEVENT)
/*======================================================================*
 * SLOTEVENT INTERFACE
 *======================================================================*/

static
unsigned long
_pkcs11h_slotevent_checksum (
	IN const unsigned char * const p,
	IN const size_t s
) {
	unsigned long r = 0;
	size_t i;
	for (i=0;i<s;i++) {
		r += p[i];
	}
	return r;
}

static
void *
_pkcs11h_slotevent_provider (
	IN void *p
) {
	pkcs11h_provider_t provider = (pkcs11h_provider_t)p;
	CK_SLOT_ID slot;
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_provider provider='%s' entry",
		provider->manufacturerID
	);

	if (rv == CKR_OK && !provider->fEnabled) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
	}

	if (rv == CKR_OK) {

		if (provider->nSlotEventPollInterval == 0) {
			provider->nSlotEventPollInterval = PKCS11H_DEFAULT_SLOTEVENT_POLL;
		}

		/*
		 * If we cannot finalize, we cannot cause
		 * WaitForSlotEvent to terminate
		 */
		if (!provider->fShouldFinalize) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Setup slotevent provider='%s' mode hardset to poll",
				provider->manufacturerID
			);
			provider->nSlotEventMethod = PKCS11H_SLOTEVENT_METHOD_POLL;
		}

		if (
			provider->nSlotEventMethod == PKCS11H_SLOTEVENT_METHOD_AUTO ||
			provider->nSlotEventMethod == PKCS11H_SLOTEVENT_METHOD_TRIGGER
		) { 
			if (
				provider->f->C_WaitForSlotEvent (
					CKF_DONT_BLOCK,
					&slot,
					NULL_PTR
				) == CKR_FUNCTION_NOT_SUPPORTED
			) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Setup slotevent provider='%s' mode is poll",
					provider->manufacturerID
				);

				provider->nSlotEventMethod = PKCS11H_SLOTEVENT_METHOD_POLL;
			}
			else {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Setup slotevent provider='%s' mode is trigger",
					provider->manufacturerID
				);

				provider->nSlotEventMethod = PKCS11H_SLOTEVENT_METHOD_TRIGGER;
			}
		}
	}

	if (provider->nSlotEventMethod == PKCS11H_SLOTEVENT_METHOD_TRIGGER) {
		while (
			!s_pkcs11h_data->fSlotEventShouldTerminate &&
			provider->fEnabled &&
			rv == CKR_OK &&
			(rv = provider->f->C_WaitForSlotEvent (
				0,
				&slot,
				NULL_PTR
			)) == CKR_OK
		) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent provider='%s' event",
				provider->manufacturerID
			);

			_pkcs11h_condSignal (&s_pkcs11h_data->condSlotEvent);
		}
	}
	else {
		unsigned long ulLastChecksum = 0;
		PKCS11H_BOOL fFirstTime = TRUE;

		while (
			!s_pkcs11h_data->fSlotEventShouldTerminate &&
			provider->fEnabled &&
			rv == CKR_OK
		) {
			unsigned long ulCurrentChecksum = 0;

			CK_SLOT_ID_PTR slots = NULL;
			CK_ULONG slotnum;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent provider='%s' poll",
				provider->manufacturerID
			);

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_getSlotList (
					provider,
					TRUE,
					&slots,
					&slotnum
				)) == CKR_OK
			) {
				CK_ULONG i;
				
				for (i=0;i<slotnum;i++) {
					CK_TOKEN_INFO info;

					if (provider->f->C_GetTokenInfo (slots[i], &info) == CKR_OK) {
						ulCurrentChecksum += (
							_pkcs11h_slotevent_checksum (
								info.label,
								sizeof (info.label)
							) +
							_pkcs11h_slotevent_checksum (
								info.manufacturerID,
								sizeof (info.manufacturerID)
							) +
							_pkcs11h_slotevent_checksum (
								info.model,
								sizeof (info.model)
							) +
							_pkcs11h_slotevent_checksum (
								info.serialNumber,
								sizeof (info.serialNumber)
							)
						);
					}
				}
			}
			
			if (rv == CKR_OK) {
				if (fFirstTime) {
					fFirstTime = FALSE;
				}
				else {
					if (ulLastChecksum != ulCurrentChecksum) {
						PKCS11H_DEBUG (
							PKCS11H_LOG_DEBUG1,
							"PKCS#11: Slotevent provider='%s' event",
							provider->manufacturerID
						);

						_pkcs11h_condSignal (&s_pkcs11h_data->condSlotEvent);
					}
				}
				ulLastChecksum = ulCurrentChecksum;
			}

			if (slots != NULL) {
				_pkcs11h_free ((void *)&slots);
			}
			
			if (!s_pkcs11h_data->fSlotEventShouldTerminate) {
				_pkcs11h_sleep (provider->nSlotEventPollInterval);
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_provider provider='%s' return",
		provider->manufacturerID
	);

	return NULL;
}

static
void *
_pkcs11h_slotevent_manager (
	IN void *p
) {
	PKCS11H_BOOL fFirst = TRUE;

	(void)p;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_manager entry"
	);

	/*
	 * Trigger hook, so application may
	 * depend on initial slot change
	 */
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Calling slotevent hook"
	);
	s_pkcs11h_data->hooks.slotevent (s_pkcs11h_data->hooks.slotevent_data);

	while (
		fFirst ||	/* Must enter wait or mutex will never be free */
		!s_pkcs11h_data->fSlotEventShouldTerminate
	) {
		pkcs11h_provider_t current_provider;

		fFirst = FALSE;

		/*
		 * Start each provider thread
		 * if not already started.
		 * This is required in order to allow
		 * adding new providers.
		 */
		for (
			current_provider = s_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			if (!current_provider->fEnabled) {
				if (current_provider->threadSlotEvent == PKCS11H_THREAD_NULL) {
					_pkcs11h_threadStart (
						&current_provider->threadSlotEvent,
						_pkcs11h_slotevent_provider,
						current_provider
					);
				}
			}
			else {
				if (current_provider->threadSlotEvent != PKCS11H_THREAD_NULL) {
					_pkcs11h_threadJoin (&current_provider->threadSlotEvent);
				}
			}
		}

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: _pkcs11h_slotevent_manager waiting for slotevent"
		);
		_pkcs11h_condWait (&s_pkcs11h_data->condSlotEvent, PKCS11H_COND_INFINITE);

		if (s_pkcs11h_data->fSlotEventSkipEvent) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent skipping event"
			);
			s_pkcs11h_data->fSlotEventSkipEvent = FALSE;
		}
		else {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling slotevent hook"
			);
			s_pkcs11h_data->hooks.slotevent (s_pkcs11h_data->hooks.slotevent_data);
		}
	}

	{
		pkcs11h_provider_t current_provider;

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: _pkcs11h_slotevent_manager joining threads"
		);


		for (
			current_provider = s_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			if (current_provider->threadSlotEvent != PKCS11H_THREAD_NULL) {
				_pkcs11h_threadJoin (&current_provider->threadSlotEvent);
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_manager return"
	);

	return NULL;
}

static
CK_RV
_pkcs11h_slotevent_init () {
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_init entry"
	);

	if (!s_pkcs11h_data->fSlotEventInitialized) {
		if (rv == CKR_OK) {
			rv = _pkcs11h_condInit (&s_pkcs11h_data->condSlotEvent);
		}
		
		if (rv == CKR_OK) {
			rv = _pkcs11h_threadStart (
				&s_pkcs11h_data->threadSlotEvent,
				_pkcs11h_slotevent_manager,
				NULL
			);
		}
		
		if (rv == CKR_OK) {
			s_pkcs11h_data->fSlotEventInitialized = TRUE;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_init return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_slotevent_notify () {
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_notify entry"
	);

	if (s_pkcs11h_data->fSlotEventInitialized) {
		s_pkcs11h_data->fSlotEventSkipEvent = TRUE;
		_pkcs11h_condSignal (&s_pkcs11h_data->condSlotEvent);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_notify return"
	);

	return CKR_OK;
}

static
CK_RV
_pkcs11h_slotevent_terminate () {
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_terminate entry"
	);

	if (s_pkcs11h_data->fSlotEventInitialized) {
		s_pkcs11h_data->fSlotEventShouldTerminate = TRUE;

		_pkcs11h_slotevent_notify ();

		if (s_pkcs11h_data->threadSlotEvent != PKCS11H_THREAD_NULL) {
			_pkcs11h_threadJoin (&s_pkcs11h_data->threadSlotEvent);
		}

		_pkcs11h_condFree (&s_pkcs11h_data->condSlotEvent);
		s_pkcs11h_data->fSlotEventInitialized = FALSE;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_terminate return"
	);

	return CKR_OK;
}

#endif

#if defined(ENABLE_PKCS11H_OPENSSL)
/*======================================================================*
 * OPENSSL INTERFACE
 *======================================================================*/

static
pkcs11h_openssl_session_t
_pkcs11h_openssl_get_openssl_session (
	IN OUT const RSA *rsa
) {
	pkcs11h_openssl_session_t session;
		
	PKCS11H_ASSERT (rsa!=NULL);
#if OPENSSL_VERSION_NUMBER < 0x00907000L
	session = (pkcs11h_openssl_session_t)RSA_get_app_data ((RSA *)rsa);
#else
	session = (pkcs11h_openssl_session_t)RSA_get_app_data (rsa);
#endif
	PKCS11H_ASSERT (session!=NULL);

	return session;
}

static
pkcs11h_certificate_t
_pkcs11h_openssl_get_pkcs11h_certificate (
	IN OUT const RSA *rsa
) {
	pkcs11h_openssl_session_t session = _pkcs11h_openssl_get_openssl_session (rsa);
	
	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (session->certificate!=NULL);

	return session->certificate;
}

#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#else
static
int
_pkcs11h_openssl_dec (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#endif
	PKCS11H_ASSERT (from!=NULL);
	PKCS11H_ASSERT (to!=NULL);
	PKCS11H_ASSERT (rsa!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_dec entered - flen=%d, from=%p, to=%p, rsa=%p, padding=%d",
		flen,
		from,
		to,
		(void *)rsa,
		padding
	);

	PKCS11H_LOG (
		PKCS11H_LOG_ERROR,
		"PKCS#11: Private key decryption is not supported"
	);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_dec return"
	);

	return -1;
}

#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
_pkcs11h_openssl_sign (
	IN int type,
	IN unsigned char *m,
	IN unsigned int m_len,
	OUT unsigned char *sigret,
	OUT unsigned int *siglen,
	IN OUT RSA *rsa
) {
#else
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
#endif
	pkcs11h_certificate_t certificate = _pkcs11h_openssl_get_pkcs11h_certificate (rsa);
	CK_RV rv = CKR_OK;

	int myrsa_size = 0;
	
	unsigned char *enc_alloc = NULL;
	unsigned char *enc = NULL;
	int enc_len = 0;

	PKCS11H_ASSERT (m!=NULL);
	PKCS11H_ASSERT (sigret!=NULL);
	PKCS11H_ASSERT (siglen!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_sign entered - type=%d, m=%p, m_len=%u, signret=%p, signlen=%p, rsa=%p",
		type,
		m,
		m_len,
		sigret,
		(void *)siglen,
		(void *)rsa
	);

	if (rv == CKR_OK) {
		myrsa_size=RSA_size(rsa);
	}

	if (type == NID_md5_sha1) {
		if (rv == CKR_OK) {
			enc = (unsigned char *)m;
			enc_len = m_len;
		}
	}
	else {
		X509_SIG sig;
		ASN1_TYPE parameter;
		X509_ALGOR algor;
		ASN1_OCTET_STRING digest;

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_malloc ((void*)&enc, myrsa_size+1)) == CKR_OK
		) {
			enc_alloc = enc;
		}
		
		if (rv == CKR_OK) {
			sig.algor = &algor;
		}

		if (
			rv == CKR_OK &&
			(sig.algor->algorithm = OBJ_nid2obj (type)) == NULL
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
			parameter.type = V_ASN1_NULL;
			parameter.value.ptr = NULL;
	
			sig.algor->parameter = &parameter;

			sig.digest = &digest;
			sig.digest->data = (unsigned char *)m;
			sig.digest->length = m_len;
		}
	
		if (
			rv == CKR_OK &&
			(enc_len=i2d_X509_SIG (&sig, NULL)) < 0
		) {
			rv = CKR_FUNCTION_FAILED;
		}
	
		if (rv == CKR_OK) {
			unsigned char *p = enc;
			i2d_X509_SIG (&sig, &p);
		}
	}

	if (
		rv == CKR_OK &&
		enc_len > (myrsa_size-RSA_PKCS1_PADDING_SIZE)
	) {
		rv = CKR_KEY_SIZE_RANGE;
	}

	if (rv == CKR_OK) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Performing signature"
		);

		*siglen = myrsa_size;

		if (
			(rv = pkcs11h_certificate_signAny (
				certificate,
				CKM_RSA_PKCS,
				enc,
				enc_len,
				sigret,
				siglen
			)) != CKR_OK
		) {
			PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		}
	}

	if (enc_alloc != NULL) {
		_pkcs11h_free ((void *)&enc_alloc);
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_sign - return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK ? 1 : -1; 
}

static
int
_pkcs11h_openssl_finish (
	IN OUT RSA *rsa
) {
	pkcs11h_openssl_session_t openssl_session = _pkcs11h_openssl_get_openssl_session (rsa);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_finish - entered rsa=%p",
		(void *)rsa
	);

	RSA_set_app_data (rsa, NULL);
	
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

	pkcs11h_openssl_freeSession (openssl_session);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_finish - return"
	);
	
	return 1;
}

pkcs11h_openssl_session_t
pkcs11h_openssl_createSession (
	IN const pkcs11h_certificate_t certificate
) {
	pkcs11h_openssl_session_t openssl_session = NULL;
	PKCS11H_BOOL fOK = TRUE;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - entry"
	);

	if (
		fOK &&
		_pkcs11h_malloc (
			(void*)&openssl_session,
			sizeof (struct pkcs11h_openssl_session_s)) != CKR_OK
	) {
		fOK = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate memory");
	}

	if (fOK) {
		const RSA_METHOD *def = RSA_get_default_method();

		memmove (&openssl_session->smart_rsa, def, sizeof(RSA_METHOD));

		openssl_session->orig_finish = def->finish;

		openssl_session->smart_rsa.name = "pkcs11";
		openssl_session->smart_rsa.rsa_priv_dec = _pkcs11h_openssl_dec;
		openssl_session->smart_rsa.rsa_sign = _pkcs11h_openssl_sign;
		openssl_session->smart_rsa.finish = _pkcs11h_openssl_finish;
		openssl_session->smart_rsa.flags  = RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY;
		openssl_session->certificate = certificate;
		openssl_session->nReferenceCount = 1;
	}

	if (!fOK) {
		_pkcs11h_free ((void *)&openssl_session);
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - return openssl_session=%p",
		(void *)openssl_session
	);

	return openssl_session;
}

void
pkcs11h_openssl_freeSession (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	PKCS11H_ASSERT (openssl_session!=NULL);
	PKCS11H_ASSERT (openssl_session->nReferenceCount>0);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - entry openssl_session=%p, count=%d",
		(void *)openssl_session,
		openssl_session->nReferenceCount
	);

	openssl_session->nReferenceCount--;
	
	if (openssl_session->nReferenceCount == 0) {
		if (openssl_session->x509 != NULL) {
			X509_free (openssl_session->x509);
			openssl_session->x509 = NULL;
		}
		if (openssl_session->certificate != NULL) {
			pkcs11h_freeCertificate (openssl_session->certificate);
			openssl_session->certificate = NULL;
		}
		
		_pkcs11h_free ((void *)&openssl_session);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - return"
	);
}

RSA *
pkcs11h_openssl_getRSA (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	X509 *x509 = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pubkey = NULL;
	CK_RV rv = CKR_OK;

	pkcs11_openssl_d2i_t d2i1 = NULL;
	PKCS11H_BOOL fOK = TRUE;

	PKCS11H_ASSERT (openssl_session!=NULL);
	PKCS11H_ASSERT (!openssl_session->fInitialized);
	PKCS11H_ASSERT (openssl_session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getRSA - entry openssl_session=%p",
		(void *)openssl_session
	);

	if (
		fOK &&
		(x509 = X509_new ()) == NULL
	) {
		fOK = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Unable to allocate certificate object");
	}

	if (
		fOK &&
		(rv = _pkcs11h_ensureCertificateBlob (openssl_session->certificate)) != CKR_OK
	) {
		fOK = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot read X.509 certificate from token %ld-'%s'", rv, pkcs11h_getMessage (rv));
	}

	d2i1 = (pkcs11_openssl_d2i_t)openssl_session->certificate->id->certificate_blob;
	if (
		fOK &&
		!d2i_X509 (&x509, &d2i1, openssl_session->certificate->id->certificate_blob_size)
	) {
		fOK = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Unable to parse X.509 certificate");
	}

	if (
		fOK &&
		(pubkey = X509_get_pubkey (x509)) == NULL
	) {
		fOK = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get public key");
	}
	
	if (
		fOK &&
		pubkey->type != EVP_PKEY_RSA
	) {
		fOK = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Invalid public key algorithm");
	}

	if (
		fOK &&
		(rsa = EVP_PKEY_get1_RSA (pubkey)) == NULL
	) {
		fOK = FALSE;
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get RSA key");
	}

	if (fOK) {

		RSA_set_method (rsa, &openssl_session->smart_rsa);
		RSA_set_app_data (rsa, openssl_session);
		openssl_session->nReferenceCount++;
	}
	
#ifdef BROKEN_OPENSSL_ENGINE
	if (fOK) {
		if (!rsa->engine) {
			rsa->engine = ENGINE_get_default_RSA();
		}

		ENGINE_set_RSA(ENGINE_get_default_RSA(), &openssl_session->smart_rsa);
		PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: OpenSSL engine support is broken! Workaround enabled");
	}
#endif
		
	if (fOK) {
		/*
		 * dup x509 so that it won't hold RSA
		 */
		openssl_session->x509 = X509_dup (x509);
		rsa->flags |= RSA_FLAG_SIGN_VER;
		openssl_session->fInitialized = TRUE;
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
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getRSA - return rsa=%p",
		(void *)rsa
	);

	return rsa;
}

X509 *
pkcs11h_openssl_getX509 (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	X509 *x509 = NULL;
	
	PKCS11H_ASSERT (openssl_session!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - entry openssl_session=%p",
		(void *)openssl_session
	);

	if (openssl_session->x509 != NULL) {
		x509 = X509_dup (openssl_session->x509);
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - return x509=%p",
		(void *)x509
	);

	return x509;
}

#endif				/* ENABLE_PKCS11H_OPENSSL */

#if defined(ENABLE_PKCS11H_STANDALONE)
/*======================================================================*
 * STANDALONE INTERFACE
 *======================================================================*/

void
pkcs11h_standalone_dump_slots (
	IN const pkcs11h_output_print_t my_output,
	IN const void *pData,
	IN const char * const provider
) {
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t pkcs11h_provider;

	PKCS11H_ASSERT (my_output!=NULL);
	/*PKCS11H_ASSERT (pData) NOT NEEDED */
	PKCS11H_ASSERT (provider!=NULL);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot initialize interface %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			FALSE,
			(
				PKCS11H_SIGNMODE_MASK_SIGN |
				PKCS11H_SIGNMODE_MASK_RECOVER
			),
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			FALSE
		)) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = s_pkcs11h_data->providers;
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
				szManufacturerID,
				(char *)info.manufacturerID,
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
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;
		
		if (
			 _pkcs11h_getSlotList (
				pkcs11h_provider,
				CK_FALSE,
				&slots,
				&slotnum
			) != CKR_OK
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
				PKCS11H_PRM_SLOT_TYPE,
				PKCS11H_PRM_SLOT_ID
			);
			for (slot_index=0;slot_index < slotnum;slot_index++) {
				CK_SLOT_INFO info;
	
				if (
					(rv = pkcs11h_provider->f->C_GetSlotInfo (
						slots[slot_index],
						&info
					)) == CKR_OK
				) {
					char szCurrentName[sizeof (info.slotDescription)+1];
				
					_pkcs11h_fixupFixedString (
						szCurrentName,
						(char *)info.slotDescription,
						sizeof (info.slotDescription)
					);
	
					my_output (pData, "\t%lu - %s\n", slots[slot_index], szCurrentName);
				}
			}
		}

		if (slots != NULL) {
			_pkcs11h_free ((void *)&slots);
		}
	}
	
	pkcs11h_terminate ();
}

static
PKCS11H_BOOL
_pkcs11h_standalone_dump_objects_pin_prompt (
	IN const void *pData,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const szPIN,
	IN const size_t nMaxPIN
) {
	/*
	 * Don't lock card
	 */
	if (retry == 0) {
		strncpy (szPIN, (char *)pData, nMaxPIN);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

void
_pkcs11h_standalone_dump_objects_hex (
	IN const unsigned char * const p,
	IN const size_t p_size,
	OUT char * const sz,
	IN const size_t max,
	IN const char * const szLinePrefix
) {
	size_t j;

	sz[0] = '\0';

	for (j=0;j<p_size;j+=16) {
		char szLine[3*16+1];
		size_t k;

		szLine[0] = '\0';
		for (k=0;k<16 && j+k<p_size;k++) {
			sprintf (szLine+strlen (szLine), "%02x ", p[j+k]);
		}

		strncat (
			sz,
			szLinePrefix,
			max-1-strlen (sz)
		);
		strncat (
			sz,
			szLine,
			max-1-strlen (sz)
		);
		strncat (
			sz,
			"\n",
			max-1-strlen (sz)
		);
	}

	sz[max-1] = '\0';
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

	pkcs11h_provider_t pkcs11h_provider = NULL;
	pkcs11h_token_id_t token_id = NULL;
	pkcs11h_session_t session = NULL;

	PKCS11H_ASSERT (my_output!=NULL);
	/*PKCS11H_ASSERT (pData) NOT NEEDED */
	PKCS11H_ASSERT (provider!=NULL);
	PKCS11H_ASSERT (slot!=NULL);
	PKCS11H_ASSERT (pin!=NULL);

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
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			FALSE,
			(
				PKCS11H_SIGNMODE_MASK_SIGN |
				PKCS11H_SIGNMODE_MASK_RECOVER
			),
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			FALSE
		)) != CKR_OK
	) {
		my_output (pData, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = s_pkcs11h_data->providers;
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
			/* Ignore this error */
			rv = CKR_OK;
		}
		else {
			char szLabel[sizeof (info.label)+1];
			char szManufacturerID[sizeof (info.manufacturerID)+1];
			char szModel[sizeof (info.model)+1];
			char szSerialNumber[sizeof (info.serialNumber)+1];
			
			_pkcs11h_fixupFixedString (
				szLabel,
				(char *)info.label,
				sizeof (info.label)
			);
			_pkcs11h_fixupFixedString (
				szManufacturerID,
				(char *)info.manufacturerID,
				sizeof (info.manufacturerID)
			);
			_pkcs11h_fixupFixedString (
				szModel,
				(char *)info.model,
				sizeof (info.model)
			);
			_pkcs11h_fixupFixedString (
				szSerialNumber,
				(char *)info.serialNumber,
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
				PKCS11H_PRM_SLOT_TYPE,
				PKCS11H_PRM_SLOT_ID,
				szLabel
			);

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_getTokenId (
					&info,
					&token_id
				)) != CKR_OK
			) {
				my_output (pData, "PKCS#11: Cannot get token id for slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));		
				rv = CKR_OK;
			}
		}
	}

	if (token_id != NULL) {
		if (
			(rv = _pkcs11h_getSessionByTokenId (
				token_id,
				&session
			)) != CKR_OK
		) {
			my_output (pData, "PKCS#11: Cannot session for token '%s' %ld-'%s'\n", token_id->label, rv, pkcs11h_getMessage (rv));		
			rv = CKR_OK;
		}
	}

	if (session != NULL) {
		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;
		CK_ULONG i;

		if (
			(rv = _pkcs11h_login (
				session,
				FALSE,
				TRUE,
				PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT
			)) != CKR_OK
		) {
			my_output (pData, "PKCS#11: Cannot open session to token '%s' %ld-'%s'\n", session->token_id->label, rv, pkcs11h_getMessage (rv));
		}
	
		my_output (
			pData,
			(
				"The following objects are available for use with this token.\n"
				"Each object shown below may be used as a parameter to\n"
				"%s and %s options.\n"
				"\n"
			),
			PKCS11H_PRM_OBJ_TYPE,
			PKCS11H_PRM_OBJ_ID
		);

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_findObjects (
				session,
				NULL,
				0,
				&objects,
				&objects_found
			)) != CKR_OK
		) {
			my_output (pData, "PKCS#11: Cannot query objects for token '%s' %ld-'%s'\n", session->token_id->label, rv, pkcs11h_getMessage (rv));
		}
	
		for (i=0;rv == CKR_OK && i < objects_found;i++) {
			CK_OBJECT_CLASS attrs_class = 0;
			CK_ATTRIBUTE attrs[] = {
				{CKA_CLASS, &attrs_class, sizeof (attrs_class)}
			};

			if (
				_pkcs11h_getObjectAttributes (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				) == CKR_OK
			) {
				if (attrs_class == CKO_CERTIFICATE) {
					CK_ATTRIBUTE attrs_cert[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0},
						{CKA_VALUE, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					unsigned char *attrs_value = NULL;
					int attrs_value_size = 0;
					char *attrs_label = NULL;
					char szHexId[1024];
					char szSubject[1024];
					char szSerial[1024];
					char szNotBefore[1024];

					szSubject[0] = '\0';
					szSerial[0] = '\0';
					szNotBefore[0] = '\0';


					if (
						_pkcs11h_getObjectAttributes (
							session,
							objects[i],
							attrs_cert,
							sizeof (attrs_cert) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_malloc (
							(void *)&attrs_label,
							attrs_cert[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_cert[0].pValue;
						attrs_id_size = attrs_cert[0].ulValueLen;
						attrs_value = (unsigned char *)attrs_cert[2].pValue;
						attrs_value_size = attrs_cert[2].ulValueLen;

						memset (attrs_label, 0, attrs_cert[1].ulValueLen+1);
						memmove (attrs_label, attrs_cert[1].pValue, attrs_cert[1].ulValueLen);
						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							szHexId,
							sizeof (szHexId),
							"\t\t"
						);
					}

					if (attrs_value != NULL) {
						X509 *x509 = NULL;
						BIO *bioSerial = NULL;

						if ((x509 = X509_new ()) == NULL) {
							my_output (pData, "Cannot create x509 context\n");
						}
						else {
							pkcs11_openssl_d2i_t d2i1 = (pkcs11_openssl_d2i_t)attrs_value;
							if (d2i_X509 (&x509, &d2i1, attrs_value_size)) {

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
					}

					my_output (
						pData,
						(
							"Object\n"
							"\tType:\t\t\tCertificate\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
							"\tsubject:\t\t%s\n"
							"\tserialNumber:\t\t%s\n"
							"\tnotBefore:\t\t%s\n"
						),
						szHexId,
						attrs_label,
						szSubject,
						szSerial,
						szNotBefore
					);

					_pkcs11h_free ((void *)&attrs_label);

					_pkcs11h_freeObjectAttributes (
						attrs_cert,
						sizeof (attrs_cert) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_PRIVATE_KEY) {
					CK_BBOOL sign_recover = CK_FALSE;
					CK_BBOOL sign = CK_FALSE;
					CK_ATTRIBUTE attrs_key[] = {
						{CKA_SIGN, &sign, sizeof (sign)},
						{CKA_SIGN_RECOVER, &sign_recover, sizeof (sign_recover)}
					};
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					char *attrs_label = NULL;
					char szHexId[1024];

					pkcs11h_provider->f->C_GetAttributeValue (
						session->hSession,
						objects[i],
						attrs_key,
						sizeof (attrs_key) / sizeof (CK_ATTRIBUTE)
					);

					if (
						_pkcs11h_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_key_common[0].pValue;
						attrs_id_size = attrs_key_common[0].ulValueLen;

						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);

						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							szHexId,
							sizeof (szHexId),
							"\t\t"
						);
							
					}

					my_output (
						pData,
						(
							"Object\n"
							"\tType:\t\t\tPrivate Key\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
							"\tCKA_SIGN:\t\t%s\n"
							"\tCKA_SIGN_RECOVER:\t%s\n"
						),
						szHexId,
						attrs_label,
						sign ? "TRUE" : "FALSE",
						sign_recover ? "TRUE" : "FALSE"
					);

					_pkcs11h_free ((void *)&attrs_label);

					_pkcs11h_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_PUBLIC_KEY) {
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					char *attrs_label = NULL;
					char szHexId[1024];

					if (
						_pkcs11h_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_key_common[0].pValue;
						attrs_id_size = attrs_key_common[0].ulValueLen;

						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);

						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							szHexId,
							sizeof (szHexId),
							"\t\t"
						);
							
					}

					my_output (
						pData,
						(
							"Object\n"
							"\tType:\t\t\tPublic Key\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
						),
						szHexId,
						attrs_label
					);

					_pkcs11h_free ((void *)&attrs_label);

					_pkcs11h_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_DATA) {
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_APPLICATION, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					char *attrs_application = NULL;
					char *attrs_label = NULL;

					if (
						_pkcs11h_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_malloc (
							(void *)&attrs_application,
							attrs_key_common[0].ulValueLen+1
						) == CKR_OK &&
						_pkcs11h_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						memset (attrs_application, 0, attrs_key_common[0].ulValueLen+1);
						memmove (attrs_application, attrs_key_common[0].pValue, attrs_key_common[0].ulValueLen);
						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);
					}

					my_output (
						pData,
						(
							"Object\n"
							"\tType:\t\t\tData\n"
							"\tCKA_APPLICATION\t\t%s\n"
							"\tCKA_LABEL:\t\t%s\n"
						),
						attrs_application,
						attrs_label
					);

					_pkcs11h_free ((void *)&attrs_application);
					_pkcs11h_free ((void *)&attrs_label);

					_pkcs11h_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else {
					my_output (
						pData,
						(
							"Object\n"
							"\tType:\t\t\tUnsupported\n"
						)
					);
				}
			}

			_pkcs11h_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			/*
			 * Ignore any error and
			 * perform next iteration
			 */
			rv = CKR_OK;
		}
	
		if (objects != NULL) {
			_pkcs11h_free ((void *)&objects);
		}

		/*
		 * Ignore this error
		 */
		rv = CKR_OK;
	}

	if (session != NULL) {
		_pkcs11h_releaseSession (session);
		session = NULL;
	}

	if (token_id != NULL) {
		pkcs11h_freeTokenId (token_id);
		token_id = NULL;
	}
	
	pkcs11h_terminate ();
}

#endif				/* ENABLE_PKCS11H_STANDALONE */

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
#endif				/* PKCS11H_HELPER_ENABLE */

