#if DLOPEN_PAM
/*
 * If you want to dynamically load libpam using dlopen() or something,
 * then dlopen( ' this shared object ' ); It takes care of exporting
 * the right symbols to any modules loaded by libpam.
 *
 * Modified by JY for use with openvpn-pam-auth
 */

#include <stdio.h>
#include <dlfcn.h>
#include <security/pam_appl.h>

#include "pamdl.h"

static void *libpam_h = NULL;

#define RESOLVE_PAM_FUNCTION(x, y, z, err) \
    { \
        union { const void *tpointer; y (*fn) z ; } fptr; \
	fptr.tpointer = dlsym(libpam_h, #x); real_##x = fptr.fn; \
	if (real_##x == NULL) { \
	    fprintf (stderr, "PAMDL: unable to resolve '%s': %s\n", #x, dlerror()); \
	    return err; \
	} \
    }

int
dlopen_pam (const char *so)
{
  if (libpam_h == NULL)
    {
      libpam_h = dlopen(so, RTLD_GLOBAL|RTLD_NOW);
    }
  return libpam_h != NULL;
}

void
dlclose_pam (void)
{
  if (libpam_h != NULL)
    {
      dlclose(libpam_h);
      libpam_h = NULL;
    }
}

int pam_start(const char *service_name, const char *user,
	      const struct pam_conv *pam_conversation,
	      pam_handle_t **pamh)
{
    int (*real_pam_start)(const char *, const char *,
				 const struct pam_conv *,
				 pam_handle_t **);
    RESOLVE_PAM_FUNCTION(pam_start, int, (const char *, const char *,
					  const struct pam_conv *,
					  pam_handle_t **), PAM_ABORT);
    return real_pam_start(service_name, user, pam_conversation, pamh);
}

int pam_end(pam_handle_t *pamh, int pam_status)
{
    int (*real_pam_end)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_end, int, (pam_handle_t *, int), PAM_ABORT);
    return real_pam_end(pamh, pam_status);
}

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
    int (*real_pam_set_item)(pam_handle_t *, int, const void *);
    RESOLVE_PAM_FUNCTION(pam_set_item, int,
			 (pam_handle_t *, int, const void *), PAM_ABORT);
    return real_pam_set_item(pamh, item_type, item);
}

int pam_get_item(pam_handle_t *pamh, int item_type, const void **item)
{
    int (*real_pam_get_item)(const pam_handle_t *, int, const void **);
    RESOLVE_PAM_FUNCTION(pam_get_item, int,
			 (const pam_handle_t *, int, const void **),
			 PAM_ABORT);
    return real_pam_get_item(pamh, item_type, item);
}

int pam_fail_delay(pam_handle_t *pamh, unsigned int musec_delay)
{
    int (*real_pam_fail_delay)(pam_handle_t *, unsigned int);
    RESOLVE_PAM_FUNCTION(pam_fail_delay, int, (pam_handle_t *, unsigned int),
			 PAM_ABORT);
    return real_pam_fail_delay(pamh, musec_delay);
}

typedef const char * const_char_pointer;

const_char_pointer pam_strerror(pam_handle_t *pamh, int errnum)
{
    const_char_pointer (*real_pam_strerror)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_strerror, const_char_pointer,
			 (pam_handle_t *, int), NULL);
    return real_pam_strerror(pamh, errnum);
}

int pam_putenv(pam_handle_t *pamh, const char *name_value)
{
    int (*real_pam_putenv)(pam_handle_t *, const char *);
    RESOLVE_PAM_FUNCTION(pam_putenv, int, (pam_handle_t *, const char *),
			 PAM_ABORT);
    return real_pam_putenv(pamh, name_value);
}

const_char_pointer pam_getenv(pam_handle_t *pamh, const char *name)
{
    const_char_pointer (*real_pam_getenv)(pam_handle_t *, const char *);
    RESOLVE_PAM_FUNCTION(pam_getenv, const_char_pointer,
			 (pam_handle_t *, const char *), NULL);
    return real_pam_getenv(pamh, name);
}

typedef char ** char_ppointer;
char_ppointer pam_getenvlist(pam_handle_t *pamh)
{
    char_ppointer (*real_pam_getenvlist)(pam_handle_t *);
    RESOLVE_PAM_FUNCTION(pam_getenvlist, char_ppointer, (pam_handle_t *),
			 NULL);
    return real_pam_getenvlist(pamh);
}

/* Authentication management */

int pam_authenticate(pam_handle_t *pamh, int flags)
{
    int (*real_pam_authenticate)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_authenticate, int, (pam_handle_t *, int),
			 PAM_ABORT);
    return real_pam_authenticate(pamh, flags);
}

int pam_setcred(pam_handle_t *pamh, int flags)
{
    int (*real_pam_setcred)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_setcred, int, (pam_handle_t *, int), PAM_ABORT);
    return real_pam_setcred(pamh, flags);
}

/* Account Management API's */

int pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
    int (*real_pam_acct_mgmt)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_acct_mgmt, int, (pam_handle_t *, int), PAM_ABORT);
    return real_pam_acct_mgmt(pamh, flags);
}

/* Session Management API's */

int pam_open_session(pam_handle_t *pamh, int flags)
{
    int (*real_pam_open_session)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_open_session, int, (pam_handle_t *, int),
			 PAM_ABORT);
    return real_pam_open_session(pamh, flags);
}

int pam_close_session(pam_handle_t *pamh, int flags)
{
    int (*real_pam_close_session)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_close_session, int, (pam_handle_t *, int),
			 PAM_ABORT);
    return real_pam_close_session(pamh, flags);
}

/* Password Management API's */

int pam_chauthtok(pam_handle_t *pamh, int flags)
{
    int (*real_pam_chauthtok)(pam_handle_t *, int);
    RESOLVE_PAM_FUNCTION(pam_chauthtok, int, (pam_handle_t *, int), PAM_ABORT);
    return real_pam_chauthtok(pamh, flags);
}
#endif
