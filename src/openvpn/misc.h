/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef MISC_H
#define MISC_H

#include "argv.h"
#include "basic.h"
#include "common.h"
#include "env_set.h"
#include "integer.h"
#include "buffer.h"
#include "platform.h"

/* forward declarations */
struct plugin_list;


/* Set standard file descriptors to /dev/null */
void set_std_files_to_null(bool stdin_only);

/* Make arrays of strings */

const char **make_arg_array(const char *first, const char *parms, struct gc_arena *gc);

const char **make_extended_arg_array(char **p, bool is_inline,
                                     struct gc_arena *gc);

/* prepend a random prefix to hostname */
const char *hostname_randomize(const char *hostname, struct gc_arena *gc);

/*
 * Get and store a username/password
 */

struct user_pass
{
    bool defined;
    /* For auth-token username and token can be set individually, so we
     * use this second bool to track if the token (password) is defined */
    bool token_defined;
    bool nocache;
    bool protected;

/* max length of username/password */
#ifdef ENABLE_PKCS11
#define USER_PASS_LEN 4096
#else
#define USER_PASS_LEN 128
#endif
    /* Note that username and password are expected to be null-terminated */
    char username[USER_PASS_LEN];
    char password[USER_PASS_LEN];
};

#ifdef ENABLE_MANAGEMENT
/*
 * Challenge response info on client as pushed by server.
 */
struct auth_challenge_info {
#define CR_ECHO     (1<<0)  /* echo response when typed by user */
#define CR_RESPONSE (1<<1)  /* response needed */
    unsigned int flags;

    const char *user;
    const char *state_id;
    const char *challenge_text;
};

/*
 * Challenge response info on client as pushed by server.
 */
struct static_challenge_info {
#define SC_ECHO     (1<<0)  /* echo response when typed by user */
#define SC_CONCAT   (1<<1)  /* concatenate password and response and do not base64 encode */
    unsigned int flags;

    const char *challenge_text;
};

#else  /* ifdef ENABLE_MANAGEMENT */
struct auth_challenge_info {};
struct static_challenge_info {};
#endif /* ifdef ENABLE_MANAGEMENT */

/*
 * Flags for get_user_pass and management_query_user_pass
 */
#define GET_USER_PASS_MANAGEMENT    (1<<0)
/* GET_USER_PASS_SENSITIVE     (1<<1)  not used anymore */
#define GET_USER_PASS_PASSWORD_ONLY (1<<2)
#define GET_USER_PASS_NEED_OK       (1<<3)
#define GET_USER_PASS_NOFATAL       (1<<4)
#define GET_USER_PASS_NEED_STR      (1<<5)
#define GET_USER_PASS_PREVIOUS_CREDS_FAILED (1<<6)

#define GET_USER_PASS_DYNAMIC_CHALLENGE      (1<<7) /**< CRV1 protocol  -- dynamic challenge */
#define GET_USER_PASS_STATIC_CHALLENGE       (1<<8) /**< SCRV1 protocol -- static challenge */
#define GET_USER_PASS_STATIC_CHALLENGE_ECHO  (1<<9) /**< SCRV1 protocol -- echo response */

/** indicates that auth_file is actually inline creds */
#define GET_USER_PASS_INLINE_CREDS (1<<10)
/** indicates password and response should be concatenated */
#define GET_USER_PASS_STATIC_CHALLENGE_CONCAT (1<<11)

/**
 * Retrieves the user credentials from various sources depending on the flags.
 *
 * @param up The user_pass structure to store the retrieved credentials.
 * @param auth_file The path to the authentication file. Might be NULL.
 * @param prefix The prefix to prepend to user prompts.
 * @param flags Additional flags to control the behavior of the function.
 * @param auth_challenge The authentication challenge string.
 * @return true if the user credentials were successfully retrieved, false otherwise.
 */
bool get_user_pass_cr(struct user_pass *up,
                      const char *auth_file,
                      const char *prefix,
                      const unsigned int flags,
                      const char *auth_challenge);

/**
 * Retrieves the user credentials from various sources depending on the flags.
 *
 * @param up The user_pass structure to store the retrieved credentials.
 * @param auth_file The path to the authentication file. Might be NULL.
 * @param prefix The prefix to prepend to user prompts.
 * @param flags Additional flags to control the behavior of the function.
 * @return true if the user credentials were successfully retrieved, false otherwise.
 */
static inline bool
get_user_pass(struct user_pass *up,
              const char *auth_file,
              const char *prefix,
              const unsigned int flags)
{
    return get_user_pass_cr(up, auth_file, prefix, flags, NULL);
}

void purge_user_pass(struct user_pass *up, const bool force);

/**
 * Sets the auth-token to token. The method will also purge up if
 * the auth-nocache option is active.
 *
 * @param tk        auth-token userpass to set
 * @param token     token to use as password for the auth-token
 *
 * @note    all parameters to this function must not be null.
 */
void set_auth_token(struct user_pass *tk, const char *token);

/**
 * Sets the auth-token username by base64 decoding the passed
 * username
 *
 * @param tk        auth-token userpass to set
 * @param username  base64 encoded username to set
 *
 * @note    all parameters to this function must not be null.
 */
void set_auth_token_user(struct user_pass *tk, const char *username);

/*
 * Process string received by untrusted peer before
 * printing to console or log file.
 * Assumes that string has been null terminated.
 */
const char *safe_print(const char *str, struct gc_arena *gc);

const char *sanitize_control_message(const char *str, struct gc_arena *gc);

/*
 * /sbin/ip path, may be overridden
 */
#ifdef ENABLE_IPROUTE
extern const char *iproute_path;
#endif

/* helper to parse peer_info received from multi client, validate
 * (this is untrusted data) and put into environment */
bool validate_peer_info_line(char *line);

void output_peer_info_env(struct env_set *es, const char *peer_info);

/**
 * Prepend a directory to a path.
 */
struct buffer
prepend_dir(const char *dir, const char *path, struct gc_arena *gc);

/**
 * Encrypt username and password buffers in user_pass
 */
void
protect_user_pass(struct user_pass *up);

/**
 * Decrypt username and password buffers in user_pass
 */
void
unprotect_user_pass(struct user_pass *up);


#define _STRINGIFY(S) #S
/* *INDENT-OFF* - uncrustify need to ignore this macro */
#define MAC_FMT _STRINGIFY(%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx)
/* *INDENT-ON* */
#define MAC_PRINT_ARG(_mac) _mac[0], _mac[1], _mac[2],  \
    _mac[3], _mac[4], _mac[5]
#define MAC_SCAN_ARG(_mac) &_mac[0], &_mac[1], &_mac[2], \
    &_mac[3], &_mac[4], &_mac[5]

#endif /* ifndef MISC_H */
