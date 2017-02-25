/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifndef MISC_H
#define MISC_H

#include "argv.h"
#include "basic.h"
#include "common.h"
#include "integer.h"
#include "buffer.h"
#include "platform.h"

/* socket descriptor passed by inetd/xinetd server to us */
#define INETD_SOCKET_DESCRIPTOR 0

/* forward declarations */
struct plugin_list;

/*
 * Handle environmental variable lists
 */

struct env_item {
    char *string;
    struct env_item *next;
};

struct env_set {
    struct gc_arena *gc;
    struct env_item *list;
};

void run_up_down(const char *command,
                 const struct plugin_list *plugins,
                 int plugin_type,
                 const char *arg,
#ifdef _WIN32
                 DWORD adapter_index,
#endif
                 const char *dev_type,
                 int tun_mtu,
                 int link_mtu,
                 const char *ifconfig_local,
                 const char *ifconfig_remote,
                 const char *context,
                 const char *signal_text,
                 const char *script_type,
                 struct env_set *es);

void write_pid(const char *filename);

/* system flags */
#define S_SCRIPT (1<<0)
#define S_FATAL  (1<<1)

const char *system_error_message(int, struct gc_arena *gc);

/* wrapper around the execve() call */
int openvpn_popen(const struct argv *a,  const struct env_set *es);

int openvpn_execve(const struct argv *a, const struct env_set *es, const unsigned int flags);

bool openvpn_execve_check(const struct argv *a, const struct env_set *es, const unsigned int flags, const char *error_message);

bool openvpn_execve_allowed(const unsigned int flags);

static inline bool
openvpn_run_script(const struct argv *a, const struct env_set *es, const unsigned int flags, const char *hook)
{
    char msg[256];

    openvpn_snprintf(msg, sizeof(msg), "WARNING: Failed running command (%s)", hook);
    return openvpn_execve_check(a, es, flags | S_SCRIPT, msg);
}


#ifdef HAVE_STRERROR
/* a thread-safe version of strerror */
const char *strerror_ts(int errnum, struct gc_arena *gc);

#endif

/* Set standard file descriptors to /dev/null */
void set_std_files_to_null(bool stdin_only);

/* dup inetd/xinetd socket descriptor and save */
extern int inetd_socket_descriptor;
void save_inetd_socket_descriptor(void);

/* init random() function, only used as source for weak random numbers, when !ENABLE_CRYPTO */
void init_random_seed(void);

/* set/delete environmental variable */
void setenv_str_ex(struct env_set *es,
                   const char *name,
                   const char *value,
                   const unsigned int name_include,
                   const unsigned int name_exclude,
                   const char name_replace,
                   const unsigned int value_include,
                   const unsigned int value_exclude,
                   const char value_replace);

void setenv_counter(struct env_set *es, const char *name, counter_type value);

void setenv_int(struct env_set *es, const char *name, int value);

void setenv_unsigned(struct env_set *es, const char *name, unsigned int value);

void setenv_str(struct env_set *es, const char *name, const char *value);

void setenv_str_safe(struct env_set *es, const char *name, const char *value);

void setenv_del(struct env_set *es, const char *name);

/**
 * Store the supplied name value pair in the env_set.  If the variable with the
 * supplied name  already exists, append _N to the name, starting at N=1.
 */
void setenv_str_incr(struct env_set *es, const char *name, const char *value);

void setenv_int_i(struct env_set *es, const char *name, const int value, const int i);

void setenv_str_i(struct env_set *es, const char *name, const char *value, const int i);

/* struct env_set functions */

struct env_set *env_set_create(struct gc_arena *gc);

void env_set_destroy(struct env_set *es);

bool env_set_del(struct env_set *es, const char *str);

void env_set_add(struct env_set *es, const char *str);

const char *env_set_get(const struct env_set *es, const char *name);

void env_set_print(int msglevel, const struct env_set *es);

void env_set_inherit(struct env_set *es, const struct env_set *src);

/* Make arrays of strings */

const char **make_env_array(const struct env_set *es,
                            const bool check_allowed,
                            struct gc_arena *gc);

const char **make_arg_array(const char *first, const char *parms, struct gc_arena *gc);

const char **make_extended_arg_array(char **p, struct gc_arena *gc);

/* an analogue to the random() function, but use OpenSSL functions if available */
#ifdef ENABLE_CRYPTO
long int get_random(void);

#else
#define get_random random
#endif

/* return true if filename can be opened for read */
bool test_file(const char *filename);

/* create a temporary file in directory, returns the filename of the created file */
const char *create_temp_file(const char *directory, const char *prefix, struct gc_arena *gc);

/* put a directory and filename together */
const char *gen_path(const char *directory, const char *filename, struct gc_arena *gc);

/* return true if pathname is absolute */
bool absolute_pathname(const char *pathname);

/* prepend a random prefix to hostname (need ENABLE_CRYPTO) */
const char *hostname_randomize(const char *hostname, struct gc_arena *gc);

/*
 * Get and store a username/password
 */

struct user_pass
{
    bool defined;
    bool nocache;

/* max length of username/password */
#ifdef ENABLE_PKCS11
#define USER_PASS_LEN 4096
#else
#define USER_PASS_LEN 128
#endif
    char username[USER_PASS_LEN];
    char password[USER_PASS_LEN];
};

#ifdef ENABLE_CLIENT_CR
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

struct auth_challenge_info *get_auth_challenge(const char *auth_challenge, struct gc_arena *gc);

/*
 * Challenge response info on client as pushed by server.
 */
struct static_challenge_info {
#define SC_ECHO     (1<<0)  /* echo response when typed by user */
    unsigned int flags;

    const char *challenge_text;
};

#else  /* ifdef ENABLE_CLIENT_CR */
struct auth_challenge_info {};
struct static_challenge_info {};
#endif /* ifdef ENABLE_CLIENT_CR */

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

#define GET_USER_PASS_DYNAMIC_CHALLENGE      (1<<7) /* CRV1 protocol  -- dynamic challenge */
#define GET_USER_PASS_STATIC_CHALLENGE       (1<<8) /* SCRV1 protocol -- static challenge */
#define GET_USER_PASS_STATIC_CHALLENGE_ECHO  (1<<9) /* SCRV1 protocol -- echo response */

#define GET_USER_PASS_INLINE_CREDS (1<<10)  /* indicates that auth_file is actually inline creds */

bool get_user_pass_cr(struct user_pass *up,
                      const char *auth_file,
                      const char *prefix,
                      const unsigned int flags,
                      const char *auth_challenge);

static inline bool
get_user_pass(struct user_pass *up,
              const char *auth_file,
              const char *prefix,
              const unsigned int flags)
{
    return get_user_pass_cr(up, auth_file, prefix, flags, NULL);
}

void fail_user_pass(const char *prefix,
                    const unsigned int flags,
                    const char *reason);

void purge_user_pass(struct user_pass *up, const bool force);

void set_auth_token(struct user_pass *up, const char *token);

/*
 * Process string received by untrusted peer before
 * printing to console or log file.
 * Assumes that string has been null terminated.
 */
const char *safe_print(const char *str, struct gc_arena *gc);

/* returns true if environmental variable safe to print to log */
bool env_safe_to_print(const char *str);

/* returns true if environmental variable may be passed to an external program */
bool env_allowed(const char *str);

/*
 * A sleep function that services the management layer for n
 * seconds rather than doing nothing.
 */
void openvpn_sleep(const int n);

void configure_path(void);

const char *sanitize_control_message(const char *str, struct gc_arena *gc);

#if AUTO_USERID
void get_user_pass_auto_userid(struct user_pass *up, const char *tag);

#endif

/*
 * /sbin/ip path, may be overridden
 */
#ifdef ENABLE_IPROUTE
extern const char *iproute_path;
#endif

/* Script security */
#define SSEC_NONE      0 /* strictly no calling of external programs */
#define SSEC_BUILT_IN  1 /* only call built-in programs such as ifconfig, route, netsh, etc.*/
#define SSEC_SCRIPTS   2 /* allow calling of built-in programs and user-defined scripts */
#define SSEC_PW_ENV    3 /* allow calling of built-in programs and user-defined scripts that may receive a password as an environmental variable */
extern int script_security; /* GLOBAL */

/* return the next largest power of 2 */
size_t adjust_power_of_2(size_t u);

#define COMPAT_FLAG_QUERY         0       /** compat_flags operator: Query for a flag */
#define COMPAT_FLAG_SET           (1<<0)  /** compat_flags operator: Set a compat flag */
#define COMPAT_NAMES              (1<<1)  /** compat flag: --compat-names set */
#define COMPAT_NO_NAME_REMAPPING  (1<<2)  /** compat flag: --compat-names without char remapping */
bool compat_flag(unsigned int flag);

#if P2MP_SERVER
/* helper to parse peer_info received from multi client, validate
 * (this is untrusted data) and put into environment */
bool validate_peer_info_line(char *line);

void output_peer_info_env(struct env_set *es, const char *peer_info);

#endif /* P2MP_SERVER */

#endif /* ifndef MISC_H */
