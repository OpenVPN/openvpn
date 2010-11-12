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

#ifndef MISC_H
#define MISC_H

#include "basic.h"
#include "common.h"
#include "integer.h"
#include "buffer.h"

/* socket descriptor passed by inetd/xinetd server to us */
#define INETD_SOCKET_DESCRIPTOR 0

/* forward declarations */
struct plugin_list;

/* used by argv_x functions */
struct argv {
  size_t capacity;
  size_t argc;
  char **argv;
  char *system_str;
};

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

/* Get/Set UID of process */

struct user_state {
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
  const char *username;
  struct passwd *pw;
#else
  int dummy;
#endif
};

bool get_user (const char *username, struct user_state *state);
void set_user (const struct user_state *state);

/* Get/Set GID of process */

struct group_state {
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
  const char *groupname;
  struct group *gr;
#else
  int dummy;
#endif
};

bool get_group (const char *groupname, struct group_state *state);
void set_group (const struct group_state *state);

void set_nice (int niceval);
void do_chroot (const char *path);

void run_up_down (const char *command,
		  const struct plugin_list *plugins,
		  int plugin_type,
		  const char *arg,
		  int tun_mtu,
		  int link_mtu,
		  const char *ifconfig_local,
		  const char* ifconfig_remote,
		  const char *context,
		  const char *signal_text,
		  const char *script_type,
		  struct env_set *es);

/* workspace for get_pid_file/write_pid */
struct pid_state {
  FILE *fp;
  const char *filename;
};

void get_pid_file (const char* filename, struct pid_state *state);
void write_pid (const struct pid_state *state);
unsigned int openvpn_getpid (void);

void do_mlockall (bool print_msg); /* Disable paging */

#ifndef HAVE_DAEMON
int daemon (int nochdir, int noclose);
#endif

/* check file protections */
void warn_if_group_others_accessible(const char* filename);

/* system flags */
#define S_SCRIPT (1<<0)
#define S_FATAL  (1<<1)

/* interpret the status code returned by system()/execve() */
bool system_ok(int);
bool system_executed (int stat);
const char *system_error_message (int, struct gc_arena *gc);

/* wrapper around the execve() call */
int openvpn_execve (const struct argv *a, const struct env_set *es, const unsigned int flags);
bool openvpn_execve_check (const struct argv *a, const struct env_set *es, const unsigned int flags, const char *error_message);
bool openvpn_execve_allowed (const unsigned int flags);
int openvpn_system (const char *command, const struct env_set *es, unsigned int flags);

static inline bool
openvpn_run_script (const struct argv *a, const struct env_set *es, const unsigned int flags, const char *hook)
{
  char msg[256];

  openvpn_snprintf(msg, sizeof(msg), "WARNING: Failed running command (%s)", hook);
  return openvpn_execve_check(a, es, flags | S_SCRIPT, msg);
};

#ifdef HAVE_STRERROR
/* a thread-safe version of strerror */
const char* strerror_ts (int errnum, struct gc_arena *gc);
#endif

/* Set standard file descriptors to /dev/null */
void set_std_files_to_null (bool stdin_only);

/* Wrapper for chdir library function */
int openvpn_chdir (const char* dir);

/* dup inetd/xinetd socket descriptor and save */
extern int inetd_socket_descriptor;
void save_inetd_socket_descriptor (void);

/* init random() function, only used as source for weak random numbers, when !USE_CRYPTO */
void init_random_seed(void);

/* set/delete environmental variable */
void setenv_str_ex (struct env_set *es,
		    const char *name,
		    const char *value,
		    const unsigned int name_include,
		    const unsigned int name_exclude,
		    const char name_replace,
		    const unsigned int value_include,
		    const unsigned int value_exclude,
		    const char value_replace);

void setenv_counter (struct env_set *es, const char *name, counter_type value);
void setenv_int (struct env_set *es, const char *name, int value);
void setenv_unsigned (struct env_set *es, const char *name, unsigned int value);
void setenv_str (struct env_set *es, const char *name, const char *value);
void setenv_str_safe (struct env_set *es, const char *name, const char *value);
void setenv_del (struct env_set *es, const char *name);

void setenv_int_i (struct env_set *es, const char *name, const int value, const int i);
void setenv_str_i (struct env_set *es, const char *name, const char *value, const int i);

/* struct env_set functions */

struct env_set *env_set_create (struct gc_arena *gc);
void env_set_destroy (struct env_set *es);
bool env_set_del (struct env_set *es, const char *str);
void env_set_add (struct env_set *es, const char *str);

void env_set_print (int msglevel, const struct env_set *es);

void env_set_inherit (struct env_set *es, const struct env_set *src);

void env_set_add_to_environment (const struct env_set *es);
void env_set_remove_from_environment (const struct env_set *es);

/* Make arrays of strings */

const char **make_env_array (const struct env_set *es,
			     const bool check_allowed,
			     struct gc_arena *gc);

const char **make_arg_array (const char *first, const char *parms, struct gc_arena *gc);
const char **make_extended_arg_array (char **p, struct gc_arena *gc);

/* convert netmasks for iproute2 */
int count_netmask_bits(const char *);
unsigned int count_bits(unsigned int );

/* go to sleep for n milliseconds */
void sleep_milliseconds (unsigned int n);

/* go to sleep indefinitely */
void sleep_until_signal (void);

/* an analogue to the random() function, but use OpenSSL functions if available */
#ifdef USE_CRYPTO
long int get_random(void);
#else
#define get_random random
#endif

/* return true if filename can be opened for read */
bool test_file (const char *filename);

/* create a temporary file in directory, returns the filename of the created file */
const char *create_temp_file (const char *directory, const char *prefix, struct gc_arena *gc);

/* put a directory and filename together */
const char *gen_path (const char *directory, const char *filename, struct gc_arena *gc);

/* delete a file, return true if succeeded */
bool delete_file (const char *filename);

/* return true if pathname is absolute */
bool absolute_pathname (const char *pathname);

/* prepend a random prefix to hostname (need USE_CRYPTO) */
const char *hostname_randomize(const char *hostname, struct gc_arena *gc);

/*
 * Get and store a username/password
 */

struct user_pass
{
  bool defined;
  bool nocache;

/* max length of username/password */
# ifdef ENABLE_PKCS11
#   define USER_PASS_LEN 4096
# else
#   define USER_PASS_LEN 128
# endif
  char username[USER_PASS_LEN];
  char password[USER_PASS_LEN];
};

#ifdef ENABLE_CLIENT_CR
/*
 * Challenge response info on client as pushed by server.
 */
struct auth_challenge_info {
# define CR_ECHO     (1<<0) /* echo response when typed by user */
# define CR_RESPONSE (1<<1) /* response needed */
  unsigned int flags;

  const char *user;
  const char *state_id;
  const char *challenge_text;
};

struct auth_challenge_info *get_auth_challenge (const char *auth_challenge, struct gc_arena *gc);

#else
struct auth_challenge_info {};
#endif

bool get_console_input (const char *prompt, const bool echo, char *input, const int capacity);

/*
 * Flags for get_user_pass and management_query_user_pass
 */
#define GET_USER_PASS_MANAGEMENT    (1<<0)
#define GET_USER_PASS_SENSITIVE     (1<<1)
#define GET_USER_PASS_PASSWORD_ONLY (1<<2)
#define GET_USER_PASS_NEED_OK       (1<<3)
#define GET_USER_PASS_NOFATAL       (1<<4)
#define GET_USER_PASS_NEED_STR      (1<<5)
#define GET_USER_PASS_PREVIOUS_CREDS_FAILED (1<<6)

bool get_user_pass_cr (struct user_pass *up,
		       const char *auth_file,
		       const char *prefix,
		       const unsigned int flags,
		       const char *auth_challenge);

static inline bool
get_user_pass (struct user_pass *up,
	       const char *auth_file,
	       const char *prefix,
	       const unsigned int flags)
{
  return get_user_pass_cr (up, auth_file, prefix, flags, NULL);
}

void fail_user_pass (const char *prefix,
		     const unsigned int flags,
		     const char *reason);

void purge_user_pass (struct user_pass *up, const bool force);

/*
 * Process string received by untrusted peer before
 * printing to console or log file.
 * Assumes that string has been null terminated.
 */
const char *safe_print (const char *str, struct gc_arena *gc);

/* returns true if environmental variable safe to print to log */
bool env_safe_to_print (const char *str);

/* returns true if environmental variable may be passed to an external program */
bool env_allowed (const char *str);

/*
 * A sleep function that services the management layer for n
 * seconds rather than doing nothing.
 */
void openvpn_sleep (const int n);

void configure_path (void);

#if AUTO_USERID
void get_user_pass_auto_userid (struct user_pass *up, const char *tag);
#endif

/*
 * /sbin/ip path, may be overridden
 */
#ifdef CONFIG_FEATURE_IPROUTE
extern const char *iproute_path;
#endif

/* Script security */
#define SSEC_NONE      0 /* strictly no calling of external programs */
#define SSEC_BUILT_IN  1 /* only call built-in programs such as ifconfig, route, netsh, etc.*/
#define SSEC_SCRIPTS   2 /* allow calling of built-in programs and user-defined scripts */
#define SSEC_PW_ENV    3 /* allow calling of built-in programs and user-defined scripts that may receive a password as an environmental variable */
extern int script_security; /* GLOBAL */

#define SM_EXECVE 0      /* call external programs with execve() or CreateProcess() */
#define SM_SYSTEM 1      /* call external programs with system() */
extern int script_method; /* GLOBAL */

/* return the next largest power of 2 */
size_t adjust_power_of_2 (size_t u);

/* return the basename of path */
const char *openvpn_basename (const char *path);

/*
 * A printf-like function (that only recognizes a subset of standard printf
 * format operators) that prints arguments to an argv list instead
 * of a standard string.  This is used to build up argv arrays for passing
 * to execve.
 */
void argv_init (struct argv *a);
struct argv argv_new (void);
void argv_reset (struct argv *a);
char *argv_term (const char **f);
const char *argv_str (const struct argv *a, struct gc_arena *gc, const unsigned int flags);
struct argv argv_insert_head (const struct argv *a, const char *head);
void argv_msg (const int msglev, const struct argv *a);
void argv_msg_prefix (const int msglev, const struct argv *a, const char *prefix);
const char *argv_system_str (const struct argv *a);

#define APA_CAT (1<<0) /* concatentate onto existing struct argv list */
void argv_printf_arglist (struct argv *a, const char *format, const unsigned int flags, va_list arglist);

void argv_printf (struct argv *a, const char *format, ...)
#ifdef __GNUC__
  __attribute__ ((format (printf, 2, 3)))
#endif
  ;

void argv_printf_cat (struct argv *a, const char *format, ...)
#ifdef __GNUC__
  __attribute__ ((format (printf, 2, 3)))
#endif
  ;

/*
 * Extract UID or GID
 */

static inline int
user_state_uid (const struct user_state *s)
{
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
  if (s->pw)
    return s->pw->pw_uid;
#endif
  return -1;
}

static inline int
group_state_gid (const struct group_state *s)
{
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
  if (s->gr)
    return s->gr->gr_gid;
#endif
  return -1;
}

#endif
