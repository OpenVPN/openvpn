/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2008-2026 David Sommerseth <dazo@eurephia.org>
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

/*
 *  Check file/directory sanity
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Expect people using the stripped down version to know what they do */
#ifndef ENABLE_SMALL

#include "syshead.h"

#include "check_file_access.h"

#include "argv.h"
#include "buffer.h"
#include "error.h"
#include "options.h"
#include "platform.h"
#include "ssl_common.h"

#include <string.h>

#define CHKACC_FILE       (1 << 0) /**< Check for a file/directory presence */
#define CHKACC_DIRPATH    (1 << 1) /**< Check for directory presence where a file should reside */
#define CHKACC_FILEXSTWR  (1 << 2) /**< If file exists, is it writable? */
#define CHKACC_ACPTSTDIN  (1 << 3) /**< If filename is stdin, it's allowed and "exists" */
#define CHKACC_PRIVATE    (1 << 4) /**< Warn if this (private) file is group/others accessible */
#define CHKACC_ACCEPT_URI (1 << 5) /**< Do not check URIs, unless they start with file: */

static bool
check_file_access(const int type, const char *file, const int mode, const char *opt)
{
    int errcode = 0;

    /* If no file configured, no errors to look for */
    if (!file)
    {
        return false;
    }

    /* If stdin is allowed and the file name is 'stdin', then do no
     * further checks as stdin is always available
     */
    if ((type & CHKACC_ACPTSTDIN) && streq(file, "stdin"))
    {
        return false;
    }

    /* file name is a URI if its first segment  has ":" (i.e., before any "/")
     * Then no checks done if CHKACC_ACCEPT_URI is set and the URI does not start with "file:"
     */
    if ((type & CHKACC_ACCEPT_URI) && strchr(file, ':'))
    {
        if (!strncmp(file, "file:", 5))
        {
            file += 5;
        }
        else if (!strchr(file, '/') || strchr(file, '/') > strchr(file, ':'))
        {
            return false;
        }
    }

    /* Is the directory path leading to the given file accessible? */
    if (type & CHKACC_DIRPATH)
    {
        char *fullpath =
            string_alloc(file, NULL); /* POSIX dirname() implementation may modify its arguments */
        const char *dirpath = dirname(fullpath);

        if (platform_access(dirpath, mode | X_OK) != 0)
        {
            errcode = errno;
        }
        free(fullpath);
    }

    /* Is the file itself accessible? */
    if (!errcode && (type & CHKACC_FILE) && (platform_access(file, mode) != 0))
    {
        errcode = errno;
    }

    /* If the file exists and is accessible, is it writable? */
    if (!errcode && (type & CHKACC_FILEXSTWR) && (platform_access(file, F_OK) == 0))
    {
        if (platform_access(file, W_OK) != 0)
        {
            errcode = errno;
        }
    }

    /* Warn if a given private file is group/others accessible. */
    if (type & CHKACC_PRIVATE)
    {
        platform_stat_t st;
        if (platform_stat(file, &st))
        {
            msg(M_WARN | M_ERRNO, "WARNING: cannot stat file '%s'", file);
        }
#ifndef _WIN32
        else
        {
            if (st.st_mode & (S_IRWXG | S_IRWXO))
            {
                msg(M_WARN, "WARNING: file '%s' is group or others accessible", file);
            }
        }
#endif
    }

    /* Scream if an error is found */
    if (errcode > 0)
    {
        msg(M_NOPREFIX | M_OPTERR | M_ERRNO, "%s fails with '%s'", opt, file);
    }

    /* Return true if an error occurred */
    return (errcode != 0 ? true : false);
}

/** A wrapper for check_file_access() which also takes a chroot directory.
 * If chroot is NULL, behaviour is exactly the same as calling check_file_access() directly,
 * otherwise it will look for the file inside the given chroot directory instead.
 */
static bool
check_file_access_chroot(const char *chroot, const int type, const char *file, const int mode,
                         const char *opt)
{
    bool ret = false;

    /* If no file configured, no errors to look for */
    if (!file)
    {
        return false;
    }

    /* If chroot is set, look for the file/directory inside the chroot */
    if (chroot)
    {
        struct gc_arena gc = gc_new();
        struct buffer chroot_file;

        chroot_file = prepend_dir(chroot, file, &gc);
        ret = check_file_access(type, BSTR(&chroot_file), mode, opt);
        gc_free(&gc);
    }
    else
    {
        /* No chroot in play, just call core file check function */
        ret = check_file_access(type, file, mode, opt);
    }
    return ret;
}

/**
 * A wrapper for check_file_access_chroot() that returns false immediately if
 * the file is inline (and therefore there is no access to check)
 */
static bool
check_file_access_chroot_inline(bool is_inline, const char *chroot, const int type,
                                const char *file, const int mode, const char *opt)
{
    if (is_inline)
    {
        return false;
    }

    return check_file_access_chroot(chroot, type, file, mode, opt);
}

/**
 * A wrapper for check_file_access() that returns false immediately if the file
 * is inline (and therefore there is no access to check)
 */
static bool
check_file_access_inline(bool is_inline, const int type, const char *file, const int mode,
                         const char *opt)
{
    if (is_inline)
    {
        return false;
    }

    return check_file_access(type, file, mode, opt);
}

bool
check_cmd_access(const char *command, const char *opt, const char *chroot)
{
    struct argv argv;
    bool return_code;

    /* If no command was set, there are no errors to look for */
    if (!command)
    {
        return false;
    }

    /* Extract executable path and arguments */
    argv = argv_new();
    argv_parse_cmd(&argv, command);

    /* if an executable is specified then check it; otherwise, complain */
    if (argv.argv[0])
    {
        /* Scripts requires R_OK as well, but that might fail on binaries which
         * only requires X_OK to function on Unix - a scenario not unlikely to
         * be seen on suid binaries.
         */
        return_code = check_file_access_chroot(chroot, CHKACC_FILE, argv.argv[0], X_OK, opt);
    }
    else
    {
        msg(M_NOPREFIX | M_OPTERR, "%s fails with '%s': No path to executable.", opt, command);
        return_code = true;
    }

    argv_free(&argv);

    return return_code;
}

void
options_postprocess_filechecks(struct options *options)
{
    bool errs = false;

    /* ** SSL/TLS/crypto related files ** */
    errs |= check_file_access_inline(options->dh_file_inline, CHKACC_FILE, options->dh_file, R_OK,
                                     "--dh");

    if (!options->verify_hash_no_ca)
    {
        errs |= check_file_access_inline(options->ca_file_inline, CHKACC_FILE, options->ca_file,
                                         R_OK, "--ca");
    }

    errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE, options->ca_path, R_OK,
                                     "--capath");

    errs |= check_file_access_inline(options->cert_file_inline, CHKACC_FILE | CHKACC_ACCEPT_URI,
                                     options->cert_file, R_OK, "--cert");

    errs |= check_file_access_inline(options->extra_certs_file, CHKACC_FILE,
                                     options->extra_certs_file, R_OK, "--extra-certs");

    if (!(options->management_flags & MF_EXTERNAL_KEY))
    {
        errs |= check_file_access_inline(options->priv_key_file_inline,
                                         CHKACC_FILE | CHKACC_PRIVATE | CHKACC_ACCEPT_URI,
                                         options->priv_key_file, R_OK, "--key");
    }

    errs |= check_file_access_inline(options->pkcs12_file_inline, CHKACC_FILE | CHKACC_PRIVATE,
                                     options->pkcs12_file, R_OK, "--pkcs12");

    if (options->ssl_flags & SSLF_CRL_VERIFY_DIR)
    {
        errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE, options->crl_file,
                                         R_OK | X_OK, "--crl-verify directory");
    }
    else
    {
        errs |=
            check_file_access_chroot_inline(options->crl_file_inline, options->chroot_dir,
                                            CHKACC_FILE, options->crl_file, R_OK, "--crl-verify");
    }

    if (options->tls_export_peer_cert_dir)
    {
        errs |=
            check_file_access_chroot(options->chroot_dir, CHKACC_FILE,
                                     options->tls_export_peer_cert_dir, W_OK, "--tls-export-cert");
    }

    ASSERT(options->connection_list);
    for (int i = 0; i < options->connection_list->len; ++i)
    {
        const struct connection_entry *ce = options->connection_list->array[i];

        errs |= check_file_access_inline(ce->tls_auth_file_inline, CHKACC_FILE | CHKACC_PRIVATE,
                                         ce->tls_auth_file, R_OK, "--tls-auth");
        errs |= check_file_access_inline(ce->tls_crypt_file_inline, CHKACC_FILE | CHKACC_PRIVATE,
                                         ce->tls_crypt_file, R_OK, "--tls-crypt");
        errs |= check_file_access_inline(ce->tls_crypt_v2_file_inline, CHKACC_FILE | CHKACC_PRIVATE,
                                         ce->tls_crypt_v2_file, R_OK, "--tls-crypt-v2");
    }

    errs |=
        check_file_access_inline(options->shared_secret_file_inline, CHKACC_FILE | CHKACC_PRIVATE,
                                 options->shared_secret_file, R_OK, "--secret");

    errs |= check_file_access(CHKACC_DIRPATH | CHKACC_FILEXSTWR, options->packet_id_file,
                              R_OK | W_OK, "--replay-persist");

    /* ** Password files ** */
    errs |= check_file_access(CHKACC_FILE | CHKACC_ACPTSTDIN | CHKACC_PRIVATE,
                              options->key_pass_file, R_OK, "--askpass");
#ifdef ENABLE_MANAGEMENT
    errs |=
        check_file_access(CHKACC_FILE | CHKACC_ACPTSTDIN | CHKACC_PRIVATE,
                          options->management_user_pass, R_OK, "--management user/password file");
#endif /* ENABLE_MANAGEMENT */
    errs |= check_file_access_inline(options->auth_user_pass_file_inline,
                                     CHKACC_FILE | CHKACC_ACPTSTDIN | CHKACC_PRIVATE,
                                     options->auth_user_pass_file, R_OK, "--auth-user-pass");
    /* ** System related ** */
    errs |= check_file_access(CHKACC_FILE, options->chroot_dir, R_OK | X_OK, "--chroot directory");
    errs |= check_file_access(CHKACC_DIRPATH | CHKACC_FILEXSTWR, options->writepid, R_OK | W_OK,
                              "--writepid");

    /* ** Log related ** */
    errs |= check_file_access(CHKACC_DIRPATH | CHKACC_FILEXSTWR, options->status_file, R_OK | W_OK,
                              "--status");

    /* ** Config related ** */
    errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE, options->client_config_dir,
                                     R_OK | X_OK, "--client-config-dir");
    errs |= check_file_access_chroot(options->chroot_dir, CHKACC_FILE, options->tmp_dir,
                                     R_OK | W_OK | X_OK, "Temporary directory (--tmp-dir)");

    if (errs)
    {
        msg(M_USAGE, "Please correct these errors.");
    }
}

#endif /* !ENABLE_SMALL */
