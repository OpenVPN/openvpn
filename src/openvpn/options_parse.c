/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2008-2025 David Sommerseth <dazo@eurephia.org>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "options.h"
#include "options_util.h"
#include "push.h"

static void
bypass_doubledash(char **p)
{
    if (strlen(*p) >= 3 && !strncmp(*p, "--", 2))
    {
        *p += 2;
    }
}

static inline bool
space(char c)
{
    return c == '\0' || isspace(c);
}

int
parse_line(const char *line, char *p[], const int n, const char *file, const int line_num,
           msglvl_t msglevel, struct gc_arena *gc)
{
    const int STATE_INITIAL = 0;
    const int STATE_READING_QUOTED_PARM = 1;
    const int STATE_READING_UNQUOTED_PARM = 2;
    const int STATE_DONE = 3;
    const int STATE_READING_SQUOTED_PARM = 4;

    const char *error_prefix = "";

    int ret = 0;
    const char *c = line;
    int state = STATE_INITIAL;
    bool backslash = false;
    char in, out;

    char parm[OPTION_PARM_SIZE];
    unsigned int parm_len = 0;

    msglevel &= ~M_OPTERR;

    if (msglevel & M_MSG_VIRT_OUT)
    {
        error_prefix = "ERROR: ";
    }

    do
    {
        in = *c;
        out = 0;

        if (!backslash && in == '\\' && state != STATE_READING_SQUOTED_PARM)
        {
            backslash = true;
        }
        else
        {
            if (state == STATE_INITIAL)
            {
                if (!space(in))
                {
                    if (in == ';' || in == '#') /* comment */
                    {
                        break;
                    }
                    if (!backslash && in == '\"')
                    {
                        state = STATE_READING_QUOTED_PARM;
                    }
                    else if (!backslash && in == '\'')
                    {
                        state = STATE_READING_SQUOTED_PARM;
                    }
                    else
                    {
                        out = in;
                        state = STATE_READING_UNQUOTED_PARM;
                    }
                }
            }
            else if (state == STATE_READING_UNQUOTED_PARM)
            {
                if (!backslash && space(in))
                {
                    state = STATE_DONE;
                }
                else
                {
                    out = in;
                }
            }
            else if (state == STATE_READING_QUOTED_PARM)
            {
                if (!backslash && in == '\"')
                {
                    state = STATE_DONE;
                }
                else
                {
                    out = in;
                }
            }
            else if (state == STATE_READING_SQUOTED_PARM)
            {
                if (in == '\'')
                {
                    state = STATE_DONE;
                }
                else
                {
                    out = in;
                }
            }
            if (state == STATE_DONE)
            {
                /* ASSERT (parm_len > 0); */
                p[ret] = gc_malloc(parm_len + 1, true, gc);
                memcpy(p[ret], parm, parm_len);
                p[ret][parm_len] = '\0';
                state = STATE_INITIAL;
                parm_len = 0;
                ++ret;
            }

            if (backslash && out)
            {
                if (!(out == '\\' || out == '\"' || space(out)))
                {
#ifdef ENABLE_SMALL
                    msg(msglevel, "%sOptions warning: Bad backslash ('\\') usage in %s:%d",
                        error_prefix, file, line_num);
#else
                    msg(msglevel,
                        "%sOptions warning: Bad backslash ('\\') usage in %s:%d: remember that backslashes are treated as shell-escapes and if you need to pass backslash characters as part of a Windows filename, you should use double backslashes such as \"c:\\\\" PACKAGE
                        "\\\\static.key\"",
                        error_prefix, file, line_num);
#endif
                    return 0;
                }
            }
            backslash = false;
        }

        /* store parameter character */
        if (out)
        {
            if (parm_len >= SIZE(parm))
            {
                parm[SIZE(parm) - 1] = 0;
                msg(msglevel, "%sOptions error: Parameter at %s:%d is too long (%d chars max): %s",
                    error_prefix, file, line_num, (int)SIZE(parm), parm);
                return 0;
            }
            parm[parm_len++] = out;
        }

        /* avoid overflow if too many parms in one config file line */
        if (ret >= n)
        {
            break;
        }

    } while (*c++ != '\0');

    if (state == STATE_READING_QUOTED_PARM)
    {
        msg(msglevel, "%sOptions error: No closing quotation (\") in %s:%d", error_prefix, file,
            line_num);
        return 0;
    }
    if (state == STATE_READING_SQUOTED_PARM)
    {
        msg(msglevel, "%sOptions error: No closing single quotation (\') in %s:%d", error_prefix,
            file, line_num);
        return 0;
    }
    if (state != STATE_INITIAL)
    {
        msg(msglevel, "%sOptions error: Residual parse state (%d) in %s:%d", error_prefix, state,
            file, line_num);
        return 0;
    }
#if 0
    {
        int i;
        for (i = 0; i < ret; ++i)
        {
            msg(M_INFO|M_NOPREFIX, "%s:%d ARG[%d] '%s'", file, line_num, i, p[i]);
        }
    }
#endif
    return ret;
}

struct in_src
{
#define IS_TYPE_FP  1
#define IS_TYPE_BUF 2
    int type;
    union
    {
        FILE *fp;
        struct buffer *multiline;
    } u;
};

static bool
in_src_get(const struct in_src *is, char *line, const int size)
{
    if (is->type == IS_TYPE_FP)
    {
        return BOOL_CAST(fgets(line, size, is->u.fp));
    }
    else if (is->type == IS_TYPE_BUF)
    {
        bool status = buf_parse(is->u.multiline, '\n', line, size);
        if ((int)strlen(line) + 1 < size)
        {
            strcat(line, "\n");
        }
        return status;
    }
    else
    {
        ASSERT(0);
        return false;
    }
}

static char *
read_inline_file(struct in_src *is, const char *close_tag, int *num_lines, struct gc_arena *gc)
{
    char line[OPTION_LINE_SIZE];
    struct buffer buf = alloc_buf(8 * OPTION_LINE_SIZE);
    char *ret;
    bool endtagfound = false;

    while (in_src_get(is, line, sizeof(line)))
    {
        (*num_lines)++;
        char *line_ptr = line;
        /* Remove leading spaces */
        while (isspace(*line_ptr))
        {
            line_ptr++;
        }
        if (!strncmp(line_ptr, close_tag, strlen(close_tag)))
        {
            endtagfound = true;
            break;
        }
        if (!buf_safe(&buf, strlen(line) + 1))
        {
            /* Increase buffer size */
            struct buffer buf2 = alloc_buf(buf.capacity * 2);
            ASSERT(buf_copy(&buf2, &buf));
            buf_clear(&buf);
            free_buf(&buf);
            buf = buf2;
        }
        buf_printf(&buf, "%s", line);
    }
    if (!endtagfound)
    {
        msg(M_FATAL, "ERROR: Endtag %s missing", close_tag);
    }
    ret = string_alloc(BSTR(&buf), gc);
    buf_clear(&buf);
    free_buf(&buf);
    secure_memzero(line, sizeof(line));
    return ret;
}

static int
check_inline_file(struct in_src *is, char *p[], struct gc_arena *gc)
{
    int num_inline_lines = 0;

    if (p[0] && !p[1])
    {
        char *arg = p[0];
        if (arg[0] == '<' && arg[strlen(arg) - 1] == '>')
        {
            struct buffer close_tag;

            arg[strlen(arg) - 1] = '\0';
            p[0] = string_alloc(arg + 1, gc);
            close_tag = alloc_buf(strlen(p[0]) + 4);
            buf_printf(&close_tag, "</%s>", p[0]);
            p[1] = read_inline_file(is, BSTR(&close_tag), &num_inline_lines, gc);
            p[2] = NULL;
            free_buf(&close_tag);
        }
    }
    return num_inline_lines;
}

static int
check_inline_file_via_fp(FILE *fp, char *p[], struct gc_arena *gc)
{
    struct in_src is;
    is.type = IS_TYPE_FP;
    is.u.fp = fp;
    return check_inline_file(&is, p, gc);
}

static int
check_inline_file_via_buf(struct buffer *multiline, char *p[], struct gc_arena *gc)
{
    struct in_src is;
    is.type = IS_TYPE_BUF;
    is.u.multiline = multiline;
    return check_inline_file(&is, p, gc);
}

void
read_config_file(struct options *options, const char *file, int level, const char *top_file,
                 const int top_line, const msglvl_t msglevel,
                 const unsigned int permission_mask, unsigned int *option_types_found,
                 struct env_set *es)
{
    const int max_recursive_levels = 10;
    FILE *fp;
    int line_num;
    char line[OPTION_LINE_SIZE + 1];
    char *p[MAX_PARMS + 1];

    ++level;
    if (level <= max_recursive_levels)
    {
        if (streq(file, "stdin"))
        {
            fp = stdin;
        }
        else
        {
            fp = platform_fopen(file, "r");
        }
        if (fp)
        {
            line_num = 0;
            while (fgets(line, sizeof(line), fp))
            {
                int offset = 0;
                CLEAR(p);
                ++line_num;
                if (strlen(line) == OPTION_LINE_SIZE)
                {
                    msg(msglevel,
                        "In %s:%d: Maximum option line length (%d) exceeded, line starts with %s",
                        file, line_num, OPTION_LINE_SIZE, line);
                }

                /* Ignore UTF-8 BOM at start of stream */
                if (line_num == 1 && strncmp(line, "\xEF\xBB\xBF", 3) == 0)
                {
                    offset = 3;
                }
                if (parse_line(line + offset, p, SIZE(p) - 1, file, line_num, msglevel,
                               &options->gc))
                {
                    bypass_doubledash(&p[0]);
                    int lines_inline = check_inline_file_via_fp(fp, p, &options->gc);
                    add_option(options, p, lines_inline, file, line_num, level, msglevel,
                               permission_mask, option_types_found, es);
                    line_num += lines_inline;
                }
            }
            if (fp != stdin)
            {
                fclose(fp);
            }
        }
        else
        {
            msg(msglevel, "In %s:%d: Error opening configuration file: %s", top_file, top_line,
                file);
        }
    }
    else
    {
        msg(msglevel,
            "In %s:%d: Maximum recursive include levels exceeded in include attempt of file %s -- probably you have a configuration file that tries to include itself.",
            top_file, top_line, file);
    }
    secure_memzero(line, sizeof(line));
    CLEAR(p);
}

void
read_config_string(const char *prefix, struct options *options, const char *config,
                   const msglvl_t msglevel, const unsigned int permission_mask,
                   unsigned int *option_types_found, struct env_set *es)
{
    char line[OPTION_LINE_SIZE];
    struct buffer multiline;
    int line_num = 0;

    buf_set_read(&multiline, (uint8_t *)config, strlen(config));

    while (buf_parse(&multiline, '\n', line, sizeof(line)))
    {
        char *p[MAX_PARMS + 1];
        CLEAR(p);
        ++line_num;
        if (parse_line(line, p, SIZE(p) - 1, prefix, line_num, msglevel, &options->gc))
        {
            bypass_doubledash(&p[0]);
            int lines_inline = check_inline_file_via_buf(&multiline, p, &options->gc);
            add_option(options, p, lines_inline, prefix, line_num, 0, msglevel, permission_mask,
                       option_types_found, es);
            line_num += lines_inline;
        }
        CLEAR(p);
    }
    secure_memzero(line, sizeof(line));
}

void
parse_argv(struct options *options, const int argc, char *argv[], const msglvl_t msglevel,
           const unsigned int permission_mask, unsigned int *option_types_found, struct env_set *es)
{
    /* usage message */
    if (argc <= 1)
    {
        usage();
    }

    /* config filename specified only? */
    if (argc == 2 && strncmp(argv[1], "--", 2))
    {
        char *p[MAX_PARMS + 1];
        CLEAR(p);
        p[0] = "config";
        p[1] = argv[1];
        add_option(options, p, false, NULL, 0, 0, msglevel, permission_mask, option_types_found,
                   es);
    }
    else
    {
        /* parse command line */
        for (int i = 1; i < argc; ++i)
        {
            char *p[MAX_PARMS + 1];
            CLEAR(p);
            p[0] = argv[i];
            if (strncmp(p[0], "--", 2))
            {
                msg(msglevel,
                    "I'm trying to parse \"%s\" as an --option parameter but I don't see a leading '--'",
                    p[0]);
            }
            else
            {
                p[0] += 2;
            }

            int j;
            for (j = 1; j < MAX_PARMS; ++j)
            {
                if (i + j < argc)
                {
                    char *arg = argv[i + j];
                    if (strncmp(arg, "--", 2))
                    {
                        p[j] = arg;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            add_option(options, p, false, NULL, 0, 0, msglevel, permission_mask, option_types_found,
                       es);
            i += j - 1;
        }
    }
}

bool
apply_push_options(struct context *c, struct options *options, struct buffer *buf,
                   unsigned int permission_mask, unsigned int *option_types_found,
                   struct env_set *es, bool is_update)
{
    char line[OPTION_PARM_SIZE];
    int line_num = 0;
    const char *file = "[PUSH-OPTIONS]";
    const msglvl_t msglevel = D_PUSH_ERRORS | M_OPTERR;
    unsigned int update_options_found = 0;

    while (buf_parse(buf, ',', line, sizeof(line)))
    {
        char *p[MAX_PARMS + 1];
        CLEAR(p);
        ++line_num;
        unsigned int push_update_option_flags = 0;
        int i = 0;

        /* skip leading spaces matching the behaviour of parse_line */
        while (isspace(line[i]))
        {
            i++;
        }

        /* If we are not in a 'PUSH_UPDATE' we just check `apply_pull_filter()`
         * otherwise we must call `check_push_update_option_flags()` first
         */
        if ((is_update && !check_push_update_option_flags(line, &i, &push_update_option_flags))
            || !apply_pull_filter(options, &line[i]))
        {
            /* In case we are in a `PUSH_UPDATE` and `check_push_update_option_flags()`
             * or `apply_pull_filter()` fail but the option is flagged by `PUSH_OPT_OPTIONAL`,
             * instead of restarting, we just ignore the option and we process the next one
             */
            if (push_update_option_flags & PUSH_OPT_OPTIONAL)
            {
                continue; /* Ignoring this option */
            }
            return false; /* Cause push/pull error and stop push processing */
        }

        if (parse_line(&line[i], p, SIZE(p) - 1, file, line_num, msglevel, &options->gc))
        {
            if (!is_update)
            {
                add_option(options, p, false, file, line_num, 0, msglevel, permission_mask,
                           option_types_found, es);
            }
            else if (push_update_option_flags & PUSH_OPT_TO_REMOVE)
            {
                remove_option(c, options, p, false, file, line_num, msglevel, permission_mask,
                              option_types_found, es);
            }
            else
            {
                update_option(c, options, p, false, file, line_num, 0, msglevel, permission_mask,
                              option_types_found, es, &update_options_found);
            }
        }
    }
    return true;
}

void
options_server_import(struct options *o, const char *filename, msglvl_t msglevel,
                      unsigned int permission_mask, unsigned int *option_types_found,
                      struct env_set *es)
{
    msg(D_PUSH, "OPTIONS IMPORT: reading client specific options from: %s", filename);
    read_config_file(o, filename, 0, filename, 0, msglevel, permission_mask, option_types_found,
                     es);
}

void
options_string_import(struct options *options, const char *config, const msglvl_t msglevel,
                      const unsigned int permission_mask, unsigned int *option_types_found,
                      struct env_set *es)
{
    read_config_string("[CONFIG-STRING]", options, config, msglevel, permission_mask,
                       option_types_found, es);
}
