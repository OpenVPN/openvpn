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
 *
 *
 *  A printf-like function (that only recognizes a subset of standard printf
 *  format operators) that prints arguments to an argv list instead
 *  of a standard string.  This is used to build up argv arrays for passing
 *  to execve.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "argv.h"
#include "options.h"

void
argv_init (struct argv *a)
{
  a->capacity = 0;
  a->argc = 0;
  a->argv = NULL;
  a->system_str = NULL;
}

struct argv
argv_new (void)
{
  struct argv ret;
  argv_init (&ret);
  return ret;
}

void
argv_reset (struct argv *a)
{
  size_t i;
  for (i = 0; i < a->argc; ++i)
    free (a->argv[i]);
  free (a->argv);
  free (a->system_str);
  argv_init (a);
}

static void
argv_extend (struct argv *a, const size_t newcap)
{
  if (newcap > a->capacity)
    {
      char **newargv;
      size_t i;
      ALLOC_ARRAY_CLEAR (newargv, char *, newcap);
      for (i = 0; i < a->argc; ++i)
        newargv[i] = a->argv[i];
      free (a->argv);
      a->argv = newargv;
      a->capacity = newcap;
    }
}

static void
argv_grow (struct argv *a, const size_t add)
{
  const size_t newargc = a->argc + add + 1;
  ASSERT (newargc > a->argc);
  argv_extend (a, adjust_power_of_2 (newargc));
}

static void
argv_append (struct argv *a, char *str) /* str must have been malloced or be NULL */
{
  argv_grow (a, 1);
  a->argv[a->argc++] = str;
}

static void
argv_system_str_append (struct argv *a, const char *str, const bool enquote)
{
  if (str)
    {
      char *newstr;

      /* compute length of new system_str */
      size_t l = strlen (str) + 1; /* space for new string plus trailing '\0' */
      if (a->system_str)
        l += strlen (a->system_str) + 1; /* space for existing string + space (" ") separator */
      if (enquote)
        l += 2; /* space for two quotes */

      /* build new system_str */
      newstr = (char *) malloc (l);
      newstr[0] = '\0';
      check_malloc_return (newstr);
      if (a->system_str)
        {
          strcpy (newstr, a->system_str);
          strcat (newstr, " ");
        }
      if (enquote)
        strcat (newstr, "\"");
      strcat (newstr, str);
      if (enquote)
        strcat (newstr, "\"");
      free (a->system_str);
      a->system_str = newstr;
    }
}

static char *
argv_extract_cmd_name (const char *path)
{
  char *ret = NULL;
  if (path)
    {
      char *path_cp = string_alloc(path, NULL); /* POSIX basename() implementaions may modify its arguments */
      const char *bn = basename (path_cp);
      if (bn)
        {
          char *dot = NULL;
          ret = string_alloc (bn, NULL);
          dot = strrchr (ret, '.');
          if (dot)
            *dot = '\0';
          free(path_cp);
          if (ret[0] == '\0')
            {
              free(ret);
              ret = NULL;
            }
        }
    }
  return ret;
}

const char *
argv_system_str (const struct argv *a)
{
  return a->system_str;
}

static struct argv
argv_clone (const struct argv *a, const size_t headroom)
{
  struct argv r;
  size_t i;

  argv_init (&r);
  for (i = 0; i < headroom; ++i)
    argv_append (&r, NULL);
  if (a)
    {
      for (i = 0; i < a->argc; ++i)
        argv_append (&r, string_alloc (a->argv[i], NULL));
      r.system_str = string_alloc (a->system_str, NULL);
    }
  return r;
}

struct argv
argv_insert_head (const struct argv *a, const char *head)
{
  struct argv r;
  char *s;

  r = argv_clone (a, 1);
  r.argv[0] = string_alloc (head, NULL);
  s = r.system_str;
  r.system_str = string_alloc (head, NULL);
  if (s)
    {
      argv_system_str_append (&r, s, false);
      free (s);
    }
  return r;
}

char *
argv_term (const char **f)
{
  const char *p = *f;
  const char *term = NULL;
  size_t termlen = 0;

  if (*p == '\0')
    return NULL;

  while (true)
    {
      const int c = *p;
      if (c == '\0')
        break;
      if (term)
        {
          if (!isspace (c))
            ++termlen;
          else
            break;
        }
      else
        {
          if (!isspace (c))
            {
              term = p;
              termlen = 1;
            }
        }
      ++p;
    }
  *f = p;

  if (term)
    {
      char *ret;
      ASSERT (termlen > 0);
      ret = malloc (termlen + 1);
      check_malloc_return (ret);
      memcpy (ret, term, termlen);
      ret[termlen] = '\0';
      return ret;
    }
  else
    return NULL;
}

const char *
argv_str (const struct argv *a, struct gc_arena *gc, const unsigned int flags)
{
  if (a->argv)
    return print_argv ((const char **)a->argv, gc, flags);
  else
    return "";
}

void
argv_msg (const int msglev, const struct argv *a)
{
  struct gc_arena gc = gc_new ();
  msg (msglev, "%s", argv_str (a, &gc, 0));
  gc_free (&gc);
}

void
argv_msg_prefix (const int msglev, const struct argv *a, const char *prefix)
{
  struct gc_arena gc = gc_new ();
  msg (msglev, "%s: %s", prefix, argv_str (a, &gc, 0));
  gc_free (&gc);
}

void
argv_printf (struct argv *a, const char *format, ...)
{
  va_list arglist;
  va_start (arglist, format);
  argv_printf_arglist (a, format, 0, arglist);
  va_end (arglist);
 }

void
argv_printf_cat (struct argv *a, const char *format, ...)
{
  va_list arglist;
  va_start (arglist, format);
  argv_printf_arglist (a, format, APA_CAT, arglist);
  va_end (arglist);
}

void
argv_printf_arglist (struct argv *a, const char *format, const unsigned int flags, va_list arglist)
{
  struct gc_arena gc = gc_new ();
  char *term;
  const char *f = format;

  if (!(flags & APA_CAT))
    argv_reset (a);
  argv_extend (a, 1); /* ensure trailing NULL */

  while ((term = argv_term (&f)) != NULL)
    {
      if (term[0] == '%')
        {
          if (!strcmp (term, "%s"))
            {
              char *s = va_arg (arglist, char *);
              if (!s)
                s = "";
              argv_append (a, string_alloc (s, NULL));
              argv_system_str_append (a, s, true);
            }
          else if (!strcmp (term, "%sc"))
            {
              char *s = va_arg (arglist, char *);
              if (s)
                {
                  int nparms;
                  char *parms[MAX_PARMS+1];
                  int i;

                  nparms = parse_line (s, parms, MAX_PARMS, "SCRIPT-ARGV", 0, D_ARGV_PARSE_CMD, &gc);
                  if (nparms)
                    {
                      for (i = 0; i < nparms; ++i)
                        argv_append (a, string_alloc (parms[i], NULL));
                    }
                  else
                    argv_append (a, string_alloc (s, NULL));

                  argv_system_str_append (a, s, false);
                }
              else
                {
                  argv_append (a, string_alloc ("", NULL));
                  argv_system_str_append (a, "echo", false);
                }
            }
          else if (!strcmp (term, "%d"))
            {
              char numstr[64];
              openvpn_snprintf (numstr, sizeof (numstr), "%d", va_arg (arglist, int));
              argv_append (a, string_alloc (numstr, NULL));
              argv_system_str_append (a, numstr, false);
            }
          else if (!strcmp (term, "%u"))
            {
              char numstr[64];
              openvpn_snprintf (numstr, sizeof (numstr), "%u", va_arg (arglist, unsigned int));
              argv_append (a, string_alloc (numstr, NULL));
              argv_system_str_append (a, numstr, false);
            }
          else if (!strcmp (term, "%s/%d"))
            {
              char numstr[64];
              char *s = va_arg (arglist, char *);

              if (!s)
                s = "";

              openvpn_snprintf (numstr, sizeof (numstr), "%d", va_arg (arglist, int));

              {
                const size_t len = strlen(s) + strlen(numstr) + 2;
                char *combined = (char *) malloc (len);
                check_malloc_return (combined);

                strcpy (combined, s);
                strcat (combined, "/");
                strcat (combined, numstr);
                argv_append (a, combined);
                argv_system_str_append (a, combined, false);
              }
            }
          else if (!strcmp (term, "%s%sc"))
            {
              char *s1 = va_arg (arglist, char *);
              char *s2 = va_arg (arglist, char *);
              char *combined;
              char *cmd_name;

              if (!s1) s1 = "";
              if (!s2) s2 = "";
              combined = (char *) malloc (strlen(s1) + strlen(s2) + 1);
              check_malloc_return (combined);
              strcpy (combined, s1);
              strcat (combined, s2);
              argv_append (a, combined);

              cmd_name = argv_extract_cmd_name (combined);
              if (cmd_name)
                {
                  argv_system_str_append (a, cmd_name, false);
                  free (cmd_name);
                }
            }
          else
            ASSERT (0);
          free (term);
        }
      else
        {
          argv_append (a, term);
          argv_system_str_append (a, term, false);
        }
    }
  gc_free (&gc);
}
