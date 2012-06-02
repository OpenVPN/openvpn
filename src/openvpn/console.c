/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "console.h"
#include "error.h"
#include "buffer.h"
#include "misc.h"

#ifdef WIN32

#include "win32.h"

/*
 * Get input from console.
 *
 * Return false on input error, or if service
 * exit event is signaled.
 */

static bool
get_console_input_win32 (const char *prompt, const bool echo, char *input, const int capacity)
{
  HANDLE in = INVALID_HANDLE_VALUE;
  HANDLE err = INVALID_HANDLE_VALUE;
  DWORD len = 0;

  ASSERT (prompt);
  ASSERT (input);
  ASSERT (capacity > 0);

  input[0] = '\0';

  in = GetStdHandle (STD_INPUT_HANDLE);
  err = get_orig_stderr ();

  if (in != INVALID_HANDLE_VALUE
      && err != INVALID_HANDLE_VALUE
      && !win32_service_interrupt (&win32_signal)
      && WriteFile (err, prompt, strlen (prompt), &len, NULL))
    {
      bool is_console = (GetFileType (in) == FILE_TYPE_CHAR);
      DWORD flags_save = 0;
      int status = 0;
      WCHAR *winput;

      if (is_console)
	{
	  if (GetConsoleMode (in, &flags_save))
	    {
	      DWORD flags = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
	      if (echo)
		flags |= ENABLE_ECHO_INPUT;
	      SetConsoleMode (in, flags);
	    }
	  else
	    is_console = 0;
	}

      if (is_console)
        {
          winput = malloc (capacity * sizeof (WCHAR));
          if (winput == NULL)
            return false;

          status = ReadConsoleW (in, winput, capacity, &len, NULL);
          WideCharToMultiByte (CP_UTF8, 0, winput, len, input, capacity, NULL, NULL);
          free (winput);
        }
      else
        status = ReadFile (in, input, capacity, &len, NULL);

      string_null_terminate (input, (int)len, capacity);
      chomp (input);

      if (!echo)
	WriteFile (err, "\r\n", 2, &len, NULL);
      if (is_console)
	SetConsoleMode (in, flags_save);
      if (status && !win32_service_interrupt (&win32_signal))
	return true;
    }

  return false;
}

#endif

#ifdef HAVE_GETPASS

static FILE *
open_tty (const bool write)
{
  FILE *ret;
  ret = fopen ("/dev/tty", write ? "w" : "r");
  if (!ret)
    ret = write ? stderr : stdin;
  return ret;
}

static void
close_tty (FILE *fp)
{
  if (fp != stderr && fp != stdin)
    fclose (fp);
}

#endif

#ifdef ENABLE_SYSTEMD

/*
 * is systemd running
 */

static bool
check_systemd_running ()
{
  struct stat a, b;

  /* We simply test whether the systemd cgroup hierarchy is
   * mounted */

  return (lstat("/sys/fs/cgroup", &a) == 0)
	  && (lstat("/sys/fs/cgroup/systemd", &b) == 0)
	  && (a.st_dev != b.st_dev);

}

static bool
get_console_input_systemd (const char *prompt, const bool echo, char *input, const int capacity)
{
  int std_out;
  bool ret = false;
  struct argv argv;

  argv_init (&argv);
  argv_printf (&argv, "/bin/systemd-ask-password");
  argv_printf_cat (&argv, "%s", prompt);

  if ((std_out = openvpn_popen (&argv, NULL)) < 0) {
	  return false;
  }
  CLEAR (*input);
  if (read (std_out, input, capacity) != 0)
    {
       chomp (input);
       ret = true;
    }
  close (std_out);

  argv_reset (&argv);

  return ret;
}


#endif

/*
 * Get input from console
 */
bool
get_console_input (const char *prompt, const bool echo, char *input, const int capacity)
{
  bool ret = false;
  ASSERT (prompt);
  ASSERT (input);
  ASSERT (capacity > 0);
  input[0] = '\0';

#ifdef ENABLE_SYSTEMD
  if (check_systemd_running ())
    return get_console_input_systemd (prompt, echo, input, capacity);
#endif

#if defined(WIN32)
  return get_console_input_win32 (prompt, echo, input, capacity);
#elif defined(HAVE_GETPASS)
  if (echo)
    {
      FILE *fp;

      fp = open_tty (true);
      fprintf (fp, "%s", prompt);
      fflush (fp);
      close_tty (fp);

      fp = open_tty (false);
      if (fgets (input, capacity, fp) != NULL)
	{
	  chomp (input);
	  ret = true;
	}
      close_tty (fp);
    }
  else
    {
      char *gp = getpass (prompt);
      if (gp)
	{
	  strncpynt (input, gp, capacity);
	  memset (gp, 0, strlen (gp));
	  ret = true;
	}
    }
#else
  msg (M_FATAL, "Sorry, but I can't get console input on this OS (%s)", prompt);
#endif
  return ret;
}
