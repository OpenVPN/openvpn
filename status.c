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

#include "syshead.h"

#include "status.h"
#include "perf.h"

#include "memdbg.h"

/*
 * printf-style interface for outputting status info
 */

static const char *
print_status_mode (unsigned int flags)
{
  switch (flags)
    {
    case STATUS_OUTPUT_WRITE:
      return "WRITE";
    case STATUS_OUTPUT_READ:
      return "READ";
    case STATUS_OUTPUT_READ|STATUS_OUTPUT_WRITE:
      return "READ/WRITE";
    default:
      return "UNDEF";
    }
}

struct status_output *
status_open (const char *filename,
	     const int refresh_freq,
	     const int msglevel,
	     const struct virtual_output *vout,
	     const unsigned int flags)
{
  struct status_output *so = NULL;
  if (filename || msglevel >= 0 || vout)
    {
      ALLOC_OBJ_CLEAR (so, struct status_output);
      so->flags = flags;
      so->msglevel = msglevel;
      so->vout = vout;
      so->fd = -1;
      buf_reset (&so->read_buf);
      event_timeout_clear (&so->et);
      if (filename)
	{
	  switch (so->flags)
	    {
#ifdef _MSC_VER
            case STATUS_OUTPUT_WRITE:
              so->fd = open (filename,
                             O_CREAT | O_TRUNC | O_WRONLY,
			     _S_IREAD | _S_IWRITE);
              break;
            case STATUS_OUTPUT_READ:
              so->fd = open (filename,
                             O_RDONLY,
			     _S_IREAD | _S_IWRITE);
              break;
            case STATUS_OUTPUT_READ|STATUS_OUTPUT_WRITE:
              so->fd = open (filename,
                             O_CREAT | O_RDWR,
			     _S_IREAD | _S_IWRITE);
              break;
#else
	    case STATUS_OUTPUT_WRITE:
	      so->fd = open (filename,
			     O_CREAT | O_TRUNC | O_WRONLY,
			     S_IRUSR | S_IWUSR);
	      break;
	    case STATUS_OUTPUT_READ:
	      so->fd = open (filename,
			     O_RDONLY,
			     S_IRUSR | S_IWUSR);
	      break;
	    case STATUS_OUTPUT_READ|STATUS_OUTPUT_WRITE:
	      so->fd = open (filename,
			     O_CREAT | O_RDWR,
			     S_IRUSR | S_IWUSR);
	      break;
#endif
	    default:
	      ASSERT (0);
	    }
	  if (so->fd >= 0)
	    {
	      so->filename = string_alloc (filename, NULL);

	      /* allocate read buffer */
	      if (so->flags & STATUS_OUTPUT_READ)
		so->read_buf = alloc_buf (512);
	    }
	  else
	    {
	      msg (M_WARN, "Note: cannot open %s for %s", filename, print_status_mode (so->flags));
	      so->errors = true;
	    }
	}
      else
	so->flags = STATUS_OUTPUT_WRITE;

      if ((so->flags & STATUS_OUTPUT_WRITE) && refresh_freq > 0)
	{
	  event_timeout_init (&so->et, refresh_freq, 0);
	}
    }
  return so;
}

bool
status_trigger (struct status_output *so)
{
  if (so)
    {
      struct timeval null;
      CLEAR (null);
      return event_timeout_trigger (&so->et, &null, ETT_DEFAULT);
    }
  else
    return false;
}

bool
status_trigger_tv (struct status_output *so, struct timeval *tv)
{
  if (so)
    return event_timeout_trigger (&so->et, tv, ETT_DEFAULT);
  else
    return false;
}

void
status_reset (struct status_output *so)
{
  if (so && so->fd >= 0)
    lseek (so->fd, (off_t)0, SEEK_SET);
}

void
status_flush (struct status_output *so)
{
  if (so && so->fd >= 0 && (so->flags & STATUS_OUTPUT_WRITE))
    {
#if defined(HAVE_FTRUNCATE)
      {
	const off_t off = lseek (so->fd, (off_t)0, SEEK_CUR);
	if (ftruncate (so->fd, off) != 0) {
	  msg (M_WARN, "Failed to truncate status file: %s", strerror(errno));
	}
      }
#elif defined(HAVE_CHSIZE)
      {
	const long off = (long) lseek (so->fd, (off_t)0, SEEK_CUR);
	chsize (so->fd, off);
      }
#else
#warning both ftruncate and chsize functions appear to be missing from this OS
#endif

      /* clear read buffer */
      if (buf_defined (&so->read_buf))
	{
	  ASSERT (buf_init (&so->read_buf, 0));
	}
    }
}

/* return false if error occurred */
bool
status_close (struct status_output *so)
{
  bool ret = true;
  if (so)
    {
      if (so->errors)
	ret = false;
      if (so->fd >= 0)
	{
	  if (close (so->fd) < 0)
	    ret = false;
	}
      if (so->filename)
	free (so->filename);
      if (buf_defined (&so->read_buf))
	free_buf (&so->read_buf);
      free (so);
    }
  else
    ret = false;
  return ret;
}

#define STATUS_PRINTF_MAXLEN 512

void
status_printf (struct status_output *so, const char *format, ...)
{
  if (so && (so->flags & STATUS_OUTPUT_WRITE))
    {
      char buf[STATUS_PRINTF_MAXLEN+2]; /* leave extra bytes for CR, LF */
      va_list arglist;
      int stat;

      va_start (arglist, format);
      stat = vsnprintf (buf, STATUS_PRINTF_MAXLEN, format, arglist);
      va_end (arglist);
      buf[STATUS_PRINTF_MAXLEN - 1] = 0;

      if (stat < 0 || stat >= STATUS_PRINTF_MAXLEN)
	so->errors = true;

      if (so->msglevel >= 0 && !so->errors)
	msg (so->msglevel, "%s", buf);

      if (so->fd >= 0 && !so->errors)
	{
	  int len;
	  strcat (buf, "\n");
	  len = strlen (buf);
	  if (len > 0)
	    {
	      if (write (so->fd, buf, len) != len)
		so->errors = true;
	    }
	}

      if (so->vout && !so->errors)
	{
	  chomp (buf);
	  (*so->vout->func) (so->vout->arg, so->vout->flags_default, buf);
	}
    }
}

bool
status_read (struct status_output *so, struct buffer *buf)
{
  bool ret = false;

  if (so && so->fd >= 0 && (so->flags & STATUS_OUTPUT_READ))
    {
      ASSERT (buf_defined (&so->read_buf));      
      ASSERT (buf_defined (buf));
      while (true)
	{
	  const int c = buf_read_u8 (&so->read_buf);

	  /* read more of file into buffer */
	  if (c == -1)
	    {
	      int len;

	      ASSERT (buf_init (&so->read_buf, 0));
	      len = read (so->fd, BPTR (&so->read_buf), BCAP (&so->read_buf));
	      if (len <= 0)
		break;

	      ASSERT (buf_inc_len (&so->read_buf, len));
	      continue;
	    }

	  ret = true;

	  if (c == '\r')
	    continue;

	  if (c == '\n')
	    break;

	  buf_write_u8 (buf, c);
	}

      buf_null_terminate (buf);
    }

  return ret;
}
