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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "win32.h"

#include "memdbg.h"

#include "platform.h"

/* Redefine the top level directory of the filesystem
   to restrict access to files for security */
void
platform_chroot (const char *path)
{
  if (path)
    {
#ifdef HAVE_CHROOT
      const char *top = "/";
      if (chroot (path))
	msg (M_ERR, "chroot to '%s' failed", path);
      if (platform_chdir (top))
	msg (M_ERR, "cd to '%s' failed", top);
      msg (M_INFO, "chroot to '%s' and cd to '%s' succeeded", path, top);
#else
      msg (M_FATAL, "Sorry but I can't chroot to '%s' because this operating system doesn't appear to support the chroot() system call", path);
#endif
    }
}

/* Get/Set UID of process */

bool
platform_user_get (const char *username, struct platform_state_user *state)
{
  bool ret = false;
  CLEAR (*state);
  if (username)
    {
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
      state->pw = getpwnam (username);
      if (!state->pw)
	msg (M_ERR, "failed to find UID for user %s", username);
      state->username = username;
      ret = true;
#else
      msg (M_FATAL, "cannot get UID for user %s -- platform lacks getpwname() or setuid() system calls", username);
#endif
    }
  return ret;
}

void
platform_user_set (const struct platform_state_user *state)
{
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
  if (state->username && state->pw)
    {
      if (setuid (state->pw->pw_uid))
	msg (M_ERR, "setuid('%s') failed", state->username);
      msg (M_INFO, "UID set to %s", state->username);
    }
#endif
}

/* Get/Set GID of process */

bool
platform_group_get (const char *groupname, struct platform_state_group *state)
{
  bool ret = false;
  CLEAR (*state);
  if (groupname)
    {
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
      state->gr = getgrnam (groupname);
      if (!state->gr)
	msg (M_ERR, "failed to find GID for group %s", groupname);
      state->groupname = groupname;
      ret = true;
#else
      msg (M_FATAL, "cannot get GID for group %s -- platform lacks getgrnam() or setgid() system calls", groupname);
#endif
    }
  return ret;
}

void
platform_group_set (const struct platform_state_group *state)
{
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
  if (state->groupname && state->gr)
    {
      if (setgid (state->gr->gr_gid))
	msg (M_ERR, "setgid('%s') failed", state->groupname);
      msg (M_INFO, "GID set to %s", state->groupname);
#ifdef HAVE_SETGROUPS
      {
        gid_t gr_list[1];
	gr_list[0] = state->gr->gr_gid;
	if (setgroups (1, gr_list))
	  msg (M_ERR, "setgroups('%s') failed", state->groupname);
      }
#endif
    }
#endif
}

/* Change process priority */
void
platform_nice (int niceval)
{
  if (niceval)
    {
#ifdef HAVE_NICE
      errno = 0;
      if (nice (niceval) < 0 && errno != 0)
	msg (M_WARN | M_ERRNO, "WARNING: nice %d failed: %s", niceval, strerror(errno));
      else
	msg (M_INFO, "nice %d succeeded", niceval);
#else
      msg (M_WARN, "WARNING: nice %d failed (function not implemented)", niceval);
#endif
    }
}

/* Get current PID */
unsigned int
platform_getpid ()
{
#ifdef WIN32
  return (unsigned int) GetCurrentProcessId ();
#else
#ifdef HAVE_GETPID
  return (unsigned int) getpid ();
#else
  return 0;
#endif
#endif
}

/* Disable paging */
void
platform_mlockall(bool print_msg)
{
#ifdef HAVE_MLOCKALL
  if (mlockall (MCL_CURRENT | MCL_FUTURE))
    msg (M_WARN | M_ERRNO, "WARNING: mlockall call failed");
  else if (print_msg)
    msg (M_INFO, "mlockall call succeeded");
#else
  msg (M_WARN, "WARNING: mlockall call failed (function not implemented)");
#endif
}

/*
 * Wrapper for chdir library function
 */
int
platform_chdir (const char* dir)
{
#ifdef HAVE_CHDIR
#ifdef WIN32
  int res;
  struct gc_arena gc = gc_new ();
  res = _wchdir (wide_string (dir, &gc));
  gc_free (&gc);
  return res;
#else
  return chdir (dir);
#endif
#else
  return -1;
#endif
}

/*
 * convert execve() return into a success/failure value
 */
bool
platform_system_ok (int stat)
{
#ifdef WIN32
  return stat == 0;
#else
  return stat != -1 && WIFEXITED (stat) && WEXITSTATUS (stat) == 0;
#endif
}

int
platform_access (const char *path, int mode)
{
#ifdef WIN32
  struct gc_arena gc = gc_new ();
  int ret = _waccess (wide_string (path, &gc), mode & ~X_OK);
  gc_free (&gc);
  return ret;
#else
  return access (path, mode);
#endif
}

/*
 * Go to sleep for n milliseconds.
 */
void
platform_sleep_milliseconds (unsigned int n)
{
#ifdef WIN32
  Sleep (n);
#else
  struct timeval tv;
  tv.tv_sec = n / 1000;
  tv.tv_usec = (n % 1000) * 1000;
  select (0, NULL, NULL, NULL, &tv);
#endif
}

/*
 * Go to sleep indefinitely.
 */
void
platform_sleep_until_signal (void)
{
#ifdef WIN32
  ASSERT (0);
#else
  select (0, NULL, NULL, NULL, NULL);
#endif
}

/* delete a file, return true if succeeded */
bool
platform_unlink (const char *filename)
{
#if defined(WIN32)
  struct gc_arena gc = gc_new ();
  BOOL ret = DeleteFileW (wide_string (filename, &gc));
  gc_free (&gc);
  return (ret != 0);
#elif defined(HAVE_UNLINK)
  return (unlink (filename) == 0);
#else
  return false;
#endif
}

FILE *
platform_fopen (const char *path, const char *mode)
{
#ifdef WIN32
  struct gc_arena gc = gc_new ();
  FILE *f = _wfopen (wide_string (path, &gc), wide_string (mode, &gc));
  gc_free (&gc);
  return f;
#else
  return fopen(path, mode);
#endif
}

int
platform_open (const char *path, int flags, int mode)
{
#ifdef WIN32
  struct gc_arena gc = gc_new ();
  int fd = _wopen (wide_string (path, &gc), flags, mode);
  gc_free (&gc);
  return fd;
#else
  return open(path, flags, mode);
#endif
}

int
platform_stat (const char *path, platform_stat_t *buf)
{
#ifdef WIN32
  struct gc_arena gc = gc_new ();
  int res = _wstat (wide_string (path, &gc), buf);
  gc_free (&gc);
  return res;
#else
  return stat(path, buf);
#endif
}

