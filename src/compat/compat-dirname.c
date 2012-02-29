/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2011 - David Sommerseth <davids@redhat.com>
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


#ifndef HAVE_DIRNAME

#include "compat.h"
#include <string.h>

/* Unoptimised version of glibc memrchr().
 * This is considered fast enough, as only this compat
 * version of dirname() depends on it.
 */
static const char *
__memrchr(const char *str, int c, size_t n)
{
  const char *end = str;

  end += n - 1; /* Go to the end of the string */
  while (end >= str) {
    if(c == *end)
      return end;
    else
      end--;
  }
  return NULL;
}

/* Modified version based on glibc-2.14.1 by Ulrich Drepper <drepper@akkadia.org>
 * This version is extended to handle both / and \ in path names.
 */
char *
dirname (char *path)
{
  static const char dot[] = ".";
  char *last_slash;
  char separator = '/';

  /* Find last '/'.  */
  last_slash = path != NULL ? strrchr (path, '/') : NULL;
  /* If NULL, check for \ instead ... might be Windows a path */
  if (!last_slash) {
    last_slash = path != NULL ? strrchr (path, '\\') : NULL;
    separator = last_slash ? '\\' : '/';  /* Change the separator if \ was found */
  }

  if (last_slash != NULL && last_slash != path && last_slash[1] == '\0') {
      /* Determine whether all remaining characters are slashes.  */
      char *runp;

      for (runp = last_slash; runp != path; --runp)
	if (runp[-1] != separator)
	  break;

      /* The '/' is the last character, we have to look further.  */
      if (runp != path)
	last_slash = (char *) __memrchr (path, separator, runp - path);
    }

  if (last_slash != NULL) {
      /* Determine whether all remaining characters are slashes.  */
      char *runp;

      for (runp = last_slash; runp != path; --runp)
	if (runp[-1] != separator)
	  break;

      /* Terminate the path.  */
      if (runp == path) {
	  /* The last slash is the first character in the string.  We have to
	     return "/".  As a special case we have to return "//" if there
	     are exactly two slashes at the beginning of the string.  See
	     XBD 4.10 Path Name Resolution for more information.  */
	  if (last_slash == path + 1)
	    ++last_slash;
	  else
	    last_slash = path + 1;
	}
      else
	last_slash = runp;

      last_slash[0] = '\0';
  } else
    /* This assignment is ill-designed but the XPG specs require to
       return a string containing "." in any case no directory part is
       found and so a static and constant string is required.  */
    path = (char *) dot;

  return path;
}

#endif /* HAVE_DIRNAME */
