/* memcmp.c -- Replacement memcmp.c
 *
 * Useful on systems that don't have a working memcmp, such as SunOS
 * 4.1.3 and NeXT x86 OpenStep.
 *
 * Copyright (C) 2002 - 2003 Matthias Andree <matthias.andree@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <string.h>

int
memcmp (const void *s1, const void *s2, size_t n)
{
	register unsigned const char *p1 = s1, *p2 = s2;
	int d;

	if (n)
		while (n-- > 0)
		  {
			  d = *p1++ - *p2++;
			  if (d != 0)
				  return d;
		  }
	return 0;
}
