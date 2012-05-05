dnl  OpenVPN -- An application to securely tunnel IP networks
dnl             over a single UDP port, with support for SSL/TLS-based
dnl             session authentication and key exchange,
dnl             packet encryption, packet authentication, and
dnl             packet compression.
dnl
dnl  Copyright (C) 2008-2012 Alon Bar-Lev <alon.barlev@gmail.com>
dnl
dnl  This program is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation; either version 2 of the License, or
dnl  (at your option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program (see the file COPYING included with this
dnl  distribution); if not, write to the Free Software Foundation, Inc.,
dnl  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

dnl Compatibility layer for <autoconf-2.60 <automake-1.10
dnl REMOVE THIS IN FUTURE!

ifdef(
	[AS_VAR_IF],
	,
	[
		AC_DEFUN([AS_VAR_IF], [dnl
			if test "$$1" = "$2"; then
				m4_ifval([$3], [$3], [:])
			else
				m4_ifval([$4], [$4], [:])
			fi
		])
	]
)
ifdef(
	[AC_USE_SYSTEM_EXTENSIONS],
	,
	[AC_DEFUN([AC_USE_SYSTEM_EXTENSIONS], [GNU_SOURCE])]
)
ifdef(
	[AC_PROG_SED],
	,
	[AC_DEFUN([AC_PROG_SED], [AC_CHECK_PROGS([SED], [sed])])]
)
ifdef(
	[AC_TYPE_INT8_T],
	,
	[
		AC_CHECK_HEADERS([inttypes.h stdint.h])
		test -z "${ac_cv_header_inttypes_h}${ac_cv_header_stdint_h}" && \
			AC_MSG_ERROR([Required inttypes.h stdint.h not found])
		
		AC_DEFUN([AC_TYPE_INT8_T], [])
		AC_DEFUN([AC_TYPE_INT16_T], [])
		AC_DEFUN([AC_TYPE_INT32_T], [])
		AC_DEFUN([AC_TYPE_INT64_T], [])
		AC_DEFUN([AC_TYPE_UINT8_T], [])
		AC_DEFUN([AC_TYPE_UINT16_T], [])
		AC_DEFUN([AC_TYPE_UINT32_T], [])
		AC_DEFUN([AC_TYPE_UINT64_T], [])
	]
)
if test -z "${docdir}"; then
	docdir="\$(datadir)/doc/\$(PACKAGE_NAME)"
	AC_SUBST([docdir])
fi
if test -z "${htmldir}"; then
	htmldir="\$(docdir)"
	AC_SUBST([htmldir])
fi
