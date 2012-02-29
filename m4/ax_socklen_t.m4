dnl -- The following is base of curl's acinclude.m4 --
dnl Check for socklen_t: historically on BSD it is an int, and in
dnl POSIX 1g it is a type of its own, but some platforms use different
dnl types for the argument to getsockopt, getpeername, etc.  So we
dnl have to test to find something that will work.
AC_DEFUN([AX_TYPE_SOCKLEN_T], [
	AC_CHECK_TYPE(
		[socklen_t],
		,
		[
			AS_VAR_PUSHDEF([VAR],[ax_cv_socklen_t_equiv])dnl
			AC_CACHE_CHECK(
				[for socklen_t equivalent],
				[VAR],
				[
					#AS_CASE is not supported on <autoconf-2.60
					case "${host}" in
					*-mingw*) VAR=int ;;
					*)
						# Systems have either "struct sockaddr *" or
						# "void *" as the second argument to getpeername
						for arg2 in "struct sockaddr" void; do
							for t in int size_t unsigned long "unsigned long"; do
								AC_COMPILE_IFELSE(
									[AC_LANG_PROGRAM(
										[[
#include <sys/types.h>
#include <sys/socket.h>
int getpeername (int, $arg2 *, $t *);
										]],
										[[
$t len;
getpeername(0,0,&len);
										]]
									)],
									[VAR="$t"; break]
								)
							done
							test -n "$VAR" && break
						done
						;;
					esac
				]
				AS_VAR_IF(
					[VAR],
					[],
					[AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])],
					[AC_DEFINE_UNQUOTED(
						[socklen_t],
						[$VAR],
						[type to use in place of socklen_t if not defined]
					)]
				)
			)
		],
		[[
#include <sys/types.h>
#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif
		]]
	)
])
