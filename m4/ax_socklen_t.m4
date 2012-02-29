dnl -- The following is taken from curl's acinclude.m4 --
dnl Check for socklen_t: historically on BSD it is an int, and in
dnl POSIX 1g it is a type of its own, but some platforms use different
dnl types for the argument to getsockopt, getpeername, etc.  So we
dnl have to test to find something that will work.
AC_DEFUN([TYPE_SOCKLEN_T],
[
   AC_CHECK_TYPE([socklen_t], ,[
      AC_MSG_CHECKING([for socklen_t equivalent])
      AC_CACHE_VAL([curl_cv_socklen_t_equiv],
      [
         case "$host" in
	 *-mingw*) curl_cv_socklen_t_equiv=int ;;
	 *)
            # Systems have either "struct sockaddr *" or
            # "void *" as the second argument to getpeername
            curl_cv_socklen_t_equiv=
            for arg2 in "struct sockaddr" void; do
               for t in int size_t unsigned long "unsigned long"; do
                  AC_TRY_COMPILE([
                     #include <sys/types.h>
                     #include <sys/socket.h>

                     int getpeername (int, $arg2 *, $t *);
                  ],[
                     $t len;
                     getpeername(0,0,&len);
                  ],[
                     curl_cv_socklen_t_equiv="$t"
                     break
                  ])
               done
            done
	 ;;
	 esac

         if test "x$curl_cv_socklen_t_equiv" = x; then
            AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])
         fi
      ])
      AC_MSG_RESULT($curl_cv_socklen_t_equiv)
      AC_DEFINE_UNQUOTED(socklen_t, $curl_cv_socklen_t_equiv,
			[type to use in place of socklen_t if not defined])],
      [#include <sys/types.h>
#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif])
])
