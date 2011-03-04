dnl Special Autoconf Macros for OpenVPN

dnl OPENVPN_ADD_LIBS(LIB)
AC_DEFUN([OPENVPN_ADD_LIBS], [
  LIBS="$1 $LIBS"
])

dnl @synopsis AX_EMPTY_ARRAY
dnl
dnl Define EMPTY_ARRAY_SIZE to be either "0"
dnl or "" depending on which syntax the compiler
dnl prefers for empty arrays in structs.
dnl
dnl @version
dnl @author James Yonan <jim@yonan.net>


AC_DEFUN([AX_EMPTY_ARRAY], [
  AC_MSG_RESULT([checking for C compiler empty array support])
  AC_COMPILE_IFELSE(
    [
        struct { int foo; int bar[[0]]; } mystruct;
    ], [
        AC_DEFINE_UNQUOTED(EMPTY_ARRAY_SIZE, 0, [Dimension to use for empty array declaration])
    ], [
        AC_COMPILE_IFELSE(
	    [
	        struct { int foo; int bar[[]]; } mystruct;
	    ], [
                AC_DEFINE_UNQUOTED(EMPTY_ARRAY_SIZE,, [Dimension to use for empty array declaration])
	    ], [
	        AC_MSG_ERROR([C compiler is unable to creaty empty arrays])
	    ])
    ])
  ]
)

dnl @synopsis AX_CPP_VARARG_MACRO_GCC
dnl
dnl Test if the preprocessor understands GNU GCC-style vararg macros.
dnl If it does, defines HAVE_CPP_VARARG_MACRO_GCC to 1.
dnl
dnl @version
dnl @author James Yonan <jim@yonan.net>, Matthias Andree <matthias.andree@web.de>
AC_DEFUN([AX_CPP_VARARG_MACRO_GCC], [dnl
    AS_VAR_PUSHDEF([VAR],[ax_cv_cpp_vararg_macro_gcc])dnl
    AC_CACHE_CHECK([for GNU GCC vararg macro support], VAR, [dnl
      AC_COMPILE_IFELSE([
	#define macro(a, b...) func(a, b)
	int func(int a, int b, int c);
	int test() { return macro(1, 2, 3); }
	], [ VAR=yes ], [VAR=no])])
    if test $VAR = yes ; then
    AC_DEFINE([HAVE_CPP_VARARG_MACRO_GCC], 1, 
      [Define to 1 if your compiler supports GNU GCC-style variadic macros])
    fi
    AS_VAR_POPDEF([VAR])dnl
])

dnl @synopsis AX_CPP_VARARG_MACRO_ISO
dnl
dnl Test if the preprocessor understands ISO C 1999 vararg macros.
dnl If it does, defines HAVE_CPP_VARARG_MACRO_ISO to 1.
dnl
dnl @version
dnl @author James Yonan <jim@yonan.net>, Matthias Andree <matthias.andree@web.de>
AC_DEFUN([AX_CPP_VARARG_MACRO_ISO], [dnl
    AS_VAR_PUSHDEF([VAR],[ax_cv_cpp_vararg_macro_iso])dnl
    AC_CACHE_CHECK([for ISO C 1999 vararg macro support], VAR, [dnl
      AC_COMPILE_IFELSE([
#define macro(a, ...) func(a, __VA_ARGS__)
	int func(int a, int b, int c);
	int test() { return macro(1, 2, 3); }
	], [ VAR=yes ], [VAR=no])])
    if test $VAR = yes ; then
    AC_DEFINE([HAVE_CPP_VARARG_MACRO_ISO], 1, 
      [Define to 1 if your compiler supports ISO C99 variadic macros])
    fi
    AS_VAR_POPDEF([VAR])dnl
])

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
#include <sys/socket.h>])
])
