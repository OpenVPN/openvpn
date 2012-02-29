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
  AC_COMPILE_IFELSE([AC_LANG_SOURCE(
    [
        struct { int foo; int bar[[0]]; } mystruct;
    ])], [
        AC_DEFINE_UNQUOTED(EMPTY_ARRAY_SIZE, 0, [Dimension to use for empty array declaration])
    ], [
        AC_COMPILE_IFELSE([AC_LANG_SOURCE(
	    [
	        struct { int foo; int bar[[]]; } mystruct;
	    ])], [
                AC_DEFINE_UNQUOTED(EMPTY_ARRAY_SIZE,, [Dimension to use for empty array declaration])
	    ], [
	        AC_MSG_ERROR([C compiler is unable to creaty empty arrays])
	    ])
    ])
  ]
)
