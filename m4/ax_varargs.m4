dnl @synopsis AX_CPP_VARARG_MACRO_GCC
dnl
dnl Test if the preprocessor understands GNU GCC-style vararg macros.
dnl If it does, defines HAVE_CPP_VARARG_MACRO_GCC to 1.
dnl
dnl @version
dnl @author James Yonan <jim@yonan.net>, Matthias Andree <matthias.andree@web.de>
AC_DEFUN([AX_CPP_VARARG_MACRO_GCC], [dnl
	AS_VAR_PUSHDEF([VAR], [ax_cv_cpp_vararg_macro_gcc])dnl
	AC_CACHE_CHECK(
		[for GNU GCC vararg macro support],
		[VAR],
		[AC_COMPILE_IFELSE(
			[AC_LANG_PROGRAM(
				[[
#define macro(a, b...) func(a, b)
int func(int a, int b, int c);
				]],
				[[
int i = macro(1, 2, 3);
				]]
			)],
			[VAR=yes],
			[VAR=no]
		)]
	)dnl

	AS_VAR_IF(
		[VAR],
		[yes],
		[AC_DEFINE(
			[HAVE_CPP_VARARG_MACRO_GCC],
			[1], 
			[Define to 1 if your compiler supports GNU GCC-style variadic macros]
		)]
	)dnl
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
	AC_CACHE_CHECK(
		[for ISO C 1999 vararg macro support],
		[VAR],
		[AC_COMPILE_IFELSE(
			[AC_LANG_PROGRAM(
				[[
#define macro(a, ...) func(a, __VA_ARGS__)
int func(int a, int b, int c);
				]],
				[[
int i = macro(1, 2, 3);
				]]
			)],
			[VAR=yes],
			[VAR=no]
		)]
	)dnl

	AS_VAR_IF(
		[VAR],
		[yes],
		[AC_DEFINE(
			[HAVE_CPP_VARARG_MACRO_ISO],
			[1], 
			[Define to 1 if your compiler supports ISO C99 variadic macros]
		)]
	)dnl
	AS_VAR_POPDEF([VAR])dnl
])
