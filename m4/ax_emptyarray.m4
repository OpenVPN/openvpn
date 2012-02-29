dnl @synopsis AX_EMPTY_ARRAY
dnl
dnl Define EMPTY_ARRAY_SIZE to be either "0"
dnl or "" depending on which syntax the compiler
dnl prefers for empty arrays in structs.
dnl
dnl @version
dnl @author James Yonan <jim@yonan.net>
AC_DEFUN([AX_EMPTY_ARRAY], [
	AS_VAR_PUSHDEF([VAR],[ax_cv_c_empty_array])dnl
	AC_CACHE_CHECK(
		[for C compiler empty array size],
		[VAR],
		[AC_COMPILE_IFELSE(
			[AC_LANG_PROGRAM(
				,
				[[
struct { int foo; int bar[0]; } mystruct;
				]]
			)],
			[VAR=0],
			[AC_COMPILE_IFELSE(
				[AC_LANG_PROGRAM(
					,
					[[
struct { int foo; int bar[]; } mystruct;
					]]
				)],
				[VAR=],
				[AC_MSG_ERROR([C compiler is unable to creaty empty arrays])]
			)]
		)]
	)dnl
	AC_DEFINE_UNQUOTED(
		[EMPTY_ARRAY_SIZE],
		[$VAR],
		[Dimension to use for empty array declaration]
	)dnl
	AS_VAR_POPDEF([VAR])dnl
])
