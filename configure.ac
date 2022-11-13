AC_INIT([merkle_trie_toolkit],[0])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CXX
AC_LANG(C++)
AX_APPEND_COMPILE_FLAGS([-pthread])
AX_APPEND_COMPILE_FLAGS([-std=gnu++2a])
AS_IF([test -z "${WFLAGS+set}"], AX_APPEND_COMPILE_FLAGS([-Wall], WFLAGS))

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([libsodium], [libsodium])
PKG_CHECK_MODULES([tbb], [tbb])
PKG_CHECK_MODULES([Catch2], [catch2])

#we only need lmdb dependence because I can't figure out how to ensure
# that libutility libs get linked 
PKG_CHECK_MODULES([lmdb], [lmdb])

AC_PROG_RANLIB

AS_IF([test -z "$ABS_TOP_BUILDDIR"],
	[
		ABS_TOP_BUILDDIR=$ac_pwd
		ABS_TOP_SRCDIR=$ac_pwd
	],
	)

AC_SUBST(r_abs_top_srcdir, $ABS_TOP_SRCDIR)
AC_SUBST(r_abs_top_builddir, $ABS_TOP_BUILDDIR)

AS_IF([test -z "$utility_INTERNAL"], 
	[
		AC_MSG_NOTICE("using pkg-config for utility")
		PKG_CHECK_MODULES([utility], [utility])
	], 
	[
		AC_MSG_CHECKING(using utility with lib=$utility_LIBS cflags=$utility_CFLAGS)
	])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile merkle_trie_toolkit.pc merkle_trie_toolkit-uninstalled.pc])
AC_OUTPUT
