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
PKG_CHECK_MODULES([Catch2], [Catch2])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile merkle_trie_toolkit.pc merkle_trie_toolkit-uninstalled.pc])
AC_OUTPUT
