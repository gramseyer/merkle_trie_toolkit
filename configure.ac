AC_INIT([merkle_trie_toolkit],[0])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CXX
AC_LANG(C++)
AX_APPEND_COMPILE_FLAGS([-pthread])
AX_APPEND_COMPILE_FLAGS([-std=gnu++2a])
AS_IF([test -z "${WFLAGS+set}"], AX_APPEND_COMPILE_FLAGS([-Wall], WFLAGS))

AC_C_BIGENDIAN
AC_C_BIGENDIAN(IS_BIG_ENDIAN=1, IS_BIG_ENDIAN=0)
AC_SUBST(IS_BIG_ENDIAN)

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([libsodium], [libsodium])
PKG_CHECK_MODULES([tbb], [tbb])
PKG_CHECK_MODULES([Catch2], [Catch2])

export CXXFLAGS
export CXX

AC_MSG_CHECKING($XDRC)

if test -z $XDRC; then
   AC_MSG_CHECKING(did not find xdrc already, looking locally)
   AX_PKGCONFIG_SUBDIR_NOCOND(xdrpp)
   AC_MSG_CHECKING(for xdrc)
   AS_IF([test -n "$XDRC"],,
          [test -n "$xdrpp_INTERNAL" -a x"$cross_compiling" != xyes],
          [XDRC='$(top_builddir)/xdrpp/xdrc/xdrc$(EXEEXT)'],
          [AC_PATH_PROG(XDRC, [xdrc])])
else
   AC_MSG_CHECKING(already have xdrc)
fi

AC_SUBST(XDRC)

if test -z "$XDRC"; then
   AC_MSG_ERROR(Cannot find xdrc)
fi

AC_MSG_RESULT($XDRC)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile merkle_trie_toolkit.pc include/mtt/trie/build_endian.h merkle_trie_toolkit-uninstalled.pc])
AC_OUTPUT
