AC_INIT([merkle_trie_toolkit],[0])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])

dnl to build tests, configure with CXXFLAGS=${location of cxxtest headers},
dnl which on my machine is -I/usr/local/include

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

export CXXFLAGS
export CXX

AC_MSG_CHECKING($XDRC)

if test -z $ALREADY_HAVE_XDRC; then
   AC_MSG_CHECKING(did not find xdrc already, looking locally)
   AX_PKGCONFIG_SUBDIR_NOCOND(xdrpp)
   AC_MSG_CHECKING(for xdrc)
   AS_IF([test -n "$XDRC"],,
          [test -n "$xdrpp_INTERNAL" -a x"$cross_compiling" != xyes],
          [XDRC='$(top_builddir)/xdrpp/xdrc/xdrc$(EXEEXT)'],
          [AC_PATH_PROG(XDRC, [xdrc])])
else
   AC_MSG_CHECKING(already have xdrc)
   XDRC=$ALREADY_HAVE_XDRC
fi

AC_SUBST(XDRC)

if test -z "$XDRC"; then
   AC_MSG_ERROR(Cannot find xdrc)
fi

AC_MSG_RESULT($XDRC)

AM_CONDITIONAL(MTT_BUILD_TESTS,
               [test -z "$mtt_disable_tests"])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile merkle_trie_toolkit.pc include/mtt/trie/build_endian.h merkle_trie_toolkit-uninstalled.pc])
AC_OUTPUT
