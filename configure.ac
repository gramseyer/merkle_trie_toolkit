AC_INIT([merkle-trie-shenanigans],[0])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])

dnl to build tests, configure with CXXFLAGS=${location of cxxtest headers},
dnl which on my machine is -I/usr/local/include

AC_PROG_CXX
AC_LANG(C++)
AX_APPEND_COMPILE_FLAGS([-pthread])
AS_IF([test -z "${WFLAGS+set}"], AX_APPEND_COMPILE_FLAGS([-Wall], WFLAGS))

AC_C_BIGENDIAN
AC_C_BIGENDIAN(IS_BIG_ENDIAN=1, IS_BIG_ENDIAN=0)
AC_SUBST(IS_BIG_ENDIAN)

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([libsodium], [libsodium])
PKG_CHECK_MODULES([tbb], [tbb])

export CXXFLAGS

AX_PKGCONFIG_SUBDIR(xdrpp)
AC_MSG_CHECKING(for xdrc)
AS_IF([test -n "$XDRC"],,
       [test -n "$xdrpp_INTERNAL" -a x"$cross_compiling" != xyes],
       [XDRC='$(top_builddir)/xdrpp/xdrc/xdrc$(EXEEXT)'],
       [AC_PATH_PROG(XDRC, [xdrc])])
if test -z "$XDRC"; then
   AC_MSG_ERROR(Cannot find xdrc)
fi
AC_MSG_RESULT($XDRC)
AC_SUBST(XDRC)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile include/trie/build_endian.h])
AC_OUTPUT
