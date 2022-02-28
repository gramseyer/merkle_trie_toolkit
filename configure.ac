AC_PREREQ([2.68])
AC_INIT([merkle-trie-shenanigans],[0])
AM_INIT_AUTOMAKE([-Wall subdir-objects])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CXX
AC_LANG(C++)
AX_APPEND_COMPILE_FLAGS([-pthread])
AS_IF([test -z "${WFLAGS+set}"], AX_APPEND_COMPILE_FLAGS([-Wall], WFLAGS))

AC_C_BIGENDIAN
AC_C_BIGENDIAN(IS_BIG_ENDIAN=1, IS_BIG_ENDIAN=0)
AC_SUBST(IS_BIG_ENDIAN)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile include/trie/build_endian.h])
AC_OUTPUT
