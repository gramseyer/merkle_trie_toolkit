

nodist_pkginclude_HEADERS = include/trie/build_endian.h

BUILT_SOURCES = include/trie/config.h

# If we use AC_CONFIG_HEADERS([xdrpp/config.h]) in configure.ac, then
# autoconf adds -Ixdrpp, which causes errors for files like endian.h
# (system headers find the xdrpp version instead of the system
# version).  Creating ./config.h and then copying it into ./xdrpp/
# solves the problem.
include/trie/config.h: $(builddir)/config.h
	cp $(builddir)/config.h include/trie/config.h

pkginclude_HEADERS = include/trie/build_endian.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = xdrpp.pc

CLEANFILES = *~ */*~ */*/*~ .gitignore~
DISTCLEANFILES = include/trie/config.h

distclean-local:
	rm -rf autom4te.cache

maintainer-clean-local:
	cd $(srcdir) && rm -rf `sed -ne 's!^/!!p' .gitignore`

EXTRA_DIST = .gitignore autogen.sh \
	include/trie/build_endian.h.in

ACLOCAL_AMFLAGS = -I m4
