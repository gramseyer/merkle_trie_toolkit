
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = $(PKGCONFIG_SUBDIRS)

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


TEST_SRCS = \
	tests/test_prefix.h \
	tests/test_merkle_trie.h \
	tests/test_merkle_trie_metadata.h \
	tests/test_recycling_trie.h

test_runner.cc : $(TEST_SRCS)
	cxxtestgen --error-printer -o test_runner.cc $(TEST_SRCS)

test_runner.o : CXXFLAGS += -I./include $(libsodium_CFLAGS) $(tbb_CFLAGS)

bin_PROGRAMS = test

test_SOURCES = test_runner.cc

test_LDFLAGS = $(libsodium_LDFLAGS) $(tbb_LDFLAGS)
