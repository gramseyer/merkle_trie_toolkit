ACLOCAL_AMFLAGS = -I m4

SUBDIRS = $(PKGCONFIG_SUBDIRS) .

abs_top_srcdir=@r_abs_top_srcdir@
abs_top_builddir=@r_abs_top_builddir@

AM_CPPFLAGS = $(libsodium_CFLAGS) $(tbb_CFLAGS) $(utility_CFLAGS) $(lmdb_CFLAGS)
LDADD = $(libsodium_LIBS) $(tbb_LIBS) $(utility_LIBS) $(lmdb_LIBS)

lib_LIBRARIES = libmtttests.a



# If we use AC_CONFIG_HEADERS([xdrpp/config.h]) in configure.ac, then
# autoconf adds -Ixdrpp, which causes errors for files like endian.h
# (system headers find the xdrpp version instead of the system
# version).  Creating ./config.h and then copying it into ./xdrpp/
# solves the problem.
include/mtt/trie/config.h: $(builddir)/config.h
	cp $(builddir)/config.h include/mtt/trie/config.h

CLEANFILES = *~ */*~ */*/*~ .gitignore~

distclean-local:
	rm -rf autom4te.cache

maintainer-clean-local:
	cd $(srcdir) && rm -rf `sed -ne 's!^/!!p' .gitignore`

EXTRA_DIST = .gitignore autogen.sh

TEST_SRCS = \
	tests/test_accumulate_values.cc \
	tests/test_atomic_trie.cc \
	tests/test_merkle_trie.cc \
	tests/test_merkle_trie_metadata.cc \
	tests/test_prefix.cc \
	tests/test_recycling_trie.cc \
	tests/test_serialize.cc

libmtttests_a_SOURCES = $(TEST_SRCS)

BUILT_SOURCES = include/mtt/trie/config.h

test.o : CXXFLAGS += $(Catch2_CFLAGS)
$(TEST_SRCS:.cc=.o) : CXXFLAGS += $(Catch2_CFLAGS) -I./include

bin_PROGRAMS = test

test_SOURCES = test.cc $(TEST_SRCS)

test_LDADD = $(LDADD) $(Catch2_LIBS)

