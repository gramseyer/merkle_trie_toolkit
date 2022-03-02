ACLOCAL_AMFLAGS = -I m4

SUBDIRS = $(PKGCONFIG_SUBDIRS) .

AM_CPPFLAGS = $(xdrpp_CFLAGS)
LDADD = $(xdrpp_LDFLAGS)

SUFFIXES = .x.h

#building x files
$(XH_FILES) : $(XDRC)

#nodist_pkginclude_HEADERS = include/trie/build_endian.h

#BUILT_SOURCES = include/trie/config.h $(XH_FILES)

# If we use AC_CONFIG_HEADERS([xdrpp/config.h]) in configure.ac, then
# autoconf adds -Ixdrpp, which causes errors for files like endian.h
# (system headers find the xdrpp version instead of the system
# version).  Creating ./config.h and then copying it into ./xdrpp/
# solves the problem.
include/trie/config.h: $(builddir)/config.h
	cp $(builddir)/config.h include/trie/config.h

#pkginclude_HEADERS = include/trie/build_endian.h include/trie/xdr/types.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = xdrpp.pc

CLEANFILES = *~ */*~ */*/*~ .gitignore~
#DISTCLEANFILES = include/trie/config.h

#distclean-local:
#	rm -rf autom4te.cache

#maintainer-clean-local:
#	cd $(srcdir) && rm -rf `sed -ne 's!^/!!p' .gitignore`

#EXTRA_DIST = .gitignore autogen.sh \
#	include/trie/build_endian.h.in

TEST_SRCS = \
	tests/test_prefix.h \
	tests/test_merkle_trie.h \
	tests/test_merkle_trie_metadata.h \
	tests/test_recycling_trie.h

.x.h:
	echo "wtf" && \
	echo $< && \
	$(XDRC)  -hh -o $@ $<

X_FILES = include/trie/xdr/types.x

TEST_X_FILES = tests/xdr/test_types.x

#no idea but including this shorthand somehow screws up this configure script
#XH_FILES = $(X_FILES:.x=.h)

test_runner.cc : $(TEST_SRCS) $(X_FILES:.x=.h) $(TEST_X_FILES:.x=.h)
	cxxtestgen --error-printer -o test_runner.cc $(TEST_SRCS)

test_runner.o : CXXFLAGS += -I./include $(libsodium_CFLAGS) $(tbb_CFLAGS) $(xdrpp_CFLAGS)

bin_PROGRAMS = test

test_SOURCES = test_runner.cc

test_LDFLAGS = $(libsodium_LIBS) $(tbb_LIBS) $(xdrpp_LIBS)
