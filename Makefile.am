ACLOCAL_AMFLAGS = -I m4

SUBDIRS = $(PKGCONFIG_SUBDIRS) .

AM_CPPFLAGS = $(xdrpp_CFLAGS) $(libsodium_CFLAGS) $(tbb_CFLAGS)
LDADD = $(libsodium_LIBS) $(tbb_LIBS) $(xdrpp_LIBS)

SUFFIXES = .x.h

#nodist_pkginclude_HEADERS = include/trie/build_endian.h

# If we use AC_CONFIG_HEADERS([xdrpp/config.h]) in configure.ac, then
# autoconf adds -Ixdrpp, which causes errors for files like endian.h
# (system headers find the xdrpp version instead of the system
# version).  Creating ./config.h and then copying it into ./xdrpp/
# solves the problem.
include/mtt/trie/config.h: $(builddir)/config.h
	cp $(builddir)/config.h include/mtt/trie/config.h

#pkginclude_HEADERS = include/mtt/trie/build_endian.h include/mtt/trie/xdr/types.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = xdrpp.pc

CLEANFILES = *~ */*~ */*/*~ .gitignore~
#DISTCLEANFILES = include/mtt/trie/config.h

#distclean-local:
#	rm -rf autom4te.cache

#maintainer-clean-local:
#	cd $(srcdir) && rm -rf `sed -ne 's!^/!!p' .gitignore`

#EXTRA_DIST = .gitignore autogen.sh \
#	include/mtt/trie/build_endian.h.in

TEST_SRCS = \
	tests/test_recycling_trie.cc \
	tests/test_serialize.cc

.x.h:
	$(XDRC)  -hh -o $@ $<

X_FILES = include/mtt/trie/xdr/types.x

TEST_X_FILES = tests/xdr/test_types.x

BUILT_SOURCES = include/mtt/trie/config.h $(X_FILES:.x=.h)

$(top_builddir)/include/mtt/trie/xdr/types.h : $(XDRC)
$(top_builddir)/tests/xdr/test_types.h : $(XDRC)

#no idea but including this shorthand somehow screws up this configure script
#XH_FILES = $(X_FILES:.x=.h)

test.o : CXXFLAGS += $(Catch2_CFLAGS)
$(TEST_SRCS:.cc=.o) : CXXFLAGS += $(Catch2_CFLAGS) -I./include
test.o : $(XDRC)

bin_PROGRAMS = test

test_SOURCES = test.cc $(TEST_SRCS)

test_LDFLAGS = $(Catch2_LIBS)

