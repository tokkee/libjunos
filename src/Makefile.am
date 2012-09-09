AM_CFLAGS = @STRICT_CFLAGS@

include_HEADERS = junos.h libjunos_features.h
lib_LTLIBRARIES = libjunos.la

BUILT_SOURCES = libjunos_features.h

libjunos_la_SOURCES = junos.c junos.h \
		libjunos_features.h \
		access_ssh.c \
		netrc.c
libjunos_la_CFLAGS = $(AM_CFLAGS) \
		@LIBSSH2_CFLAGS@ \
		@LIBXML2_CFLAGS@
libjunos_la_LDFLAGS = $(AM_LDFLAGS) -version-info 0:0:0 \
		@LIBSSH2_LIBS@ \
		@LIBXML2_LIBS@

bin_PROGRAMS = junosc

junosc_SOURCES = junosc.c junos.h
junosc_CFLAGS = $(AM_CFLAGS) -DBUILD_DATE="\"$$( date --utc '+%F %T' ) (UTC)\""
junosc_LDADD = libjunos.la

libjunos_features.h: libjunos_features.h.in ../version
	source ../version; sed \
	    -e "s/@LIBJUNOS_VERSION_MAJOR@/$$VERSION_MAJOR/g" \
	    -e "s/@LIBJUNOS_VERSION_MINOR@/$$VERSION_MINOR/g" \
	    -e "s/@LIBJUNOS_VERSION_PATCH@/$$VERSION_PATCH/g" \
	    -e "s/@LIBJUNOS_VERSION_EXTRA@/$$VERSION_EXTRA/g" \
	    -e "s/@LIBJUNOS_VERSION_STRING@/$$VERSION_STRING/g" \
	    libjunos_features.h.in > libjunos_features.h

.PHONY: FORCE

