include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-pkcs11.rc $(srcdir)/versioninfo-pkcs11-spy.rc
EXTRA_DIST = Makefile.mak versioninfo-pkcs11.rc.in versioninfo-pkcs11-spy.rc.in eidlv-pkcs11.pc.in eidlv-pkcs11.dll.manifest onepin-eidlv-pkcs11.dll.manifest

lib_LTLIBRARIES = eidlv-pkcs11.la pkcs11-spy.la onepin-eidlv-pkcs11.la

AM_CPPFLAGS = -I$(top_srcdir)/src

OPENSC_PKCS11_INC = sc-pkcs11.h pkcs11.h pkcs11-opensc.h
OPENSC_PKCS11_SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	mechanism.c openssl.c framework-pkcs15.c \
	framework-pkcs15init.c debug.c pkcs11.exports \
	pkcs11-display.c pkcs11-display.h
OPENSC_PKCS11_CFLAGS = \
	$(OPTIONAL_OPENSSL_CFLAGS) $(OPENSC_PKCS11_PTHREAD_CFLAGS)
OPENSC_PKCS11_LIBS = \
	$(top_builddir)/src/libopensc/libeidlv.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la \
	$(OPTIONAL_OPENSSL_LIBS) $(PTHREAD_LIBS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = eidlv-pkcs11.pc
DISTCLEANFILES = $(pkgconfig_DATA)

eidlv_pkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC)
eidlv_pkcs11_la_CFLAGS = $(OPENSC_PKCS11_CFLAGS)
eidlv_pkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
eidlv_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

onepin_eidlv_pkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC)
onepin_eidlv_pkcs11_la_CFLAGS = -DMODULE_APP_NAME=\"onepin-eidlv-pkcs11\" $(OPENSC_PKCS11_CFLAGS)
onepin_eidlv_pkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
onepin_eidlv_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
        -export-symbols "$(srcdir)/pkcs11.exports" \
        -module -shared -avoid-version -no-undefined

pkcs11_spy_la_SOURCES = pkcs11-spy.c pkcs11-display.c pkcs11-display.h pkcs11.exports
pkcs11_spy_la_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS)
pkcs11_spy_la_LIBADD = \
	$(top_builddir)/src/common/libpkcs11.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la \
	$(OPTIONAL_OPENSSL_LIBS)
pkcs11_spy_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

if WIN32
eidlv_pkcs11_la_SOURCES += versioninfo-pkcs11.rc
pkcs11_spy_la_SOURCES += versioninfo-pkcs11-spy.rc
endif

if WIN32
install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	for l in eidlv-pkcs11.dll pkcs11-spy.dll; do \
		mv "$(DESTDIR)$(libdir)/$$l" "$(DESTDIR)$(bindir)/$$l"; \
	done
else
# see http://wiki.cacert.org/wiki/Pkcs11TaskForce
install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(pkcs11dir)"
	for l in eidlv-pkcs11$(DYN_LIB_EXT) onepin-eidlv-pkcs11$(DYN_LIB_EXT) pkcs11-spy$(DYN_LIB_EXT); do \
		rm -f "$(DESTDIR)$(pkcs11dir)/$$l"; \
		$(LN_S) ../$$l "$(DESTDIR)$(pkcs11dir)/$$l"; \
	done

endif
