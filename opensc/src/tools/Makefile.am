include $(top_srcdir)/win32/ltrc.inc

if ENABLE_ZLIB
VDFORMAT=XML
else
VDFORMAT=GZIP
endif

do_subst = $(SED) \
	   -e 's,[@]bindir[@],$(bindir),g' \
	   -e 's,[@]CVCDIR[@],$(CVCDIR),g' \
	   -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]PACKAGE_TARNAME[@],$(PACKAGE_TARNAME),g' \
	   -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
	   -e 's,[@]PACKAGE_SUMMARY[@],$(PACKAGE_SUMMARY),g' \
	   -e 's,[@]PACKAGE_VERSION[@],"$(PACKAGE_VERSION)",g' \
	   -e 's,[@]VDFORMAT[@],$(VDFORMAT),g' \
	   -e 's,[@]X509DIR[@],$(X509DIR),g'

EGK_TOOL_BUILT_SOURCES = egk-tool-cmdline.h egk-tool-cmdline.c
NPA_TOOL_BUILT_SOURCES = npa-tool-cmdline.h npa-tool-cmdline.c
OPENSC_NOTIFY_BUILT_SOURCES = opensc-notify-cmdline.h opensc-notify-cmdline.c
OPENSC_ASN1_BUILT_SOURCES = opensc-asn1-cmdline.h opensc-asn1-cmdline.c

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/versioninfo-tools.rc $(srcdir)/versioninfo-opensc-notify.rc
EXTRA_DIST = Makefile.mak versioninfo-tools.rc.in versioninfo-opensc-notify.rc.in npa-tool.ggo.in opensc-notify.ggo.in egk-tool.ggo.in opensc-asn1.ggo.in org.opensc.notify.desktop.in exe.manifest

noinst_HEADERS = util.h fread_to_eof.h
noinst_PROGRAMS = sceac-example
bin_PROGRAMS = opensc-tool opensc-explorer \
	pkcs15-tool pkcs15-crypt pkcs11-tool \
	opensc-asn1

# compile with $(PTHREAD_CFLAGS) to allow debugging with gdb
AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(OPTIONAL_READLINE_CFLAGS) $(PTHREAD_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src -D'DEFAULT_PKCS11_PROVIDER="$(DEFAULT_PKCS11_PROVIDER)"'
LIBS = \
	$(top_builddir)/src/libopensc/libeidlv.la \
	$(top_builddir)/src/common/libscdl.la \
	$(top_builddir)/src/common/libcompat.la

sceac_example_SOURCES = sceac-example.c
sceac_example_LDADD = $(top_builddir)/src/libopensc/libeidlv.la $(OPENPACE_LIBS)
sceac_example_CFLAGS = -I$(top_srcdir)/src $(OPENPACE_CFLAGS)

opensc_tool_SOURCES = opensc-tool.c util.c
piv_tool_SOURCES = piv-tool.c util.c
piv_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
opensc_explorer_SOURCES = opensc-explorer.c util.c
opensc_explorer_LDADD = $(OPTIONAL_READLINE_LIBS)
pkcs15_tool_SOURCES = pkcs15-tool.c util.c
pkcs15_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
pkcs11_tool_SOURCES = pkcs11-tool.c util.c
pkcs11_tool_LDADD = \
	$(top_builddir)/src/common/libpkcs11.la \
	$(OPTIONAL_OPENSSL_LIBS)
pkcs15_crypt_SOURCES = pkcs15-crypt.c util.c
pkcs15_crypt_LDADD = $(OPTIONAL_OPENSSL_LIBS)
cryptoflex_tool_SOURCES = cryptoflex-tool.c util.c
cryptoflex_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
pkcs15_init_SOURCES = pkcs15-init.c util.c
pkcs15_init_LDADD = $(OPTIONAL_OPENSSL_LIBS)
cardos_tool_SOURCES = cardos-tool.c util.c
cardos_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
eidenv_SOURCES = eidenv.c util.c
netkey_tool_SOURCES = netkey-tool.c
netkey_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
westcos_tool_SOURCES = westcos-tool.c util.c
westcos_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
openpgp_tool_SOURCES = openpgp-tool.c util.c
openpgp_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
iasecc_tool_SOURCES = iasecc-tool.c util.c
iasecc_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
sc_hsm_tool_SOURCES = sc-hsm-tool.c util.c
sc_hsm_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
dnie_tool_SOURCES = dnie-tool.c util.c
dnie_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)
gids_tool_SOURCES = gids-tool.c util.c
gids_tool_LDADD = $(OPTIONAL_OPENSSL_LIBS)

npa_tool_SOURCES = npa-tool.c fread_to_eof.c $(NPA_TOOL_BUILT_SOURCES)
npa_tool_LDADD = $(top_builddir)/src/libopensc/libeidlv.la \
				 $(OPENPACE_LIBS)
npa_tool_CFLAGS = -I$(top_srcdir)/src $(OPENPACE_CFLAGS) $(OPENSSL_CFLAGS)

npa-tool.c: $(abs_builddir)/npa-tool.ggo $(NPA_TOOL_BUILT_SOURCES)

# We only want *cmdline* to be generated when they have explicitly been removed.
$(NPA_TOOL_BUILT_SOURCES):
	$(MAKE) $(abs_builddir)/npa-tool.ggo
	$(GENGETOPT) --include-getopt --file-name=npa-tool-cmdline --output-dir=$(builddir) < $(abs_builddir)/npa-tool.ggo

$(abs_builddir)/npa-tool.ggo: npa-tool.ggo.in 
	$(do_subst) < $(abs_srcdir)/npa-tool.ggo.in > $@

opensc_notify_SOURCES = opensc-notify.c $(OPENSC_NOTIFY_BUILT_SOURCES)
opensc_notify_LDADD = $(top_builddir)/src/libopensc/libeidlv.la $(OPTIONAL_NOTIFY_LIBS)
opensc_notify_CFLAGS = -I$(top_srcdir)/src $(OPTIONAL_NOTIFY_CFLAGS)
opensc_notify_CFLAGS += -Wno-unused-but-set-variable
if HAVE_UNKNOWN_WARNING_OPTION
opensc_notify_CFLAGS += -Wno-unknown-warning-option
endif

opensc-notify.c: $(abs_builddir)/opensc-notify.ggo $(OPENSC_NOTIFY_BUILT_SOURCES)

# We only want *cmdline* to be generated when they have explicitly been removed.
$(OPENSC_NOTIFY_BUILT_SOURCES):
	$(MAKE) $(abs_builddir)/opensc-notify.ggo
	$(GENGETOPT) --include-getopt --file-name=opensc-notify-cmdline --output-dir=$(builddir) < $(abs_builddir)/opensc-notify.ggo

$(abs_builddir)/opensc-notify.ggo: opensc-notify.ggo.in 
	$(do_subst) < $(abs_srcdir)/opensc-notify.ggo.in > $@

egk_tool_SOURCES = egk-tool.c $(EGK_TOOL_BUILT_SOURCES)
egk_tool_LDADD = $(top_builddir)/src/libopensc/libeidlv.la $(OPTIONAL_ZLIB_LIBS)
egk_tool_CFLAGS = -I$(top_srcdir)/src $(OPTIONAL_ZLIB_CFLAGS)
egk_tool_CFLAGS += -Wno-unused-but-set-variable
if HAVE_UNKNOWN_WARNING_OPTION
egk_tool_CFLAGS += -Wno-unknown-warning-option
endif

egk-tool.c: $(abs_builddir)/egk-tool.ggo $(EGK_TOOL_BUILT_SOURCES)

# We only want *cmdline* to be generated when they have explicitly been removed.
$(EGK_TOOL_BUILT_SOURCES):
	$(MAKE) $(abs_builddir)/egk-tool.ggo
	$(GENGETOPT) --include-getopt --file-name=egk-tool-cmdline --output-dir=$(builddir) < $(abs_builddir)/egk-tool.ggo

$(abs_builddir)/egk-tool.ggo: egk-tool.ggo.in 
	$(do_subst) < $(abs_srcdir)/egk-tool.ggo.in > $@

opensc_asn1_SOURCES = opensc-asn1.c fread_to_eof.c $(OPENSC_ASN1_BUILT_SOURCES)
opensc_asn1_LDADD = $(top_builddir)/src/libopensc/libeidlv.la $(OPTIONAL_ZLIB_LIBS)
opensc_asn1_CFLAGS = -I$(top_srcdir)/src $(OPTIONAL_ZLIB_CFLAGS)
opensc_asn1_CFLAGS += -Wno-unused-but-set-variable -Wno-unknown-warning-option

opensc-asn1.c: $(abs_builddir)/opensc-asn1.ggo $(OPENSC_ASN1_BUILT_SOURCES)

# We only want *cmdline* to be generated when they have explicitly been removed.
$(OPENSC_ASN1_BUILT_SOURCES):
	$(MAKE) $(abs_builddir)/opensc-asn1.ggo
	$(GENGETOPT) --include-getopt --file-name=opensc-asn1-cmdline --output-dir=$(builddir) < $(abs_builddir)/opensc-asn1.ggo --unamed-opts

$(abs_builddir)/opensc-asn1.ggo: opensc-asn1.ggo.in 
	$(do_subst) < $(abs_srcdir)/opensc-asn1.ggo.in > $@

if WIN32
opensc_tool_SOURCES += versioninfo-tools.rc
piv_tool_SOURCES += versioninfo-tools.rc
opensc_explorer_SOURCES += versioninfo-tools.rc
pkcs15_tool_SOURCES += versioninfo-tools.rc
pkcs11_tool_SOURCES += versioninfo-tools.rc
pkcs15_crypt_SOURCES += versioninfo-tools.rc
cryptoflex_tool_SOURCES += versioninfo-tools.rc
pkcs15_init_SOURCES += versioninfo-tools.rc
cardos_tool_SOURCES += versioninfo-tools.rc
eidenv_SOURCES += versioninfo-tools.rc
netkey_tool_SOURCES += versioninfo-tools.rc
westcos_tool_SOURCES += versioninfo-tools.rc
openpgp_tool_SOURCES += versioninfo-tools.rc
iasecc_tool_SOURCES += versioninfo-tools.rc
sc_hsm_tool_SOURCES += versioninfo-tools.rc
gids_tool_SOURCES += versioninfo-tools.rc
opensc_notify_SOURCES += versioninfo-opensc-notify.rc
endif

applicationsdir = $(datadir)/applications
applications_DATA = org.opensc.notify.desktop

org.opensc.notify.desktop: org.opensc.notify.desktop.in
	$(do_subst) < $(abs_srcdir)/org.opensc.notify.desktop.in > $@

clean-local:
	rm -f $(abs_builddir)/npa-tool.ggo $(abs_builddir)/opensc-notify.ggo $(abs_builddir)/opensc-asn1.ggo $(abs_builddir)/egk-tool.ggo org.opensc.notify.desktop
