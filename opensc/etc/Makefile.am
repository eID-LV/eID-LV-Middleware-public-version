CV_CERTS = DESRCACC100001

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
DISTCLEANFILES = latvia-eid.conf.example

EXTRA_DIST = $(CV_CERTS) Makefile.mak

SUFFIXES = .in

dist_noinst_DATA = latvia-eid.conf latvia-eid.conf.example.in
nodist_noinst_DATA = latvia-eid.conf.example

# Make sure we build this every time
# as there is no dependency for this.
# Can be removed if MSVC is not requried.
force:
latvia-eid.conf.example: latvia-eid.conf.example.in force

.in:
	@sed \
		-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
		-e 's|@DEBUG_FILE[@]|$(DEBUG_FILE)|g' \
		-e 's|@DEFAULT_PCSC_PROVIDER[@]|$(DEFAULT_PCSC_PROVIDER)|g' \
		-e 's|@DEFAULT_SM_MODULE[@]|$(DEFAULT_SM_MODULE)|g' \
		-e 's|@DEFAULT_SM_MODULE_PATH[@]|$(DEFAULT_SM_MODULE_PATH)|g' \
		-e 's|@DYN_LIB_EXT[@]|$(DYN_LIB_EXT)|g' \
		-e 's|@LIBDIR[@]|$(LIBDIR)|g' \
		-e 's|@LIB_PRE[@]|$(LIB_PRE)|g' \
		-e 's|@PROFILE_DIR[@]|$(PROFILE_DIR)|g' \
		-e 's|@PROFILE_DIR_DEFAULT[@]|$(PROFILE_DIR_DEFAULT)|g' \
		< $< > $@

install-exec-hook: latvia-eid.conf.example
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)"
	if [ -f "$(DESTDIR)$(sysconfdir)/latvia-eid.conf" ]; then \
		$(INSTALL_DATA) $(srcdir)/latvia-eid.conf "$(DESTDIR)$(sysconfdir)/latvia-eid.conf.new"; \
	else \
		$(INSTALL_DATA) $(srcdir)/latvia-eid.conf "$(DESTDIR)$(sysconfdir)/latvia-eid.conf"; \
	fi
	$(MKDIR_P) "$(DESTDIR)$(docdir)"
	$(INSTALL_DATA) latvia-eid.conf.example "$(DESTDIR)$(docdir)/latvia-eid.conf";

uninstall-hook: latvia-eid.conf.example
	rm -f "$(DESTDIR)$(sysconfdir)/latvia-eid.conf.new" "$(DESTDIR)$(sysconfdir)/latvia-eid.conf"
	rm -f "$(DESTDIR)$(docdir)/latvia-eid.conf"

if ENABLE_OPENPACE
install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(CVCDIR)"
	for cert in $(CV_CERTS);   do $(INSTALL_DATA) $(srcdir)/$${cert} "$(DESTDIR)$(CVCDIR)";  done

uninstall-local:
	for cert in $(CV_CERTS);   do rm -f "$(DESTDIR)$(CVCDIR)/$${cert}";  done
endif
