AM_DISTCHECK_CONFIGURE_FLAGS = \
    --enable-gtk-doc \
    --enable-distcheck
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src examples docs test

valgrind:
	cd test; make valgrind

dist-hook:
	@echo
	@echo "==== Run 'make update-online-doc' to update online documentation ===="
	@echo

update-online-doc:
	@tar zxf $(PACKAGE)-$(VERSION).tar.gz && \
	pushd . > /dev/null && \
	cd .. && \
	git clone https://code.google.com/p/accounts-sso.gsignon-docs/ ; \
	cd accounts-sso.gsignon-docs && \
	git pull ; \
	mkdir -p $(PACKAGE) && \
	rm -rf $(PACKAGE)/* && \
	popd > /dev/null && \
	cp -rf $(PACKAGE)-$(VERSION)/docs/html/* ../accounts-sso.gsignon-docs/$(PACKAGE)/ && \
	pushd . > /dev/null && \
	cd ../accounts-sso.gsignon-docs && \
	git add $(PACKAGE)/* && \
	git commit -m "Updated documentation for $(PACKAGE) to version $(VERSION)" && \
	git push ; \
	popd > /dev/null && \
	rm -rf $(PACKAGE)-$(VERSION)

lcov: check
	@rm -rf lcov-report
	@lcov -c --directory src/ --output-file lcov.output
	@genhtml lcov.output --output-directory lcov-report
	@rm lcov.output
	@echo "Coverage report is in file://$(abs_srcdir)/lcov-report/index.html"
