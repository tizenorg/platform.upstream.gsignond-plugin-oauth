TESTS = oauthplugintest
TESTS_ENVIRONMENT= SSO_PLUGINS_DIR=$(top_builddir)/src/.libs

check_PROGRAMS = oauthplugintest
oauthplugintest_SOURCES = oauth1tests.c oauth2tests.c oauthplugintest.c 
oauthplugintest_CFLAGS = \
    $(GSIGNON_CFLAGS) \
    $(LIBSOUP_CFLAGS) \
    $(CHECK_CFLAGS) \
    -I$(top_srcdir)/src/

oauthplugintest_LDADD = \
    $(top_builddir)/src/liboauth.la \
    $(GSIGNON_LIBS) \
    $(LIBSOUP_LIBS) \
    $(CHECK_LIBS)

EXTRA_oauthplugintest_DEPENDENCIES = $(top_builddir)/test/cacert.pem $(top_builddir)/test/privkey.pem
MOSTLYCLEANFILES = $(top_builddir)/test/cacert.pem $(top_builddir)/test/privkey.pem

$(top_builddir)/test/cacert.pem:
	cp $(top_srcdir)/test/cacert.pem.template $(top_builddir)/test/cacert.pem

$(top_builddir)/test/privkey.pem:
	cp $(top_srcdir)/test/privkey.pem.template $(top_builddir)/test/privkey.pem
   
#These recipes are nicked from gstreamer and simplified
VALGRIND_TESTS_DISABLE = 
SUPPRESSIONS = valgrind.supp

%.valgrind: %
	@$(TESTS_ENVIRONMENT) \
	CK_FORK=no \
	CK_DEFAULT_TIMEOUT=120 \
	G_SLICE=always-malloc \
	$(LIBTOOL) --mode=execute \
	valgrind -q \
	$(foreach s,$(SUPPRESSIONS),--suppressions=$(s)) \
	--tool=memcheck --leak-check=full --trace-children=yes \
	--leak-resolution=high --num-callers=40 \
	--error-exitcode=1 \
	./$* 
        
valgrind: $(TESTS)
	for t in $(filter-out $(VALGRIND_TESTS_DISABLE),$(TESTS)); do   \
		$(MAKE) $$t.valgrind;                                   \
	done;                                                         

EXTRA_DIST = cacert.pem.template privkey.pem.template valgrind.supp
