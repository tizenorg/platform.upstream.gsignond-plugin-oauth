noinst_PROGRAMS = gsignond-oauth1-example gsignond-oauth2-example

gsignond_oauth1_example_SOURCES = gsignond-oauth1-example.c
gsignond_oauth1_example_CFLAGS = \
    $(GSIGNON_CFLAGS) \
    $(LIBSOUP_CFLAGS) \
    -I$(top_srcdir)/src/

gsignond_oauth1_example_LDADD = \
    $(top_builddir)/src/liboauth.la \
    $(GSIGNON_LIBS)

gsignond_oauth2_example_SOURCES = gsignond-oauth2-example.c
gsignond_oauth2_example_CFLAGS = \
    $(GSIGNON_CFLAGS) \
    $(LIBSOUP_CFLAGS) \
    -I$(top_srcdir)/src/

gsignond_oauth2_example_LDADD = \
    $(top_builddir)/src/liboauth.la \
    $(GSIGNON_LIBS)

all-local: $(top_builddir)/docs/gsignond-oauth1-example.listing $(top_builddir)/docs/gsignond-oauth2-example.listing

mostlyclean-local: 
	rm -rf $(top_builddir)/docs/gsignond-oauth1-example.listing $(top_builddir)/docs/gsignond-oauth2-example.listing

$(top_builddir)/docs/gsignond-oauth1-example.listing:
	cp $(top_srcdir)/examples/gsignond-oauth1-example.c $(top_builddir)/docs/gsignond-oauth1-example.listing

$(top_builddir)/docs/gsignond-oauth2-example.listing:
	cp $(top_srcdir)/examples/gsignond-oauth2-example.c $(top_builddir)/docs/gsignond-oauth2-example.listing