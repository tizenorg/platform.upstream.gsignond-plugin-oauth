extensionsdir = $(EXTENSIONSDIR)
pluginsdir = $(PLUGINSDIR)

plugins_LTLIBRARIES = liboauth.la
NULL=

liboauth_la_CPPFLAGS = \
    $(GSIGNON_CFLAGS) \
    $(LIBSOUP_CFLAGS) \
    $(NULL)

liboauth_la_LIBADD = \
    $(GSIGNON_LIBS) \
    $(LIBSOUP_LIBS) \
    $(NULL)

liboauth_la_SOURCES = \
    gsignond-oauth-plugin.c \
    gsignond-oauth-plugin.h \
    gsignond-oauth-plugin-oauth2.c \
    gsignond-oauth-plugin-oauth2.h \
    gsignond-oauth-plugin-oauth1.c \
    gsignond-oauth-plugin-oauth1.h \
    gsignond-oauth-plugin-utils.c \
    gsignond-oauth-plugin-utils.h \
    $(NULL)

liboauth_la_LDFLAGS = -avoid-version

CLEANFILES = 
