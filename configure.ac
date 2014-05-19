#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([gsignond-plugin-oauth], [1.0.0], [])
AC_CONFIG_SRCDIR([src/gsignond-oauth-plugin.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 -Wall nostdinc silent-rules subdir-objects -Wno-portability])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR

#libtool
LT_PREREQ([2.2])
LT_INIT([disable-static])

#gtk-doc
GTK_DOC_CHECK([1.18],[--flavour no-tmpl])

# Checks for libraries.
PKG_CHECK_MODULES([GSIGNON], 
                  [glib-2.0 >= 2.30
                   json-glib-1.0
                   gsignond
                   gnutls
])
AC_SUBST(GSIGNON_CFLAGS)
AC_SUBST(GSIGNON_LIBS)

PKG_CHECK_MODULES(LIBSOUP, [libsoup-2.4])
AC_SUBST(LIBSOUP_CFLAGS)
AC_SUBST(LIBSOUP_LIBS)

# AM_PATH_CHECK() is deprecated, but check documentation fails to tell that :-/
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check=yes], [have_check=no])
AC_SUBST(CHECK_CFLAGS)
AC_SUBST(CHECK_LIBS)

AC_ARG_ENABLE([coverage],
    [AS_HELP_STRING([--enable-coverage], [compile with coverage info])])
AS_IF([test "x$enable_coverage" = "xyes"],
    [CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"])

# allow fake installations for "distcheck"
AC_ARG_ENABLE(distcheck,
             [  --enable-distcheck build for distcheck target],
             [enable_distcheck=yes], [enable_distcheck=no])
echo -n "running distcheck... "
echo $enable_distcheck

if test "x$enable_distcheck" = "xyes" ; then
     EXTENSIONSDIR="${libdir}/gsignond/extensions"
     PLUGINSDIR="${libdir}/gsignond/gplugins"
else
     PLUGINSDIR=`pkg-config gsignond --variable=gpluginsdir`
     EXTENSIONSDIR=`pkg-config gsignond --variable=extensionsdir`
fi
AC_SUBST(PLUGINSDIR)
AC_SUBST(EXTENSIONSDIR)

GSIGNON_CFLAGS="$GSIGNON_CFLAGS -Wall -Werror"

AC_OUTPUT([
Makefile
docs/Makefile
src/Makefile
test/Makefile
examples/Makefile
])
