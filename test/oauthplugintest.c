/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of gsignond
 *
 * Copyright (C) 2012 Intel Corporation.
 *
 * Contact: Alexander Kanavin <alex.kanavin@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <check.h>
#include <stdlib.h>
#include "gsignond-oauth-plugin.h"
#include <gsignond/gsignond-session-data.h>
#include <gsignond/gsignond-plugin-interface.h>
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-config.h>
#include <libsoup/soup.h>

void add_oauth1_tcase(Suite *s);
void add_oauth2_tcase(Suite *s);

static void check_plugin(GSignondPlugin* plugin)
{
    gchar* type;
    gchar** mechanisms;

    fail_if(plugin == NULL);
    
    g_object_get(plugin, "type", &type, "mechanisms", &mechanisms, NULL);
    
    fail_unless(g_strcmp0(type, "oauth") == 0);
    fail_unless(g_strcmp0(mechanisms[0], "oauth1") == 0);
    fail_unless(g_strcmp0(mechanisms[1], "oauth2") == 0);
    fail_unless(mechanisms[2] == NULL);
    
    g_free(type);
    g_strfreev(mechanisms);
}

START_TEST (test_oauthplugin_create)
{
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    check_plugin(plugin);
    g_object_unref(plugin);
}
END_TEST

    
Suite* oauthplugin_suite (void)
{
    Suite *s = suite_create ("OAUTH plugin");
    
    TCase *tc_oauth_plugin = tcase_create ("OAuth plugin tests");
    tcase_add_test (tc_oauth_plugin, test_oauthplugin_create);
    suite_add_tcase (s, tc_oauth_plugin);
    
    add_oauth1_tcase(s);
    add_oauth2_tcase(s);
    
    return s;
}

int main (void)
{
    int number_failed;

#if !GLIB_CHECK_VERSION (2, 36, 0)
    g_type_init ();
#endif
    
    Suite *s = oauthplugin_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
  
