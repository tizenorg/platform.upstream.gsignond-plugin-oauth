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
#include <gsignond/gsignond-utils.h>
#include <libsoup/soup.h>

static void response_callback(GSignondPlugin* plugin, GSignondSessionData* result,
                     gpointer user_data)
{
    GSignondSessionData** user_data_p = user_data;
    *user_data_p = result;
    gsignond_dictionary_ref(result);
}

static void store_callback(GSignondPlugin* plugin, GSignondSessionData* result,
                     gpointer user_data)
{
    response_callback(plugin, result, user_data);
}

static void user_action_required_callback(GSignondPlugin* plugin, 
                                          GSignondSignonuiData* ui_request, 
                                          gpointer user_data)
{
    GSignondSignonuiData** user_data_p = user_data;
    *user_data_p = ui_request;
    gsignond_dictionary_ref(ui_request);
}

static void error_callback(GSignondPlugin* plugin, GError* error,
                     gpointer user_data)
{
    GError** user_data_p = user_data;
    *user_data_p = g_error_copy(error);
}

static GVariant* make_normal_token()
{
    GSignondDictionary* token = gsignond_dictionary_new();
    gsignond_dictionary_set_string(token, "AccessToken", "megaaccesstoken");
    GDateTime* now = g_date_time_new_now_utc();
    gsignond_dictionary_set_int64(token, "Timestamp", 
        g_date_time_to_unix(now));
    g_date_time_unref(now);
    gsignond_dictionary_set_int64(token, "Duration", 3600);
    gsignond_dictionary_set_string(token, "RefreshToken", "megarefreshtoken");
    gsignond_dictionary_set_string(token, "Scope", "scope1 scope2 scope3");
    GVariant* token_var = gsignond_dictionary_to_variant(token);
    gsignond_dictionary_unref(token);
    return token_var;
}

static GVariant* make_expired_token()
{
    GSignondDictionary* token = gsignond_dictionary_new();
    gsignond_dictionary_set_string(token, "AccessToken", "megaaccesstoken");
    GDateTime* now = g_date_time_new_now_utc();
    gsignond_dictionary_set_int64(token, "Timestamp", 
        g_date_time_to_unix(now) - 7200);
    g_date_time_unref(now);
    gsignond_dictionary_set_int64(token, "Duration", 3600);
    gsignond_dictionary_set_string(token, "RefreshToken", "megarefreshtoken");
    gsignond_dictionary_set_string(token, "Scope", "scope1 scope2 scope3");
    GVariant* token_var = gsignond_dictionary_to_variant(token);
    gsignond_dictionary_unref(token);
    return token_var;
}

static GSignondDictionary* make_tokens(const gchar* client_id, GVariant* token)
{
    GSignondDictionary* tokens = gsignond_dictionary_new();
    GSignondDictionary* client_tokens = gsignond_dictionary_new();
    gsignond_dictionary_set(client_tokens, "scope1 scope2 scope3", token);
    gsignond_dictionary_set(tokens, client_id, gsignond_dictionary_to_variant(client_tokens));
    gsignond_dictionary_unref(client_tokens);
    return tokens;
}

static GVariant* make_no_refresh_token()
{
    GSignondDictionary* token = gsignond_dictionary_new();
    gsignond_dictionary_set_string(token, "AccessToken", "megaaccesstoken");
    GDateTime* now = g_date_time_new_now_utc();
    gsignond_dictionary_set_int64(token, "Timestamp", 
        g_date_time_to_unix(now));
    g_date_time_unref(now);
    gsignond_dictionary_set_int64(token, "Duration", 3600);
    gsignond_dictionary_set_string(token, "Scope", "scope1 scope2 scope3");
    GVariant* token_var = gsignond_dictionary_to_variant(token);
    gsignond_dictionary_unref(token);
    return token_var;
}

static GVariant* make_no_refresh_expired_token()
{
    GSignondDictionary* token = gsignond_dictionary_new();
    gsignond_dictionary_set_string(token, "AccessToken", "megaaccesstoken");
    GDateTime* now = g_date_time_new_now_utc();
    gsignond_dictionary_set_int64(token, "Timestamp", 
        g_date_time_to_unix(now) - 7200);
    g_date_time_unref(now);
    gsignond_dictionary_set_int64(token, "Duration", 3600);
    gsignond_dictionary_set_string(token, "Scope", "scope1 scope2 scope3");
    GVariant* token_var = gsignond_dictionary_to_variant(token);
    gsignond_dictionary_unref(token);
    return token_var;
}

START_TEST (test_oauth2_request)
{
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();

    // unknown mechanism
    gsignond_plugin_request_initial(plugin, data, NULL, "unknown-mech");

    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MECHANISM_NOT_AVAILABLE));
    g_error_free(error);
    error = NULL;
    
    // empty data
    gsignond_plugin_request_initial(plugin, data, NULL, "oauth2");

    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;
    
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    GSignondDictionary* tokens =  make_tokens("megaclient", make_normal_token());
    
    // try using expired token
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_unref(tokens);
    tokens = make_tokens("megaclient", make_no_refresh_expired_token());
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;

    // try token with incorrect (too narrow) scopes
    gsignond_dictionary_unref(tokens);
    tokens = make_tokens("megaclient", make_no_refresh_token());
    gsignond_dictionary_set_string(data, "Scope", "scope2 scope3 scope4");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;

    // try correct token without requesting scopes
    gsignond_dictionary_remove(data, "Scope");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "megaaccesstoken") != 0);
    fail_if(gsignond_dictionary_get(result, "RefreshToken") != NULL);
    gint64 expires_in;
    fail_if(gsignond_dictionary_get_int64(result, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 3600);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);
    
    // try correct token with requesting a subset of scopes
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "megaaccesstoken") != 0);
    fail_if(gsignond_dictionary_get(result, "RefreshToken") != NULL);
    fail_if(gsignond_dictionary_get_int64(result, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 3600);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);
    
    //don't reuse token
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_REQUEST_PASSWORD);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_if(g_strcmp0(error->message, "Unknown ResponseType or GrantType") != 0);
    g_error_free(error);
    error = NULL;

    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
}
END_TEST

START_TEST (test_oauth2_allowed_realms)
{
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("someclient", make_normal_token());
    
    // allowed realms is absent
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "ResponseType", "code");
    gsignond_dictionary_set_string(data, "AuthHost", "somehost.somedomain.com");
    gsignond_dictionary_set_string(data, "AuthPath", "/somepath");
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_if(g_strcmp0(error->message, "Missing realm list") != 0);
    g_error_free(error);
    error = NULL;
    
    //allowed realms is empty
    const gchar *empty_realm_list[] = { NULL };
    GSequence *allowed_realms = gsignond_copy_array_to_sequence(empty_realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_strcmp0(error->message, "Unauthorized host") != 0);
    g_error_free(error);
    error = NULL;

    //allowed realms does not contain same domain
    const gchar *non_realm_list[] = { "somedomain1.com", "somedomain2.com", "somedomain3.com", NULL };
    allowed_realms = gsignond_copy_array_to_sequence(non_realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_strcmp0(error->message, "Unauthorized host") != 0);
    g_error_free(error);
    error = NULL;
    
    //allowed realms contains same domain
    const gchar *realm_list[] = { "otherhost.somedomain.com", "somehost.somedomain.com", "thehost.somedomain.com", NULL };
    allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);

    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
}
END_TEST

START_TEST (test_oauth2_ui_request)
{
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("someclient", make_normal_token());
    
    // minimum set of input data that's sufficient
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "ResponseType", "code");
    gsignond_dictionary_set_string(data, "AuthHost", "somehost");
    gsignond_dictionary_set_string(data, "AuthPath", "/somepath");
    const gchar *realm_list[] = { "somehost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    // https://somehost/somepath?response%5Ftype=code&
    // state=lf7B9OsYHdmzWDEkQjYR0oae6HU%3D&client%5Fid=megaclient
    SoupURI* uri = soup_uri_new(gsignond_signonui_data_get_open_url(ui_action));
    fail_if(g_strcmp0(soup_uri_get_scheme(uri), "https") != 0);
    fail_if(g_strcmp0(soup_uri_get_host(uri), "somehost") != 0);
    fail_if(g_strcmp0(soup_uri_get_path(uri), "/somepath") != 0);
    fail_if(soup_uri_get_port(uri) != 443);
    GHashTable* query = soup_form_decode(soup_uri_get_query(uri));
    fail_if (query == NULL);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "response_type"), "code") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "client_id"), "megaclient") != 0);
    const gchar* state = g_hash_table_lookup(query, "state");
    fail_if(strlen(state) < 28);
    fail_if(state[strlen(state)-1] != '=');
    fail_if(g_strcmp0(state, gsignond_dictionary_get_string(data, "_Oauth2State")) != 0);
    g_hash_table_unref(query);
    soup_uri_free(uri);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);

    //maximum possible set of input data
    gsignond_dictionary_remove(data, "_Oauth2State");
    gsignond_dictionary_set_string(data, "ResponseType", "token");
    gsignond_dictionary_set_uint32(data, "AuthPort", 1234);
    gsignond_dictionary_set_string(data, "AuthQuery", "queryparam1=value1&queryparam2=value2");
    gsignond_dictionary_set_string(data, "RedirectUri", "http://somehost/login.html");
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    gsignond_dictionary_set_boolean(data, "UseLoginHint", TRUE);
    gsignond_dictionary_set_string(data, "UseDisplay", "popup");
    gsignond_session_data_set_username(data, "megauser");
    gsignond_session_data_set_secret(data, "megapassword");    

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    fail_if(g_strcmp0(gsignond_signonui_data_get_username(ui_action), "megauser") != 0);
    fail_if(g_strcmp0(gsignond_signonui_data_get_password(ui_action), "megapassword") != 0);
    fail_if(g_strcmp0(gsignond_signonui_data_get_final_url(ui_action), 
                      "http://somehost/login.html") != 0);

    //https://somehost:1234/somepath?scope=scope1+scope3&response%5Ftype=token&
    //state=YSecnz09LD3%2FEGaLfZhRsKeIGtk%3D&queryparam1=value1&queryparam2=value2&
    //redirect%5Furi=http%3A%2F%2Fsomehost%2Flogin%2Ehtml&client%5Fid=megaclient
    uri = soup_uri_new(gsignond_signonui_data_get_open_url(ui_action));
    fail_if(g_strcmp0(soup_uri_get_scheme(uri), "https") != 0);
    fail_if(g_strcmp0(soup_uri_get_host(uri), "somehost") != 0);
    fail_if(g_strcmp0(soup_uri_get_path(uri), "/somepath") != 0);
    fail_if(soup_uri_get_port(uri) != 1234);
    query = soup_form_decode(soup_uri_get_query(uri));
    fail_if (query == NULL);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "scope"), "scope1 scope3") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "queryparam1"), "value1") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "queryparam2"), "value2") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "redirect_uri"), "http://somehost/login.html") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "response_type"), "token") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "client_id"), "megaclient") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "login_hint"), "megauser") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(query, "display"), "popup") != 0);
    state = g_hash_table_lookup(query, "state");
    fail_if(strlen(state) < 28);
    fail_if(state[strlen(state)-1] != '=');
    fail_if(g_strcmp0(state, gsignond_dictionary_get_string(data, "_Oauth2State")) != 0);
    g_hash_table_unref(query);
    soup_uri_free(uri);    
    
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
}
END_TEST

START_TEST (test_oauth2_implicit)
{
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;
    
    gchar* url;
    gchar* params;
    //gsize len;
    
    //GSignondDictionary* store_tokens;
    GSignondDictionary* token;
    GSignondDictionary* client_tokens;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("someotherclient", 
                                                        make_no_refresh_expired_token());

    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "AuthHost", "somehost");
    gsignond_dictionary_set_string(data, "AuthPath", "/somepath");
    gsignond_dictionary_set_string(data, "ResponseType", "token");
    gsignond_dictionary_set_string(data, "RedirectUri", "http://somehost/login.html");
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    const gchar *realm_list[] = { "somehost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);

    GSignondSignonuiData* ui_data = gsignond_dictionary_new();
    //empty ui response
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_USER_INTERACTION));
    g_error_free(error);
    error = NULL;
    
    // ui interaction error
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_CANCELED);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_SESSION_CANCELED));
    g_error_free(error);
    error = NULL;
    
    // no error, but missing response URL
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_NONE);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;
    
    //response URL doesn't match redirect url
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    gsignond_signonui_data_set_url_response(ui_data, "http://wronghost/login.html");
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;

    //returned state doesn't match generated state
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    gsignond_signonui_data_set_url_response(ui_data, 
                                            "http://somehost/login.html#state=reallywrongstate");
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;

    //return an error 
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "error", "someerror",
                              "error_description", "somedesc",
                              "error_uri", "someuri",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;

    //no access token
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;

    //access token exists, but no token type
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "access_token", "megatoken",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;

    // unknown token type
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "access_token", "meganewtoken",
                              "token_type", "strangetokentype",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;

    //return token and token type but no other parameters, with requested scope
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "access_token", "meganewtoken",
                              "token_type", "Bearer",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(result, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(result, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(result, "Duration") != NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope3") != 0);
    fail_if(gsignond_dictionary_get(result, "RefreshToken") != NULL);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    fail_if(g_hash_table_size(store) != 2);
    client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope3"));
    fail_if(token == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(token, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(token, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(token, "Duration") != NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope3") != 0);
    fail_if(gsignond_dictionary_get(token, "RefreshToken") != NULL);
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
    
    //return token and token type but no other parameters, with
    //no requested scope
    gsignond_dictionary_remove(tokens, "megaclient");
    gsignond_dictionary_remove(data, "Scope");
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "access_token", "meganewtoken",
                              "token_type", "Bearer",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(result, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(result, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(result, "Duration") != NULL);
    fail_if(gsignond_dictionary_get(result, "Scope") == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "") != 0);
    fail_if(gsignond_dictionary_get(result, "RefreshToken") != NULL);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    fail_if(g_hash_table_size(store) != 2);
    client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, ""));
    fail_if(token == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(token, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(token, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(token, "Duration") != NULL);
    fail_if(gsignond_dictionary_get(token, "Scope") == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "") != 0);
    fail_if(gsignond_dictionary_get(token, "RefreshToken") != NULL);
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);    
    
    
    //return token and token type and all other parameters, with scope
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    //const gchar* scopes[] = { "scope1", "scope3", NULL };
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "access_token", "meganewtoken",
                              "token_type", "Bearer",
                              "expires_in", "7200",
                              "scope", "scope1 scope2 scope3",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(result, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(result, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(result, "Duration") == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope2 scope3") != 0);
    fail_if(gsignond_dictionary_get(result, "RefreshToken") != NULL);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    fail_if(g_hash_table_size(store) != 2);
    client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope2 scope3"));
    fail_if(token == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(token, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(token, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(token, "Duration") == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope2 scope3") != 0);
    fail_if(gsignond_dictionary_get(token, "RefreshToken") != NULL);
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
    
    //return token and token type and all other parameters, with 
    //no requested scope
    gsignond_dictionary_remove(tokens, "megaclient");    
    gsignond_dictionary_remove(data, "Scope");
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);
    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "access_token", "meganewtoken",
                              "token_type", "Bearer",
                              "expires_in", "7200",
                              "scope", "scope1 scope2 scope3",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html#%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(result, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(result, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(result, "Duration") == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope2 scope3") != 0);
    fail_if(gsignond_dictionary_get(result, "RefreshToken") != NULL);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    fail_if(g_hash_table_size(store) != 2);
    client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope2 scope3"));
    fail_if(token == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "meganewtoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get(token, "TokenParameters") == NULL);
    fail_if(gsignond_dictionary_get(token, "Timestamp") == NULL);
    fail_if(gsignond_dictionary_get(token, "Duration") == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope2 scope3") != 0);
    fail_if(gsignond_dictionary_get(token, "RefreshToken") != NULL);
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
    
    gsignond_dictionary_unref(ui_data);
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
}
END_TEST

static void
refresh_token_server_callback (SoupServer        *server,
         SoupMessage       *msg, 
         const char        *path,
         GHashTable        *query,
         SoupClientContext *client,
         gpointer           user_data)
{
    const gchar* normal_token_response = "{ \n\
       \"access_token\":\"new-mega-token\",\n\
       \"token_type\":\"Bearer\",\n\
       \"expires_in\":1800,\n\
       \"refresh_token\":\"new-refresh-token\",\n\
       \"scope\":\"scope1 scope2 scope3\"\n\
     }";
     const gchar* invalid_grant_error = "{\n\
       \"error\":\"invalid_grant\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";
     const gchar* generic_error = "{\n\
       \"error\":\"invalid_request\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";

    fail_if(g_str_has_prefix (path, "/tokenpath") == FALSE);
    fail_if(g_strcmp0(msg->method, "POST") != 0);
    fail_if(g_strcmp0(soup_message_headers_get_content_type(
         msg->request_headers, NULL), "application/x-www-form-urlencoded") != 0);
     
    SoupBuffer* request = soup_message_body_flatten(msg->request_body);
    GHashTable* params = soup_form_decode(request->data);
    soup_buffer_free(request);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "grant_type"), "refresh_token") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "refresh_token"), "megarefreshtoken") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "scope"), "scope1 scope3") != 0);        
    g_hash_table_unref(params);

    if (g_strrstr(path, "error/invalid_grant") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               invalid_grant_error, strlen(invalid_grant_error));
    } else if (g_strrstr(path, "error") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               generic_error, strlen(generic_error));
    } else {
        soup_message_set_status (msg, SOUP_STATUS_OK);
        soup_message_set_response (msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               normal_token_response, strlen(normal_token_response));
    }
}

START_TEST (test_oauth2_refresh)
{
    // to genenerate cert and key
    // openssl genrsa -out privkey.pem 2048
    // openssl req -new -x509 -key privkey.pem -out cacert.pem -days 365000
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/tokenpath", refresh_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);    
    
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;
    
    GSignondDictionary* token;
    GSignondDictionary* client_tokens;

    
    //gsize len;
    gint64 expires_in;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("megaclient", 
                                                        make_expired_token());

    // try using expired token
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "TokenHost", "localhost");
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath");
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    const gchar *realm_list[] = { "localhost", "somehost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(result != NULL)
            break;
    }
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(result, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope2 scope3"));
    fail_if(token == NULL);
    
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(token, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope2 scope3") != 0);
    
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);

    //try with incorrect http port
    gsignond_dictionary_unref(tokens);
    tokens = make_tokens("megaclient", make_expired_token());
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server) + 1);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(error != NULL)
            break;
    }
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Token endpoint returned an error") == FALSE);
    g_error_free(error);
    error = NULL;
    
    // try with generic error
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath/error");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(error != NULL)
            break;
    }
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Authorization server returned an error") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //try with invalid grant error, should get a ui request
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath/error/invalid_grant");
    gsignond_dictionary_set_string(data, "ResponseType", "code");
    gsignond_dictionary_set_string(data, "AuthHost", "somehost");
    gsignond_dictionary_set_string(data, "AuthPath", "/somepath");
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(ui_action != NULL)
            break;
    }
    fail_if(result != NULL);    
    fail_if(ui_action == NULL);
    
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);

    //the following two cases are for testing forcing the use of refresh token
    //first check that without forcing the use a token from cache is returned
    gsignond_dictionary_unref(tokens);
    tokens = make_tokens("megaclient", make_normal_token());
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result == NULL);    
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);
   
    //now force the use of refresh token
    gsignond_dictionary_set_boolean(data, "ForceTokenRefresh", TRUE);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(result != NULL)
            break;
    }
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(result, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope2 scope3"));
    fail_if(token == NULL);
    
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(token, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope2 scope3") != 0);
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
   
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
    g_object_unref(server);
}
END_TEST

static gboolean
client_auth_callback (SoupAuthDomain *domain, SoupMessage *msg,
           const char *username, const char *password,
           gpointer user_data)
{
    return (g_strcmp0 (password, "megapassword") == 0 &&
            g_strcmp0 (username, "megaclient") == 0);
}

START_TEST (test_oauth2_client_basic_auth)
{
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    SoupAuthDomain *domain = soup_auth_domain_basic_new (
        SOUP_AUTH_DOMAIN_REALM, "My Realm",
        SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, client_auth_callback,
        SOUP_AUTH_DOMAIN_ADD_PATH, "/tokenpath",
        NULL);
    soup_server_add_auth_domain (server, domain);
    g_object_unref (domain);    
    soup_server_add_handler (server, "/tokenpath", refresh_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);    
    
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;
    
    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("megaclient", 
                                                        make_expired_token());

    //try with client authorization using absent client credentials
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "TokenHost", "localhost");
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath");
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);

    const gchar *realm_list[] = { "localhost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(error != NULL)
            break;
    }
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Token endpoint returned an error") == FALSE);
    g_error_free(error);
    error = NULL;

    //try with client authorization using incorrect client credentials
    gsignond_dictionary_set_string(data, "ClientSecret", "incorrectpassword");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(error != NULL)
            break;
    }
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Token endpoint returned an error") == FALSE);
    g_error_free(error);
    error = NULL;

    //try with ForceClientAuthViaRequestBody set to TRUE
    gsignond_dictionary_set_boolean(data, "ForceClientAuthViaRequestBody", TRUE);
    gsignond_dictionary_set_string(data, "ClientSecret", "megapassword");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(error != NULL)
            break;
    }
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Token endpoint returned an error") == FALSE);
    g_error_free(error);
    error = NULL;

    
    //try with client authorization using correct client credentials
    gsignond_dictionary_set_boolean(data, "ForceClientAuthViaRequestBody", FALSE);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(result != NULL)
            break;
    }
    fail_if(result == NULL);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
    
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
    g_object_unref(server);
}
END_TEST


static void
request_body_auth_server_callback (SoupServer        *server,
         SoupMessage       *msg, 
         const char        *path,
         GHashTable        *query,
         SoupClientContext *client,
         gpointer           user_data)
{
    const gchar* normal_token_response = "{ \n\
       \"access_token\":\"new-mega-token\",\n\
       \"token_type\":\"Bearer\",\n\
       \"expires_in\":1800,\n\
       \"refresh_token\":\"new-refresh-token\",\n\
       \"scope\":\"scope1 scope2 scope3\"\n\
     }";
     const gchar* invalid_grant_error = "{\n\
       \"error\":\"invalid_grant\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";
     const gchar* generic_error = "{\n\
       \"error\":\"invalid_request\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";

    fail_if(g_str_has_prefix (path, "/tokenpath") == FALSE);
    fail_if(g_strcmp0(msg->method, "POST") != 0);
    fail_if(g_strcmp0(soup_message_headers_get_content_type(
         msg->request_headers, NULL), "application/x-www-form-urlencoded") != 0);
     
    SoupBuffer* request = soup_message_body_flatten(msg->request_body);
    GHashTable* params = soup_form_decode(request->data);
    soup_buffer_free(request);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "grant_type"), "refresh_token") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "refresh_token"), "megarefreshtoken") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "scope"), "scope1 scope3") != 0);
    
    gboolean auth_error = FALSE;
    if (g_strcmp0(g_hash_table_lookup(params, "client_id"), "megaclient") != 0 ||
        g_strcmp0(g_hash_table_lookup(params, "client_secret"), "megapassword") != 0) {
            auth_error = TRUE;
    }
    g_hash_table_unref(params);

    if (g_strrstr(path, "error/invalid_grant") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               invalid_grant_error, strlen(invalid_grant_error));
    } else if (g_strrstr(path, "error") != NULL || auth_error == TRUE) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               generic_error, strlen(generic_error));
    } else {
        soup_message_set_status (msg, SOUP_STATUS_OK);
        soup_message_set_response (msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               normal_token_response, strlen(normal_token_response));
    }
}


START_TEST (test_oauth2_client_request_body_auth)
{
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/tokenpath", request_body_auth_server_callback,
             NULL, NULL);
    soup_server_run_async(server);    
    
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;
    
    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("megaclient", 
                                                        make_expired_token());

    //try with client authorization using absent ForceClientAuthViaRequestBody
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_dictionary_set_string(data, "ClientSecret", "megapassword");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "TokenHost", "localhost");
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath");
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);

    const gchar *realm_list[] = { "localhost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(error != NULL)
            break;
    }
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Authorization server returned an error") == FALSE);
    g_error_free(error);
    error = NULL;

    //try with ForceClientAuthViaRequestBody set to TRUE
    gsignond_dictionary_set_boolean(data, "ForceClientAuthViaRequestBody", TRUE);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(result != NULL)
            break;
    }
    fail_if(result == NULL);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
    
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
    g_object_unref(server);
}
END_TEST


static void
password_token_server_callback (SoupServer        *server,
         SoupMessage       *msg, 
         const char        *path,
         GHashTable        *query,
         SoupClientContext *client,
         gpointer           user_data)
{
    const gchar* normal_token_response = "{ \n\
       \"access_token\":\"new-mega-token\",\n\
       \"token_type\":\"Bearer\",\n\
       \"expires_in\":1800,\n\
       \"refresh_token\":\"new-refresh-token\",\n\
       \"scope\":\"scope1 scope2 scope3\"\n\
     }";
     const gchar* invalid_grant_error = "{\n\
       \"error\":\"invalid_grant\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";
     const gchar* generic_error = "{\n\
       \"error\":\"invalid_request\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";

    fail_if(g_str_has_prefix (path, "/tokenpath") == FALSE);
    fail_if(g_strcmp0(msg->method, "POST") != 0);
    fail_if(g_strcmp0(soup_message_headers_get_content_type(
         msg->request_headers, NULL), "application/x-www-form-urlencoded") != 0);
     
    SoupBuffer* request = soup_message_body_flatten(msg->request_body);
    GHashTable* params = soup_form_decode(request->data);
    soup_buffer_free(request);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "grant_type"), "password") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "username"), "megauser") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "password"), "megapassword") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "scope"), "scope1 scope3") != 0);        
    g_hash_table_unref(params);

    if (g_strrstr(path, "error/invalid_grant") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               invalid_grant_error, strlen(invalid_grant_error));
    } else if (g_strrstr(path, "error") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               generic_error, strlen(generic_error));
    } else {
        soup_message_set_status (msg, SOUP_STATUS_OK);
        soup_message_set_response (msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               normal_token_response, strlen(normal_token_response));
    }
}

START_TEST (test_oauth2_owner_password)
{
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/tokenpath", password_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);    
    
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;
    
    //gsize len;
    gint64 expires_in;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("someclient", 
                                                        make_expired_token());

    // try a default scenario
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "TokenHost", "localhost");
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath");
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);

    const gchar *realm_list[] = { "localhost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);

    gsignond_dictionary_set_string(data, "GrantType", "password");
    gsignond_session_data_set_username(data, "megauser");
    gsignond_session_data_set_secret(data, "megapassword");    
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(result != NULL)
            break;
    }
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(result, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    GSignondDictionary* client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    GSignondDictionary* token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope2 scope3"));
    fail_if(token == NULL);
    
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(token, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);

    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
    g_object_unref(server);
}
END_TEST

static void
client_credentials_token_server_callback (SoupServer        *server,
         SoupMessage       *msg, 
         const char        *path,
         GHashTable        *query,
         SoupClientContext *client,
         gpointer           user_data)
{
    const gchar* normal_token_response = "{ \n\
       \"access_token\":\"new-mega-token\",\n\
       \"token_type\":\"Bearer\",\n\
       \"expires_in\":1800,\n\
       \"refresh_token\":\"new-refresh-token\",\n\
       \"scope\":\"scope1 scope2 scope3\"\n\
     }";
     const gchar* invalid_grant_error = "{\n\
       \"error\":\"invalid_grant\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";
     const gchar* generic_error = "{\n\
       \"error\":\"invalid_request\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";

    fail_if(g_str_has_prefix (path, "/tokenpath") == FALSE);
    fail_if(g_strcmp0(msg->method, "POST") != 0);
    fail_if(g_strcmp0(soup_message_headers_get_content_type(
         msg->request_headers, NULL), "application/x-www-form-urlencoded") != 0);
     
    SoupBuffer* request = soup_message_body_flatten(msg->request_body);
    GHashTable* params = soup_form_decode(request->data);
    soup_buffer_free(request);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "grant_type"), "client_credentials") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "scope"), "scope1 scope3") != 0);        
    g_hash_table_unref(params);

    if (g_strrstr(path, "error/invalid_grant") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               invalid_grant_error, strlen(invalid_grant_error));
    } else if (g_strrstr(path, "error") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               generic_error, strlen(generic_error));
    } else {
        soup_message_set_status (msg, SOUP_STATUS_OK);
        soup_message_set_response (msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               normal_token_response, strlen(normal_token_response));
    }
}

START_TEST (test_oauth2_client_credentials)
{
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/tokenpath", client_credentials_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);    
    
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;
    
    //gsize len;
    gint64 expires_in;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("someclient", 
                                                        make_expired_token());

    // try a default scenario
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "TokenHost", "localhost");
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath");
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    const gchar *realm_list[] = { "localhost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);

    gsignond_dictionary_set_string(data, "GrantType", "client_credentials");
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(result != NULL)
            break;
    }
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "new-mega-token") != 0);
    // client credentials grant isn't eligible for refresh tokens (see RFC6749)
    fail_if(gsignond_dictionary_get_string(result, "RefreshToken") != NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(result, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    GSignondDictionary* client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    GSignondDictionary* token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope2 scope3"));
    fail_if(token == NULL);
    
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(gsignond_dictionary_get_string(token, "RefreshToken") != NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(token, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);

    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
    g_object_unref(server);
}
END_TEST

static void
authorization_code_token_server_callback (SoupServer        *server,
         SoupMessage       *msg, 
         const char        *path,
         GHashTable        *query,
         SoupClientContext *client,
         gpointer           user_data)
{
    const gchar* normal_token_response = "{ \n\
       \"access_token\":\"new-mega-token\",\n\
       \"token_type\":\"Bearer\",\n\
       \"expires_in\":1800,\n\
       \"refresh_token\":\"new-refresh-token\",\n\
       \"scope\":\"scope1 scope2 scope3\"\n\
     }";
     const gchar* invalid_grant_error = "{\n\
       \"error\":\"invalid_grant\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";
     const gchar* generic_error = "{\n\
       \"error\":\"invalid_request\",\n\
       \"error_description\":\"some description\",\n\
       \"error_uri\":\"some uri\"\n\
     }";

    fail_if(g_str_has_prefix (path, "/tokenpath") == FALSE);
    fail_if(g_strcmp0(msg->method, "POST") != 0);
    fail_if(g_strcmp0(soup_message_headers_get_content_type(
         msg->request_headers, NULL), "application/x-www-form-urlencoded") != 0);
     
    SoupBuffer* request = soup_message_body_flatten(msg->request_body);
    GHashTable* params = soup_form_decode(request->data);
    soup_buffer_free(request);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "grant_type"), "authorization_code") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "code"), "mega-auth-code") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "redirect_uri"), "http://somehost/login.html") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(params, "client_id"), "megaclient") != 0);        
    g_hash_table_unref(params);

    if (g_strrstr(path, "error/invalid_grant") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               invalid_grant_error, strlen(invalid_grant_error));
    } else if (g_strrstr(path, "error") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
        soup_message_set_response(msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               generic_error, strlen(generic_error));
    } else {
        soup_message_set_status (msg, SOUP_STATUS_OK);
        soup_message_set_response (msg, "application/json;charset=UTF-8", 
                               SOUP_MEMORY_STATIC,
                               normal_token_response, strlen(normal_token_response));
    }
}

START_TEST (test_oauth2_authorization_code)
{
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/tokenpath", authorization_code_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);    
    
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_OAUTH_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* store = NULL;
    GSignondSignonuiData* ui_action = NULL;
    GError* error = NULL;
    
    //gsize len;
    gint64 expires_in;
    gchar* url;
    gchar* params;    

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), &ui_action);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), &store);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* tokens = make_tokens("someclient", make_expired_token());
    GSignondSignonuiData* ui_data = gsignond_dictionary_new();
    
    gsignond_dictionary_set_string(data, "ClientId", "megaclient");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "TokenHost", "localhost");
    gsignond_dictionary_set_string(data, "TokenPath", "/tokenpath");
    gsignond_dictionary_set_uint32(data, "TokenPort", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "Scope", "scope1 scope3");
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);

    gsignond_dictionary_set_string(data, "AuthHost", "somehost");
    gsignond_dictionary_set_string(data, "AuthPath", "/somepath");
    gsignond_dictionary_set_string(data, "ResponseType", "code");
    gsignond_dictionary_set_string(data, "RedirectUri", "http://somehost/login.html");
    const gchar *realm_list[] = { "localhost", "somehost", NULL };
    GSequence* allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);

    //authentication code is absent
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);  

    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              NULL);
    url = g_strdup_printf("http://somehost/login.html?%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_NONE);
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, "Authorization endpoint didn't issue an\
 authorization code") == FALSE);
    g_error_free(error);
    error = NULL;

    //authentication code is present 
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth2");
    fail_if(result != NULL);
    fail_if(ui_action == NULL);
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);  

    params = soup_form_encode("state", 
                              gsignond_dictionary_get_string(data, "_Oauth2State"),
                              "code", "mega-auth-code",
                              NULL);
    url = g_strdup_printf("http://somehost/login.html?%s", params);
    gsignond_signonui_data_set_url_response(ui_data, url);
    g_free(url);
    g_free(params);
    gsignond_plugin_user_action_finished(plugin, ui_data);

    while (1) {
        g_main_context_iteration(g_main_context_default(), TRUE);
        if(result != NULL)
            break;
    }
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(result, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);
    GSignondDictionary* client_tokens = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    GSignondDictionary* token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(client_tokens, "scope1 scope2 scope3"));
    fail_if(token == NULL);
    
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "AccessToken"),
                      "new-mega-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "RefreshToken"),
                      "new-refresh-token") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "TokenType"),
                      "Bearer") != 0);
    fail_if(gsignond_dictionary_get_int64(token, "Duration", &expires_in) != TRUE);
    fail_if(expires_in != 1800);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(token, "Scope"), "scope1 scope2 scope3") != 0);
    
    gsignond_dictionary_unref(token);
    gsignond_dictionary_unref(client_tokens);

    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);

    gsignond_dictionary_unref(ui_data);
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
    g_object_unref(server);
}
END_TEST

//printf("%s\n",g_variant_print(gsignond_dictionary_to_variant(store), TRUE));

void add_oauth2_tcase(Suite *s)
{
    TCase *tc_oauth2 = tcase_create ("OAuth 2 tests");
    tcase_add_test (tc_oauth2, test_oauth2_request);
    tcase_add_test (tc_oauth2, test_oauth2_allowed_realms);
    tcase_add_test (tc_oauth2, test_oauth2_ui_request);
    tcase_add_test (tc_oauth2, test_oauth2_implicit);
    tcase_add_test (tc_oauth2, test_oauth2_refresh);
    tcase_add_test (tc_oauth2, test_oauth2_client_basic_auth);
    tcase_add_test (tc_oauth2, test_oauth2_client_request_body_auth);
    tcase_add_test (tc_oauth2, test_oauth2_owner_password);
    tcase_add_test (tc_oauth2, test_oauth2_client_credentials);
    tcase_add_test (tc_oauth2, test_oauth2_authorization_code);
    suite_add_tcase (s, tc_oauth2);
}

