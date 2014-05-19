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
    gsignond_dictionary_set_string(token, "TokenSecret", "megatokensecret");
    gsignond_dictionary_set_string(token, "Realm", "megarealm");
    GVariant* token_var = gsignond_dictionary_to_variant(token);
    gsignond_dictionary_unref(token);
    return token_var;
}

static GVariant* make_no_realm_token()
{
    GSignondDictionary* token = gsignond_dictionary_new();
    gsignond_dictionary_set_string(token, "AccessToken", "megaaccesstoken");
    gsignond_dictionary_set_string(token, "TokenSecret", "megatokensecret");
    GVariant* token_var = gsignond_dictionary_to_variant(token);
    gsignond_dictionary_unref(token);
    return token_var;
}

static GSignondDictionary* make_tokens(const gchar* client_id, GVariant* token)
{
    GSignondDictionary* tokens = gsignond_dictionary_new();
    gsignond_dictionary_set(tokens, client_id, token);
    return tokens;
}

START_TEST (test_oauth1_request)
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
    GSignondDictionary* tokens = make_tokens("megaclient", make_normal_token());

    // unknown mechanism
    gsignond_plugin_request_initial(plugin, data, tokens, "unknown-mech");

    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MECHANISM_NOT_AVAILABLE));
    g_error_free(error);
    error = NULL;
    
    // empty data
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;

    gsignond_dictionary_set_string(data, "ConsumerKey", "megaclient");
    
    // try using normal token without requesting realm
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_unref(tokens);
    tokens = make_tokens("megaclient", make_normal_token());
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;    

    // try using normal token with realm
    gsignond_dictionary_set_string(data, "Realm", "megarealm");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "megaaccesstoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenSecret"),
                      "megatokensecret") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "Realm"),
                      "megarealm") != 0);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);
    
    //try using no-realm token with realm request
    gsignond_dictionary_unref(tokens);
    tokens = make_tokens("megaclient", make_no_realm_token());
    gsignond_dictionary_set_string(data, "Realm", "megarealm");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;
    
    //try using no-realm token with no-realm request
    gsignond_dictionary_remove(data, "Realm");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result == NULL);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "AccessToken"),
                      "megaaccesstoken") != 0);
    fail_if(g_strcmp0(gsignond_dictionary_get_string(result, "TokenSecret"),
                      "megatokensecret") != 0);
    fail_if(gsignond_dictionary_get(result, "Realm") != NULL);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error != NULL);

    //don't reuse token
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_REQUEST_PASSWORD);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;

    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);    
}
END_TEST

START_TEST (test_oauth1_allowed_realms)
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
    GSignondDictionary* tokens = make_tokens("someotherclient", make_normal_token());
    gsignond_dictionary_set_string(data, "ConsumerKey", "megaclient");
    gsignond_dictionary_set_string(data, "Realm", "megarealm");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "RequestEndpoint", "https://localhost/somepath");    
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");

    //no allowed realms
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_unless(g_strcmp0(error->message, "Missing realm list") == 0);
    g_error_free(error);
    error = NULL;
    
    //allowed realms is empty
    const gchar *empty_realm_list[] = { NULL };
    GSequence *allowed_realms = gsignond_copy_array_to_sequence(empty_realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_unless(g_strcmp0(error->message, "Unauthorized host") == 0);
    g_error_free(error);
    error = NULL;

    //allowed realms does not contain same domain
    const gchar *non_realm_list[] = { "somedomain1.com", "somedomain2.com", "somedomain3.com", NULL };
    allowed_realms = gsignond_copy_array_to_sequence(non_realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_unless(g_strcmp0(error->message, "Unauthorized host") == 0);
    g_error_free(error);
    error = NULL;

    //allowed realms contains same domain
    const gchar *realm_list[] = { "otherhost.somedomain.com", "localhost", "thehost.somedomain.com", NULL };
    allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_unless(g_strcmp0(error->message, "Unknown oauth1 signature method") == 0);
    g_error_free(error);
    error = NULL;

    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
}
END_TEST 

static void check_nonce(const gchar* nonce)
{
    fail_if(nonce == NULL);
    fail_if(strlen(nonce) < 20);
}

static void check_timestamp(const gchar* timestamp)
{
    fail_if(timestamp == NULL);
    fail_if(strlen(timestamp) < 10);
}

static void check_hmac_sha1_signature(const gchar* signature)
{
    gsize sig_len;
    guchar* signature_decoded = g_base64_decode_inplace(
                                            soup_uri_decode(signature), &sig_len);
    
    fail_if(sig_len != 20);
   
    g_free(signature_decoded);
}

static void check_rsa_sha1_signature(const gchar* signature)
{
    gsize sig_len;
    guchar* signature_decoded = g_base64_decode_inplace(
                                            soup_uri_decode(signature), &sig_len);

    fail_if(sig_len != 256);
   
    g_free(signature_decoded);
}


static void
temporary_token_server_callback (SoupServer        *server,
         SoupMessage       *msg, 
         const char        *path,
         GHashTable        *query,
         SoupClientContext *client,
         gpointer           user_data)
{
    const gchar* normal_token_response = "oauth_token=hh5s93j4hdidpola&\
oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true";
    const gchar* invalid_body_error = "some invalid body";

    fail_if(g_str_has_prefix (path, "/temporarytokenpath") == FALSE);
    fail_if(g_strcmp0(msg->method, "POST") != 0);
    const char* authorization = soup_message_headers_get_one(msg->request_headers,
                                                             "Authorization");
    fail_if(authorization == NULL);
    //printf("temporary auth header %s\n", authorization);
    fail_unless(g_str_has_prefix(authorization, "OAuth "));
    GHashTable* auth_params = soup_header_parse_param_list (authorization+6);
    
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "realm"), "megarealm") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_consumer_key"), "megaclient") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_version"), "1.0") != 0);
    gchar* oauth_callback = soup_uri_decode(g_hash_table_lookup(auth_params, "oauth_callback"));
    fail_if(g_strcmp0(oauth_callback, "http://localhost/somegsignondoauthcallback") != 0);
    g_free(oauth_callback);

    const gchar* signature_method = g_hash_table_lookup(auth_params, "oauth_signature_method");
    if (g_strcmp0(signature_method, "PLAINTEXT") == 0) {
        fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_signature"), "megasecret%26") != 0);
    } else if (g_strcmp0(signature_method, "HMAC-SHA1") == 0) {
        check_nonce(g_hash_table_lookup(auth_params, "oauth_nonce"));
        check_timestamp(g_hash_table_lookup(auth_params, "oauth_timestamp"));
        check_hmac_sha1_signature(g_hash_table_lookup(auth_params, "oauth_signature"));
    } else if (g_strcmp0(signature_method, "RSA-SHA1") == 0) {
        check_nonce(g_hash_table_lookup(auth_params, "oauth_nonce"));
        check_timestamp(g_hash_table_lookup(auth_params, "oauth_timestamp"));
        check_rsa_sha1_signature(g_hash_table_lookup(auth_params, "oauth_signature"));
    }
    
    soup_header_free_param_list(auth_params);

    if (g_strrstr(path, "error/invalid_body") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_OK);
        soup_message_set_response(msg, "application/x-www-form-urlencoded", 
                               SOUP_MEMORY_STATIC,
                               invalid_body_error, strlen(invalid_body_error));
    } else if (g_strrstr(path, "error") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
    } else {
        soup_message_set_status (msg, SOUP_STATUS_OK);
        soup_message_set_response (msg, "application/x-www-form-urlencoded", 
                               SOUP_MEMORY_STATIC,
                               normal_token_response, strlen(normal_token_response));
    }
}

static void
access_token_server_callback (SoupServer        *server,
         SoupMessage       *msg, 
         const char        *path,
         GHashTable        *query,
         SoupClientContext *client,
         gpointer           user_data)
{
    const gchar* normal_token_response = "oauth_token=j49ddk933skd9dks\
&oauth_token_secret=ll399dj47dskfjdk";
    const gchar* invalid_body_error = "some invalid body";

    fail_if(g_str_has_prefix (path, "/accesstokenpath") == FALSE);
    fail_if(g_strcmp0(msg->method, "POST") != 0);
    const char* authorization = soup_message_headers_get_one(msg->request_headers,
                                                             "Authorization");
    fail_if(authorization == NULL);
    //printf("access auth header %s\n", authorization);
    fail_unless(g_str_has_prefix(authorization, "OAuth "));
    GHashTable* auth_params = soup_header_parse_param_list (authorization+6);
    
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "realm"), "megarealm") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_consumer_key"), "megaclient") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_version"), "1.0") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_verifier"), "somerandomverifier") != 0);
    fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_token"), "hh5s93j4hdidpola") != 0);

    const gchar* signature_method = g_hash_table_lookup(auth_params, "oauth_signature_method");
    if (g_strcmp0(signature_method, "PLAINTEXT") == 0) {
        fail_if(g_strcmp0(g_hash_table_lookup(auth_params, "oauth_signature"), "megasecret%26hdhd0244k9j7ao03") != 0);
    } else if (g_strcmp0(signature_method, "HMAC-SHA1") == 0) {
        check_nonce(g_hash_table_lookup(auth_params, "oauth_nonce"));
        check_timestamp(g_hash_table_lookup(auth_params, "oauth_timestamp"));
        check_hmac_sha1_signature(g_hash_table_lookup(auth_params, "oauth_signature"));
    } else if (g_strcmp0(signature_method, "RSA-SHA1") == 0) {
        check_nonce(g_hash_table_lookup(auth_params, "oauth_nonce"));
        check_timestamp(g_hash_table_lookup(auth_params, "oauth_timestamp"));
        check_rsa_sha1_signature(g_hash_table_lookup(auth_params, "oauth_signature"));
    }
    
    soup_header_free_param_list(auth_params);

    if (g_strrstr(path, "error/invalid_body") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_OK);
        soup_message_set_response(msg, "application/x-www-form-urlencoded", 
                               SOUP_MEMORY_STATIC,
                               invalid_body_error, strlen(invalid_body_error));
    } else if (g_strrstr(path, "error") != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_BAD_REQUEST);
    } else {
        soup_message_set_status (msg, SOUP_STATUS_OK);
        soup_message_set_response (msg, "application/x-www-form-urlencoded", 
                               SOUP_MEMORY_STATIC,
                               normal_token_response, strlen(normal_token_response));
    }
}
    

START_TEST (test_oauth1_request_temporary_token)
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
    GSignondDictionary* tokens = make_tokens("someotherclient", make_normal_token());
    gsignond_dictionary_set_string(data, "ConsumerKey", "megaclient");
    gsignond_dictionary_set_string(data, "Realm", "megarealm");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    
    //no RequestEndpoint
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    g_error_free(error);
    error = NULL;
    
    //RequestEndpoint does not use https
    gsignond_dictionary_set_string(data, "RequestEndpoint", "http://localhost/somepath");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_unless(g_strcmp0(error->message, "RequestEndpoint must use https") == 0);                                
    g_error_free(error);
    error = NULL;
    
    //no signature method
    const gchar *realm_list[] = { "otherhost.somedomain.com", "localhost", "thehost.somedomain.com", NULL };
    GSequence *allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    gsignond_dictionary_set_string(data, "RequestEndpoint", "https://localhost/somepath");    
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_unless(g_strcmp0(error->message, "Unknown oauth1 signature method") == 0);
    g_error_free(error);
    error = NULL;
    
    //unknown signature method
    gsignond_dictionary_set_string(data, "SignatureMethod", "unknownmethod");    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_unless(g_strcmp0(error->message, "Unknown oauth1 signature method") == 0);
    g_error_free(error);
    error = NULL;

    //PLAINTEXT method, but no server
    gsignond_dictionary_set_string(data, "SignatureMethod", "PLAINTEXT");
    gsignond_dictionary_set_string(data, "ConsumerSecret", "megasecret");            
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
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
                             "Temporary token endpoint returned an error") == FALSE);
    g_error_free(error);
    error = NULL;

    //set up the server and try again
    // to genenerate cert and key
    // openssl genrsa -out privkey.pem 2048
    // openssl req -new -x509 -key privkey.pem -out cacert.pem -days 365000
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/temporarytokenpath", temporary_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);
    
    gchar* server_uri = g_strdup_printf("https://localhost:%d/temporarytokenpath", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "RequestEndpoint", server_uri);
    g_free(server_uri);
    gsignond_dictionary_set_string(data, "AuthorizationEndpoint", "https://localhost/authorization");

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
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

    fail_if(g_strcmp0(gsignond_signonui_data_get_open_url(ui_action),
                      "https://localhost/authorization?oauth_token=hh5s93j4hdidpola") != 0);
    fail_if(g_strcmp0(gsignond_signonui_data_get_final_url(ui_action),
                      "http://localhost/somegsignondoauthcallback") != 0);
    
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);    

    //reject the PLAINTEXT request
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    server_uri = g_strdup_printf("https://localhost:%d/temporarytokenpath/error", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "RequestEndpoint", server_uri);
    g_free(server_uri);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
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
                             "Temporary token endpoint returned an error") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //provide invalid data for PLAINTEXT request
    server_uri = g_strdup_printf("https://localhost:%d/temporarytokenpath/error/invalid_body", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "RequestEndpoint", server_uri);
    g_free(server_uri);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
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
                             "Temporary token endpoint returned an invalid response") == FALSE);
    g_error_free(error);
    error = NULL;

    //HMAC-SHA1 request
    gsignond_dictionary_set_string(data, "SignatureMethod", "HMAC-SHA1");
    server_uri = g_strdup_printf("https://localhost:%d/temporarytokenpath", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "RequestEndpoint", server_uri);
    g_free(server_uri);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
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

    fail_if(g_strcmp0(gsignond_signonui_data_get_open_url(ui_action),
                      "https://localhost/authorization?oauth_token=hh5s93j4hdidpola") != 0);
    fail_if(g_strcmp0(gsignond_signonui_data_get_final_url(ui_action),
                      "http://localhost/somegsignondoauthcallback") != 0);
    
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);    
    
    //RSA-SHA1 request with no private key
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_dictionary_set_string(data, "SignatureMethod", "RSA-SHA1");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_if(g_str_has_prefix(error->message, 
                             "Client did not supply RSAPrivateKey") == FALSE);
    g_error_free(error);
    error = NULL;    

    //RSA-SHA1 request with invalid private key
    gsignond_dictionary_set_string(data, "RSAPrivateKey", "some bogus key");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_if(g_str_has_prefix(error->message, 
                             "Invalid RSA private key") == FALSE);
    g_error_free(error);
    error = NULL;    
    
    //RSA-SHA1 request with valid private key
    gchar* privkey;
    fail_unless(g_file_get_contents("privkey.pem", &privkey, NULL, NULL));
    gsignond_dictionary_set_string(data, "RSAPrivateKey", privkey);
    g_free(privkey);
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");
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

    fail_if(g_strcmp0(gsignond_signonui_data_get_open_url(ui_action),
                      "https://localhost/authorization?oauth_token=hh5s93j4hdidpola") != 0);
    fail_if(g_strcmp0(gsignond_signonui_data_get_final_url(ui_action),
                      "http://localhost/somegsignondoauthcallback") != 0);
    
    gsignond_dictionary_unref(ui_action);
    ui_action = NULL;
    fail_if(store != NULL);
    fail_if(error != NULL);    
    
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    g_object_unref(plugin);
    g_object_unref(server);      
}
END_TEST 

START_TEST (test_oauth1_ui_request)
{
    gpointer plugin;
    
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/temporarytokenpath", temporary_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);

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
    GSignondDictionary* tokens = make_tokens("someotherclient", make_normal_token());
    GSignondSignonuiData* ui_data = gsignond_dictionary_new();

    gsignond_dictionary_set_string(data, "ConsumerKey", "megaclient");
    gsignond_dictionary_set_string(data, "Realm", "megarealm");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");
    gsignond_dictionary_set_string(data, "SignatureMethod", "PLAINTEXT");
    gsignond_dictionary_set_string(data, "ConsumerSecret", "megasecret");            
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);
    
    gchar* server_uri = g_strdup_printf("https://localhost:%d/temporarytokenpath", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "RequestEndpoint", server_uri);
    g_free(server_uri);
    gsignond_dictionary_set_string(data, "AuthorizationEndpoint", "https://localhost/authorization");

    const gchar *realm_list[] = { "otherhost.somedomain.com", "localhost", "thehost.somedomain.com", NULL };
    GSequence *allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    //return an empty response
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_USER_INTERACTION));
    fail_if(g_str_has_prefix(error->message, 
                             "userActionFinished did not return an error value") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //ui session was cancelled
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_CANCELED);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_SESSION_CANCELED));
    fail_if(g_str_has_prefix(error->message, 
                             "Session canceled") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //some other ui error
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_BAD_PARAMETERS);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_USER_INTERACTION));
    fail_if(g_str_has_prefix(error->message, 
                             "userActionFinished error:") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //no error, but no final url
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_NONE);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Callback URI and URI supplied by UI don't match") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //final url doesn't match callback url
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_final_url(ui_data, "http://somebogusurl");

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Callback URI and URI supplied by UI don't match") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //correct final url, but no query
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_url_response(ui_data, "http://localhost/somegsignondoauthcallback");

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "No query in returned redirect URI") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //correct final url, with bogus token
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_url_response(ui_data, "http://localhost/somegsignondoauthcallback?oauth_token=somebogustoken");

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "Token returned by callback URI and temporary token don't match") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //correct final url, correct token, absent verifier
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_url_response(ui_data, "http://localhost/somegsignondoauthcallback?oauth_token=hh5s93j4hdidpola");

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    fail_if(g_str_has_prefix(error->message, 
                             "No oauth_verifier in callback URI") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //correct final url, correct token, correct verifier
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_signonui_data_set_url_response(ui_data, "http://localhost/somegsignondoauthcallback?oauth_token=hh5s93j4hdidpola&oauth_verifier=somerandomverifier");

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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
    
    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_if(g_str_has_prefix(error->message, 
                             "Client did not supply TokenEndpoint") == FALSE);
    g_error_free(error);
    error = NULL;
    
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    gsignond_dictionary_unref(ui_data);
    g_object_unref(plugin);
    g_object_unref(server);      
}
END_TEST

START_TEST (test_oauth1_request_access_token)
{
    gpointer plugin;
    
    SoupServer* server = soup_server_new(SOUP_SERVER_SSL_CERT_FILE, "cacert.pem",
                                         SOUP_SERVER_SSL_KEY_FILE, "privkey.pem",
                                         NULL);
    soup_server_add_handler (server, "/temporarytokenpath", temporary_token_server_callback,
             NULL, NULL);
    soup_server_add_handler (server, "/accesstokenpath", access_token_server_callback,
             NULL, NULL);
    soup_server_run_async(server);

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
    GSignondDictionary* tokens = make_tokens("someotherclient", make_normal_token());
    GSignondSignonuiData* ui_data = gsignond_dictionary_new();

    gsignond_dictionary_set_string(data, "ConsumerKey", "megaclient");
    gsignond_dictionary_set_string(data, "Realm", "megarealm");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");
    gsignond_dictionary_set_string(data, "SignatureMethod", "PLAINTEXT");
    gsignond_dictionary_set_string(data, "ConsumerSecret", "megasecret");            
    
    gsignond_dictionary_set_boolean(data, "SslStrict", FALSE);
    
    gchar* server_uri = g_strdup_printf("https://localhost:%d/temporarytokenpath", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "RequestEndpoint", server_uri);
    g_free(server_uri);
    gsignond_dictionary_set_string(data, "AuthorizationEndpoint", "https://localhost/authorization");
    gsignond_signonui_data_set_url_response(ui_data, "http://localhost/somegsignondoauthcallback?oauth_token=hh5s93j4hdidpola&oauth_verifier=somerandomverifier");
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_NONE);

    const gchar *realm_list[] = { "otherhost.somedomain.com", "localhost", "thehost.somedomain.com", NULL };
    GSequence *allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    //bogus token endpoint
    gsignond_dictionary_set_string(data, "TokenEndpoint", "some bogus endpoint");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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

    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_if(g_str_has_prefix(error->message, 
                             "Client did not supply a valid TokenEndpoint") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //token endpoint that doesn't use https
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_dictionary_remove(data, "_OauthVerifier");
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");
    
    gsignond_dictionary_set_string(data, "TokenEndpoint", "http://somehost");
    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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

    gsignond_plugin_user_action_finished(plugin, ui_data);
    fail_if(result != NULL);    
    fail_if(ui_action != NULL);
    fail_if(store != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MISSING_DATA));
    fail_if(g_str_has_prefix(error->message, 
                             "TokenEndpoint must use https") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //token endpoint returned an error
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_dictionary_remove(data, "_OauthVerifier");
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");

    server_uri = g_strdup_printf("https://localhost:%d/accesstokenpath/error", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "TokenEndpoint", server_uri);
    g_free(server_uri);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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

    gsignond_plugin_user_action_finished(plugin, ui_data);
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
                             "Access token endpoint returned an error") == FALSE);
    g_error_free(error);
    error = NULL;
    
    //token endpoint returned a bogus response
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_dictionary_remove(data, "_OauthVerifier");
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");

    server_uri = g_strdup_printf("https://localhost:%d/accesstokenpath/error/invalid_body", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "TokenEndpoint", server_uri);
    g_free(server_uri);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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

    gsignond_plugin_user_action_finished(plugin, ui_data);
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
                             "Access token endpoint returned an invalid response") == FALSE);
    g_error_free(error);
    error = NULL;

    //token endpoint returned a valid response for PLAINTEXT
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_dictionary_remove(data, "_OauthVerifier");
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");

    server_uri = g_strdup_printf("https://localhost:%d/accesstokenpath", soup_server_get_port(server));
    gsignond_dictionary_set_string(data, "TokenEndpoint", server_uri);
    g_free(server_uri);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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

    gsignond_plugin_user_action_finished(plugin, ui_data);
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
    const gchar* realm = gsignond_dictionary_get_string(result, "Realm");
    const gchar* token_s = gsignond_dictionary_get_string(result, "AccessToken");
    const gchar* secret = gsignond_dictionary_get_string(result, "TokenSecret");
    fail_if(g_strcmp0(realm, "megarealm") != 0);
    fail_if(g_strcmp0(token_s, "j49ddk933skd9dks") != 0);
    fail_if(g_strcmp0(secret, "ll399dj47dskfjdk") != 0);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);

    fail_if(g_hash_table_size(store) != 2);
    GSignondDictionary* token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    fail_if(token == NULL);
    realm = gsignond_dictionary_get_string(token, "Realm");
    token_s = gsignond_dictionary_get_string(token, "AccessToken");
    secret = gsignond_dictionary_get_string(token, "TokenSecret");
    fail_if(g_strcmp0(realm, "megarealm") != 0);
    fail_if(g_strcmp0(token_s, "j49ddk933skd9dks") != 0);
    fail_if(g_strcmp0(secret, "ll399dj47dskfjdk") != 0);
    gsignond_dictionary_unref(token);
    
    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
    
    // valid response for HMAC-SHA1
    gsignond_dictionary_remove(tokens, "megaclient");
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_dictionary_remove(data, "_OauthVerifier");
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");
    
    gsignond_dictionary_set_string(data, "SignatureMethod", "HMAC-SHA1");

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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

    gsignond_plugin_user_action_finished(plugin, ui_data);
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
    realm = gsignond_dictionary_get_string(result, "Realm");
    token_s = gsignond_dictionary_get_string(result, "AccessToken");
    secret = gsignond_dictionary_get_string(result, "TokenSecret");
    fail_if(g_strcmp0(realm, "megarealm") != 0);
    fail_if(g_strcmp0(token_s, "j49ddk933skd9dks") != 0);
    fail_if(g_strcmp0(secret, "ll399dj47dskfjdk") != 0);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);

    fail_if(g_hash_table_size(store) != 2);
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    fail_if(token == NULL);
    realm = gsignond_dictionary_get_string(token, "Realm");
    token_s = gsignond_dictionary_get_string(token, "AccessToken");
    secret = gsignond_dictionary_get_string(token, "TokenSecret");
    fail_if(g_strcmp0(realm, "megarealm") != 0);
    fail_if(g_strcmp0(token_s, "j49ddk933skd9dks") != 0);
    fail_if(g_strcmp0(secret, "ll399dj47dskfjdk") != 0);
    gsignond_dictionary_unref(token);
    
    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
    
    // valid response for RSA-SHA1
    gsignond_dictionary_remove(tokens, "megaclient");    
    gsignond_dictionary_remove(data, "_OauthTemporaryToken");
    gsignond_dictionary_remove(data, "_OauthTemporaryTokenSecret");
    gsignond_dictionary_remove(data, "_OauthVerifier");
    gsignond_dictionary_set_string(data, "Callback", "http://localhost/somegsignondoauthcallback");
    
    gsignond_dictionary_set_string(data, "SignatureMethod", "RSA-SHA1");
    gchar* privkey;
    fail_unless(g_file_get_contents("privkey.pem", &privkey, NULL, NULL));
    gsignond_dictionary_set_string(data, "RSAPrivateKey", privkey);
    g_free(privkey);

    gsignond_plugin_request_initial(plugin, data, tokens, "oauth1");

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

    gsignond_plugin_user_action_finished(plugin, ui_data);
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
    realm = gsignond_dictionary_get_string(result, "Realm");
    token_s = gsignond_dictionary_get_string(result, "AccessToken");
    secret = gsignond_dictionary_get_string(result, "TokenSecret");
    fail_if(g_strcmp0(realm, "megarealm") != 0);
    fail_if(g_strcmp0(token_s, "j49ddk933skd9dks") != 0);
    fail_if(g_strcmp0(secret, "ll399dj47dskfjdk") != 0);
    gsignond_dictionary_unref(result);
    result = NULL;
    fail_if(ui_action != NULL);
    fail_if(store == NULL);

    fail_if(g_hash_table_size(store) != 2);
    token = gsignond_dictionary_new_from_variant(
        gsignond_dictionary_get(store, "megaclient"));
    fail_if(token == NULL);
    realm = gsignond_dictionary_get_string(token, "Realm");
    token_s = gsignond_dictionary_get_string(token, "AccessToken");
    secret = gsignond_dictionary_get_string(token, "TokenSecret");
    fail_if(g_strcmp0(realm, "megarealm") != 0);
    fail_if(g_strcmp0(token_s, "j49ddk933skd9dks") != 0);
    fail_if(g_strcmp0(secret, "ll399dj47dskfjdk") != 0);
    gsignond_dictionary_unref(token);
    
    gsignond_dictionary_unref(store);
    store = NULL;
    fail_if(error != NULL);
   
    
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(tokens);
    gsignond_dictionary_unref(ui_data);
    g_object_unref(plugin);
    g_object_unref(server);      
}
END_TEST
    
    

void add_oauth1_tcase(Suite *s)
{
    TCase *tc_oauth2 = tcase_create ("OAuth 1 tests");
    tcase_add_test (tc_oauth2, test_oauth1_request);
    tcase_add_test (tc_oauth2, test_oauth1_allowed_realms);
    tcase_add_test (tc_oauth2, test_oauth1_request_temporary_token);
    tcase_add_test (tc_oauth2, test_oauth1_ui_request);
    tcase_add_test (tc_oauth2, test_oauth1_request_access_token);
    suite_add_tcase (s, tc_oauth2);
}
