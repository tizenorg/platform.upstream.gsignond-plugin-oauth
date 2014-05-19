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

#include <gsignond/gsignond-plugin-interface.h>
#include "gsignond-oauth-plugin.h"
#include "gsignond-oauth-plugin-utils.h"
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-log.h>
#include <gsignond/gsignond-utils.h>
#include <stdlib.h>
#include <string.h>
#include <libsoup/soup.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

void _do_reset_oauth1(GSignondOauthPlugin *self)
{
    if (self->oauth1_request) {
        gsignond_dictionary_unref(self->oauth1_request);
        self->oauth1_request = NULL;
    }
    if (self->token_cache) {
        gsignond_dictionary_unref(self->token_cache);
        self->token_cache = NULL;
    }
}

gboolean _is_active_oauth1_session(GSignondOauthPlugin *self)
{
    if (self->oauth1_request)
        return TRUE;
    else
        return FALSE;
}

static gchar* _percent_encode(const gchar* s)
{
    GString *str;
    char *encoded;

    str = g_string_new (NULL);
    
    while (*s) {
        if (g_ascii_isalnum(*s) ||strchr ("-._~", *s))
            g_string_append_c (str, *s++);
        else
            g_string_append_printf (str, "%%%02X", (int)*s++);
    }
    encoded = str->str;
    g_string_free (str, FALSE);

    return encoded;
    
}

static GSignondDictionary* _respond_with_stored_token(
                                           GSignondDictionary *token, 
                                           const gchar *requested_realm_s)
{
    const gchar* token_realm_s = gsignond_dictionary_get_string(token, "Realm");

    //requested_realm must be same as token realm
    if (g_strcmp0(requested_realm_s, token_realm_s) != 0)
        return NULL;

    GVariant* token_variant = gsignond_dictionary_get(token, "AccessToken");
    GVariant* token_secret = gsignond_dictionary_get(token, "TokenSecret");
    if (token_variant != NULL && token_secret != NULL) {
        GSignondSessionData* response = gsignond_dictionary_new();
        gsignond_dictionary_set(response, "AccessToken", token_variant);
        gsignond_dictionary_set(response, "TokenSecret", token_secret);
        GVariant* token_params = gsignond_dictionary_get(token, "TokenParameters");
        if (token_params != NULL)
            gsignond_dictionary_set(response, "TokenParameters", token_params);
        if (token_realm_s != NULL) {
            gsignond_dictionary_set_string(response, "Realm", token_realm_s);
        }
        return response;
    }
    return NULL;
}

static void _insert_key_value(gpointer key, gpointer value, gpointer table)
{
    g_hash_table_insert(table, key, value);
}

static void
_temporary_token_callback (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
    GError* error = NULL;
    GSignondOauthPlugin *self = GSIGNOND_OAUTH_PLUGIN(user_data);

    if (msg->status_code != SOUP_STATUS_OK) {
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Temporary token endpoint returned an error: %d %s",
                                msg->status_code, msg->reason_phrase);
        goto out;
    }

    SoupBuffer* response_s = soup_message_body_flatten(msg->response_body);
    GHashTable* response = soup_form_decode(response_s->data);
    soup_buffer_free(response_s);

    const gchar* callback_confirmed = g_hash_table_lookup(response, "oauth_callback_confirmed");
    const gchar* token = g_hash_table_lookup(response, "oauth_token");
    const gchar* token_secret = g_hash_table_lookup(response, "oauth_token_secret");        

    if (token == NULL || token_secret == NULL || g_strcmp0(callback_confirmed, "true") != 0) {
        g_hash_table_destroy(response);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Temporary token endpoint returned an invalid response");
        goto out;
    }

    const gchar* callback_url = gsignond_dictionary_get_string(self->oauth1_request, 
                                                               "Callback");
    if (callback_url == NULL) {                                                                    
        g_hash_table_destroy(response);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Client did not supply Callback");
        goto out;
    }

    const gchar* authorization_url_s = gsignond_dictionary_get_string(self->oauth1_request, 
                                                                    "AuthorizationEndpoint");
    if (authorization_url_s == NULL) {                                                                    
        g_hash_table_destroy(response);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Client did not supply AuthorizationEndpoint");
        goto out;
    }
    
    SoupURI* authorization_url = soup_uri_new(authorization_url_s);
    if (authorization_url == NULL) {
        g_hash_table_destroy(response);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Client did not supply a valid AuthorizationEndpoint");
        goto out;
    }
    gsignond_oauth_plugin_check_host(soup_uri_get_host(authorization_url),
        gsignond_session_data_get_allowed_realms (self->oauth1_request), &error);
    if (error != NULL) {
        soup_uri_free(authorization_url);
        g_hash_table_destroy(response);
        return;
    }
    
    GHashTable* query = g_hash_table_new((GHashFunc)g_str_hash,
                                             (GEqualFunc)g_str_equal);
    const gchar* authorization_query_s = soup_uri_get_query(authorization_url);
    GHashTable *auth_query = NULL;
    if (authorization_query_s != NULL) {
        auth_query = soup_form_decode(authorization_query_s);
        g_hash_table_foreach(auth_query, _insert_key_value, query);
    }
    g_hash_table_insert(query, "oauth_token", (gchar*)token);
    soup_uri_set_query_from_form(authorization_url, query);
    if (auth_query)
        g_hash_table_destroy(auth_query);
    g_hash_table_destroy(query);
    
    gchar* open_url = soup_uri_to_string(authorization_url, FALSE);
    soup_uri_free(authorization_url);
    
    gsignond_dictionary_set_string(self->oauth1_request, "_OauthTemporaryToken", token);
    gsignond_dictionary_set_string(self->oauth1_request, "_OauthTemporaryTokenSecret", token_secret);
    
    GSignondSignonuiData* ui_request = gsignond_dictionary_new();
    gsignond_signonui_data_set_open_url(ui_request, open_url);
    g_free(open_url);
        
    if (g_strcmp0(callback_url, "oob") != 0)
        gsignond_signonui_data_set_final_url(ui_request, callback_url);
        
    /* add username and password, for fields initialization (the
     * decision on whether to actually use them is up to the signon UI */
    const gchar* username = gsignond_session_data_get_username(self->oauth1_request);
    if (username != NULL)
        gsignond_signonui_data_set_username(ui_request, username);
    const gchar* secret = gsignond_session_data_get_secret(self->oauth1_request);
    if (secret != NULL)
        gsignond_signonui_data_set_password(ui_request, secret);


     gsignond_plugin_user_action_required(GSIGNOND_PLUGIN(self), ui_request);
     gsignond_dictionary_unref(ui_request);    

    g_hash_table_destroy(response);

out:
   if (error != NULL) {
        _do_reset_oauth1(self);
        gsignond_plugin_error (GSIGNOND_PLUGIN(self), error);
        g_error_free(error);
   }
}

static gchar* _make_secret_key(GSignondSessionData *session_data)
{
    const gchar* consumer_secret = gsignond_dictionary_get_string(session_data,
                                                                  "ConsumerSecret");
    const gchar* token_secret = gsignond_dictionary_get_string(session_data,
                                                                  "_OauthTemporaryTokenSecret");
    if (consumer_secret == NULL)
        consumer_secret = "";
    if (token_secret == NULL)
        token_secret = "";
    
    gchar* consumer_secret_encoded = _percent_encode(consumer_secret);
    gchar* token_secret_encoded = _percent_encode(token_secret);
    
    GString* key = g_string_new("");
    g_string_printf(key, "%s&%s", consumer_secret_encoded, token_secret_encoded);
    g_free(consumer_secret_encoded);
    g_free(token_secret_encoded);
    return g_string_free(key, FALSE);
}

static gchar* _get_timestamp()
{
    GDateTime* now = g_date_time_new_now_utc();
    gint64 timestamp = g_date_time_to_unix(now);
    g_date_time_unref(now);
    return g_strdup_printf("%"G_GINT64_FORMAT, timestamp);
}

static void _insert_into_tree(gpointer key, gpointer value, gpointer user_data)
{
    g_tree_insert(user_data, key, value);
}

static gboolean _make_parameters_string(gpointer key, gpointer value, gpointer user_data)
{
    gchar* key_encoded = _percent_encode(key);
    gchar* value_encoded = value ? _percent_encode(value) : _percent_encode("");
    
    g_string_append(user_data, key_encoded);
    g_string_append(user_data, "=");
    g_string_append(user_data, value_encoded);
    g_string_append(user_data, "&");
    g_free(key_encoded);
    g_free(value_encoded);
    return FALSE;
}

static gchar* _make_base_string(
                                GSignondSessionData *session_data, 
                                SoupURI* uri, gchar* nonce, gchar* timestamp)
{
    GString* base_string = g_string_new("POST&");
    
    gchar* base_uri;
    if (soup_uri_uses_default_port(uri))
        base_uri = g_strdup_printf("https://%s%s", soup_uri_get_host(uri),
                                                    soup_uri_get_path(uri));
    else
        base_uri = g_strdup_printf("https://%s:%u%s", soup_uri_get_host(uri),
                                                       soup_uri_get_port(uri),
                                                       soup_uri_get_path(uri));
    gchar* base_uri_e = _percent_encode(base_uri);
    g_string_append(base_string, base_uri_e);
    g_string_append(base_string, "&");
    g_free(base_uri);
    g_free(base_uri_e);
    
    GTree* parameters = g_tree_new((GCompareFunc)g_strcmp0);
    
    const gchar* query_s = soup_uri_get_query(uri);
    GHashTable* query;
    if (query_s != NULL)
        query = soup_form_decode(query_s);
    else    
        query = soup_form_decode("");
   
    g_hash_table_foreach(query, _insert_into_tree, parameters);
    
    const gchar* callback_uri = gsignond_dictionary_get_string(session_data, "Callback");
    if (callback_uri != NULL)
        g_tree_insert(parameters, "oauth_callback", (gchar*)callback_uri);
    const gchar* oauth_verifier = gsignond_dictionary_get_string(session_data, "_OauthVerifier");
    if (oauth_verifier != NULL)
        g_tree_insert(parameters, "oauth_verifier", (gchar*)oauth_verifier);
    g_tree_insert(parameters, "oauth_consumer_key", (gchar*)gsignond_dictionary_get_string(session_data, "ConsumerKey"));
    const gchar* oauth_temp_token = gsignond_dictionary_get_string(session_data, "_OauthTemporaryToken");
    if (oauth_temp_token != NULL)
        g_tree_insert(parameters, "oauth_token", (gchar*)oauth_temp_token);
    g_tree_insert(parameters, "oauth_signature_method", (gchar*)gsignond_dictionary_get_string(session_data, "SignatureMethod"));
    g_tree_insert(parameters, "oauth_nonce", nonce);
    g_tree_insert(parameters, "oauth_timestamp", timestamp);
    g_tree_insert(parameters, "oauth_version", "1.0");
    
    GString* parameters_string = g_string_new(NULL);
    g_tree_foreach(parameters, _make_parameters_string, parameters_string);
    gchar* parameters_s = g_string_free(parameters_string, FALSE);
    parameters_s[strlen(parameters_s)-1] = '\0'; //remove trailing '&'
    gchar* parameters_encoded = _percent_encode(parameters_s);
    g_string_append(base_string, parameters_encoded);
    
    g_free(parameters_encoded);
    g_free(parameters_s);
    g_tree_destroy(parameters);
    g_hash_table_destroy(query);
    
    return g_string_free(base_string, FALSE);
}

static gchar* _make_hmacsha1_base64_signature(const gchar* base_string, 
                                             const gchar* key)
{
    gsize digest_len = 100; //sha1 is actually 160 bits
    guint8 hmac_digest[digest_len];

    GHmac* hmac = g_hmac_new(G_CHECKSUM_SHA1, (const guchar*)key, strlen(key));
    g_hmac_update(hmac, (const guchar*)base_string, strlen(base_string));
    g_hmac_get_digest(hmac, hmac_digest, &digest_len);
    g_hmac_unref(hmac);

    gchar* out = g_malloc0((digest_len / 3 + 1) * 4 + 4);
    gint state = 0;
    gint save = 0;
    gchar* p = out;
    
    p += g_base64_encode_step(hmac_digest, digest_len,
                             FALSE, p, &state, &save);
    g_base64_encode_close(FALSE, p, &state, &save);
    
    return out;
   
}

static gchar* _make_rsasha1_base64_signature(const gchar* base_string, 
                                             const gchar* key)
{
    gnutls_privkey_t pkey;
    gnutls_x509_privkey_t x509_pkey;
    gnutls_datum_t pkey_data;
    gnutls_datum_t signature;
    
    gchar* out = NULL;

    pkey_data.data = (guchar*)key;
    pkey_data.size = strlen(key);

    gnutls_privkey_init(&pkey);
    gnutls_x509_privkey_init(&x509_pkey);
    
    int res = gnutls_x509_privkey_import(x509_pkey, &pkey_data, GNUTLS_X509_FMT_PEM);
    if (res != GNUTLS_E_SUCCESS) {
        goto out;
    }
    
    res = gnutls_privkey_import_x509(pkey, x509_pkey, 0);
    
    if (res != GNUTLS_E_SUCCESS) {
        goto out;
    }

    res = gnutls_privkey_sign_data(pkey, GNUTLS_DIG_SHA1, 0, &pkey_data,
                                   &signature);
    if (res != GNUTLS_E_SUCCESS) {
        goto out;
    }

    out = g_malloc0((signature.size / 3 + 1) * 4 + 4);
    gint state = 0;
    gint save = 0;
    gchar* p = out;
    
    p += g_base64_encode_step(signature.data, signature.size,
                             FALSE, p, &state, &save);
    g_base64_encode_close(FALSE, p, &state, &save);
    
    gnutls_free(signature.data);
out:
    gnutls_x509_privkey_deinit(x509_pkey);
    gnutls_privkey_deinit(pkey);
    
    return out;
    
}

static gchar* _make_authorization_header(
                                       GSignondSessionData *session_data,
                                       SoupURI* uri,
                                       GError** error
                                        )
{
    GString* header = g_string_new("OAuth ");
    
    const gchar* realm = gsignond_dictionary_get_string(session_data, "Realm");
    if (realm != NULL) {
        gchar* realm_e = _percent_encode(realm);
        soup_header_g_string_append_param_quoted (header, "realm", realm_e);
        g_free(realm_e);
        g_string_append (header, ", ");
    }
    
    const gchar* callback_uri = gsignond_dictionary_get_string(session_data, "Callback");
    if (callback_uri != NULL) {
        gchar* callback_uri_e = _percent_encode(callback_uri);
        soup_header_g_string_append_param_quoted (header, "oauth_callback", callback_uri_e);
        g_free(callback_uri_e);
        g_string_append (header, ", ");
    }

    const gchar* oauth_verifier = gsignond_dictionary_get_string(session_data, "_OauthVerifier");
    if (oauth_verifier != NULL) {
        gchar* oauth_verifier_e = _percent_encode(oauth_verifier);
        soup_header_g_string_append_param_quoted (header, "oauth_verifier", oauth_verifier_e);
        g_free(oauth_verifier_e);
        g_string_append (header, ", ");
    }
    
    const gchar* oauth_consumer_key = gsignond_dictionary_get_string(session_data, "ConsumerKey");
    if (oauth_consumer_key == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                             GSIGNOND_ERROR_MISSING_DATA,
                             "Client did not supply ConsumerKey");
        g_string_free(header, TRUE);
        return NULL;
    }
    gchar* oauth_consumer_key_e = _percent_encode(oauth_consumer_key);
    soup_header_g_string_append_param_quoted (header, "oauth_consumer_key", oauth_consumer_key_e);
    g_free(oauth_consumer_key_e);
    g_string_append (header, ", ");
    
    const gchar* oauth_temp_token = gsignond_dictionary_get_string(session_data, "_OauthTemporaryToken");
    if (oauth_temp_token != NULL) {
        gchar* oauth_temp_token_e = _percent_encode(oauth_temp_token);
        soup_header_g_string_append_param_quoted (header, "oauth_token", oauth_temp_token_e);
        g_free(oauth_temp_token_e);
        g_string_append (header, ", ");
    }
    
    const gchar* oauth_signature_method = gsignond_dictionary_get_string(session_data, 
                                                                   "SignatureMethod");
    if (g_strcmp0(oauth_signature_method, "PLAINTEXT") == 0) {
        gchar* secret_key = _make_secret_key(session_data);
        gchar* secret_key_e = _percent_encode(secret_key);
        g_free(secret_key);
        soup_header_g_string_append_param_quoted(header, "oauth_signature",
                                                 secret_key_e);
        g_free(secret_key_e);
        g_string_append (header, ", ");
    } else if (g_strcmp0(oauth_signature_method, "HMAC-SHA1") == 0) {
        gchar* nonce = gsignond_oauth_plugin_generate_random_data(20);
        gchar* nonce_e = _percent_encode(nonce);
        gchar* timestamp = _get_timestamp();
        gchar* base_string = _make_base_string(session_data, uri, nonce, timestamp);
        gchar* key = _make_secret_key(session_data);
        gchar* signature = _make_hmacsha1_base64_signature(base_string, key);
        gchar* signature_e = _percent_encode(signature);
        soup_header_g_string_append_param_quoted(header, "oauth_nonce",
                                                 nonce_e);
        g_string_append (header, ", ");        
        soup_header_g_string_append_param_quoted(header, "oauth_timestamp",
                                                 timestamp);
        g_string_append (header, ", ");
        soup_header_g_string_append_param_quoted(header, "oauth_signature",
                                                 signature_e);
        g_string_append (header, ", ");
        
        g_free(signature_e);
        g_free(signature);
        g_free(key);
        g_free(base_string);
        g_free(timestamp);
        g_free(nonce_e);
        g_free(nonce);
        
    } else if (g_strcmp0(oauth_signature_method, "RSA-SHA1") == 0) {
        const gchar* key = gsignond_dictionary_get_string(session_data, "RSAPrivateKey");
        if (key == NULL) {
            *error = g_error_new(GSIGNOND_ERROR,
                                 GSIGNOND_ERROR_MISSING_DATA,
                                 "Client did not supply RSAPrivateKey");
            g_string_free(header, TRUE);
            return NULL;
        }
        gchar* nonce = gsignond_oauth_plugin_generate_random_data(160);
        gchar* nonce_e = _percent_encode(nonce);
        gchar* timestamp = _get_timestamp();
        gchar* base_string = _make_base_string(session_data, uri, nonce, timestamp);
        gchar* signature = _make_rsasha1_base64_signature(base_string, key);
        if (signature == NULL) {
            *error = g_error_new(GSIGNOND_ERROR,
                                 GSIGNOND_ERROR_MISSING_DATA,
                                 "Invalid RSA private key");
            g_string_free(header, TRUE);
            g_free(base_string);
            g_free(timestamp);
            g_free(nonce_e);
            g_free(nonce);
            return NULL;
        }
        gchar* signature_e = _percent_encode(signature);
        soup_header_g_string_append_param_quoted(header, "oauth_nonce",
                                                 nonce_e);
        g_string_append (header, ", ");        
        soup_header_g_string_append_param_quoted(header, "oauth_timestamp",
                                                 timestamp);
        g_string_append (header, ", ");
        soup_header_g_string_append_param_quoted(header, "oauth_signature",
                                                 signature_e);
        g_string_append (header, ", ");
        
        g_free(signature_e);
        g_free(signature);
        g_free(base_string);
        g_free(timestamp);
        g_free(nonce_e);
        g_free(nonce);
    } else {
        *error = g_error_new(GSIGNOND_ERROR,
                             GSIGNOND_ERROR_MISSING_DATA,
                             "Unknown oauth1 signature method");
        g_string_free(header, TRUE);
        return NULL;
    }
    
    soup_header_g_string_append_param_quoted(header, "oauth_signature_method",
                                             oauth_signature_method);
    g_string_append (header, ", ");
    soup_header_g_string_append_param_quoted(header, "oauth_version", "1.0");
    
    return g_string_free(header, FALSE);
}

static void _request_temporary_token(GSignondOauthPlugin *self, 
                             GSignondSessionData *session_data,
                             GError** error
                                    )
{
    //GSignondPlugin* plugin = GSIGNOND_PLUGIN(self);

    const gchar* endpoint_url_s = gsignond_dictionary_get_string(session_data,
                                                               "RequestEndpoint");
    if (endpoint_url_s == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "Client did not supply RequestEndpoint");
        return;
    }
    
    SoupURI* endpoint_uri = soup_uri_new(endpoint_url_s);
    if (endpoint_uri == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "Client did not supply a valid RequestEndpoint");
        return;
    }
    
    if (g_strcmp0(soup_uri_get_scheme(endpoint_uri), "https") != 0) {
        soup_uri_free(endpoint_uri);
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "RequestEndpoint must use https");
        return;
    }
    gsignond_oauth_plugin_check_host(soup_uri_get_host(endpoint_uri),
        gsignond_session_data_get_allowed_realms (session_data), error);
    if (*error != NULL) {
        soup_uri_free(endpoint_uri);
        return;
    }
    
    gchar* authorization_header = _make_authorization_header(
                                                             session_data, 
                                                             endpoint_uri,
                                                             error);
    if (*error == NULL) {
        SoupMessage *msg = soup_message_new_from_uri ("POST", endpoint_uri);
        soup_message_headers_append(msg->request_headers, "Authorization",
                                    authorization_header);
        g_free(authorization_header);
        soup_session_queue_message (self->soup_session, 
                                    msg, 
                                    _temporary_token_callback, 
                                    self);
    }
    soup_uri_free(endpoint_uri);
}


void _process_oauth1_request(GSignondOauthPlugin *self, 
                             GSignondSessionData *session_data,
                             GSignondDictionary *tokens
                            )
{
    //GSignondPlugin* plugin = GSIGNOND_PLUGIN(self);
    GError* error = NULL;
    const gchar* consumer_key = gsignond_dictionary_get_string(session_data, "ConsumerKey");
    
    if (consumer_key == NULL) {
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "Client did not supply ConsumerKey");
        goto out;
    }

    GSignondUiPolicy ui_policy;
    if (gsignond_session_data_get_ui_policy(session_data, &ui_policy) == FALSE) {
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "Client did not supply ui policy");
        goto out;
    }

    if (ui_policy != GSIGNOND_UI_POLICY_REQUEST_PASSWORD &&
        ui_policy != GSIGNOND_UI_POLICY_DEFAULT) {
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "UI policy must be set to default or REQUEST_PASSWORD");
        goto out;
    }

    if (tokens == NULL) {
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "Client did not supply token cache");
        goto out;
    }

    GVariant* token_variant = gsignond_dictionary_get(tokens, consumer_key);
    GSignondDictionary* token = NULL;

    // use old token only if ui policy is not REQUEST_PASSWORD
    if (token_variant != NULL && ui_policy == GSIGNOND_UI_POLICY_DEFAULT) {
        token = gsignond_dictionary_new_from_variant(token_variant);
    }
    
    if (token != NULL) {
        const gchar* realm = gsignond_dictionary_get_string(session_data, "Realm");
        GSignondDictionary* response = _respond_with_stored_token(token, realm);
        if (response) {
            gsignond_dictionary_unref(token);
            gsignond_plugin_response_final(GSIGNOND_PLUGIN(self), response);
            gsignond_dictionary_unref(response);
            goto out;
        }
        gsignond_dictionary_unref(token);
    }

    self->oauth1_request = session_data;
    gsignond_dictionary_ref(session_data);
    self->token_cache = tokens;
    gsignond_dictionary_ref(tokens);

    _request_temporary_token(self, session_data, &error);

out:
   if (error != NULL) {
        _do_reset_oauth1(self);
        gsignond_plugin_error (GSIGNOND_PLUGIN(self), error);
        g_error_free(error);
   }
}

static void _insert_token_parameters(gpointer key, gpointer value, gpointer parameters_dict)
{
    if (g_strcmp0(key, "oauth_token") != 0 && g_strcmp0(key, "oauth_token_verifier") != 0)
        gsignond_dictionary_set_string(parameters_dict, key, value);
}

static void
_access_token_callback (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
    GError* error = NULL;
    GSignondOauthPlugin *self = GSIGNOND_OAUTH_PLUGIN(user_data);

    if (msg->status_code != SOUP_STATUS_OK) {
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Access token endpoint returned an error: %d %s",
                                msg->status_code, msg->reason_phrase);
        goto out;
    }

    SoupBuffer* response_s = soup_message_body_flatten(msg->response_body);
    GHashTable* response = soup_form_decode(response_s->data);
    soup_buffer_free(response_s);

    const gchar* token = g_hash_table_lookup(response, "oauth_token");
    const gchar* token_secret = g_hash_table_lookup(response, "oauth_token_secret");        

    if (token == NULL || token_secret == NULL) {
        g_hash_table_destroy(response);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Access token endpoint returned an invalid response");
        goto out;
    }
    
    GSignondDictionary* token_dict = gsignond_dictionary_new();
    gsignond_dictionary_set_string(token_dict, "AccessToken", token);
    gsignond_dictionary_set_string(token_dict, "TokenSecret", token_secret);

    const gchar* realm = gsignond_dictionary_get_string(self->oauth1_request,
                                                        "Realm");
    if (realm != NULL)
        gsignond_dictionary_set_string(token_dict, "Realm", realm);

    GSignondDictionary* parameters_dict = gsignond_dictionary_new();
    g_hash_table_foreach(response, _insert_token_parameters, parameters_dict);
    g_hash_table_destroy(response);
    gsignond_dictionary_set(token_dict, "TokenParameters",
                            gsignond_dictionary_to_variant(parameters_dict));
    gsignond_dictionary_unref(parameters_dict);
    
    const gchar* client_id = gsignond_dictionary_get_string(self->oauth1_request, "ConsumerKey");
    gsignond_dictionary_set(self->token_cache, client_id, 
                            gsignond_dictionary_to_variant(token_dict));
    
    gsignond_plugin_store(GSIGNOND_PLUGIN(self), self->token_cache);
    
    _do_reset_oauth1(self);
    gsignond_plugin_response_final(GSIGNOND_PLUGIN(self), token_dict);
    gsignond_dictionary_unref(token_dict);

out:
   if (error != NULL) {
        _do_reset_oauth1(self);
        gsignond_plugin_error (GSIGNOND_PLUGIN(self), error);
        g_error_free(error);
   }

}

static void _request_access_token(GSignondOauthPlugin *self, 
                             GSignondSessionData *session_data,
                             GError** error
                                 )
{
    //GSignondPlugin* plugin = GSIGNOND_PLUGIN(self);

    const gchar* endpoint_url_s = gsignond_dictionary_get_string(session_data,
                                                               "TokenEndpoint");
    if (endpoint_url_s == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                             GSIGNOND_ERROR_MISSING_DATA,
                             "Client did not supply TokenEndpoint");
        return;
    }
    SoupURI* endpoint_uri = soup_uri_new(endpoint_url_s);
    if (endpoint_uri == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                             GSIGNOND_ERROR_MISSING_DATA,
                             "Client did not supply a valid TokenEndpoint");
        return;
    }
    
    if (g_strcmp0(soup_uri_get_scheme(endpoint_uri), "https") != 0) {
        soup_uri_free(endpoint_uri);
        *error = g_error_new(GSIGNOND_ERROR,
                             GSIGNOND_ERROR_MISSING_DATA,
                             "TokenEndpoint must use https");
        return;
    }
    gsignond_oauth_plugin_check_host(soup_uri_get_host(endpoint_uri),
        gsignond_session_data_get_allowed_realms (session_data), error);
    if (*error != NULL) {
        soup_uri_free(endpoint_uri);
        return;
    }
    
    gchar* authorization_header = _make_authorization_header(
                                                             session_data, 
                                                             endpoint_uri,
                                                             error
                                                            );
    if (*error == NULL) {
        SoupMessage *msg = soup_message_new_from_uri ("POST", endpoint_uri);
        soup_message_headers_append(msg->request_headers, "Authorization",
                                    authorization_header);
        g_free(authorization_header);
        soup_session_queue_message (self->soup_session, 
                                    msg, 
                                    _access_token_callback, 
                                    self);
    }
    soup_uri_free(endpoint_uri);
}



void _process_oauth1_user_action_finished(GSignondOauthPlugin *self, 
                                         GSignondSignonuiData *ui_data)
{
    GError* error = NULL;
    GSignondSignonuiError query_error;
    gboolean res = gsignond_signonui_data_get_query_error(ui_data,
                                                          &query_error);
    if (res == FALSE) {
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_USER_INTERACTION,
                                "userActionFinished did not return an error value");
        goto out;
    }
    if (query_error == SIGNONUI_ERROR_CANCELED) {
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_SESSION_CANCELED,
                                "Session canceled");
        goto out;
    } else if (query_error != SIGNONUI_ERROR_NONE) {
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_USER_INTERACTION,
                                "userActionFinished error: %d",
                                query_error);
        goto out;
    }

    const gchar* response_url = gsignond_signonui_data_get_url_response(ui_data);
    const gchar* callback_uri = gsignond_dictionary_get_string(
        self->oauth1_request, "Callback");
    if (response_url == NULL || callback_uri == NULL ||
        g_str_has_prefix(response_url, callback_uri) == FALSE) {
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Callback URI and URI supplied by UI don't match");
        goto out;
    }
    
    SoupURI* response = soup_uri_new(response_url);
    const gchar* query = soup_uri_get_query(response);
    if (query == NULL) {
        soup_uri_free(response);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "No query in returned redirect URI");
        goto out;
    }
    GHashTable* params = soup_form_decode(query);
    soup_uri_free(response);

    const gchar* oauth_token_response = g_hash_table_lookup(params, "oauth_token");
    if (g_strcmp0(oauth_token_response, 
                  gsignond_dictionary_get_string(self->oauth1_request,
                                                 "_OauthTemporaryToken")) != 0) {
        g_hash_table_destroy(params);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Token returned by callback URI and temporary token don't match");
        goto out;
    }
    
    const gchar* oauth_verifier = g_hash_table_lookup(params, "oauth_verifier");
    if (oauth_verifier == NULL) {
        g_hash_table_destroy(params);
        error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "No oauth_verifier in callback URI");
        goto out;
    }
    
    gsignond_dictionary_set_string(self->oauth1_request, "_OauthVerifier", oauth_verifier);
    gsignond_dictionary_remove(self->oauth1_request, "Callback");
    g_hash_table_destroy(params);
    
    _request_access_token(self, self->oauth1_request, &error);
out:
   if (error != NULL) {
        _do_reset_oauth1(self);
        gsignond_plugin_error (GSIGNOND_PLUGIN(self), error);
        g_error_free(error);
   }

}
