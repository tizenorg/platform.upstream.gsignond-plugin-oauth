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
#include <json-glib/json-glib.h>

static void _request_new_token(GSignondOauthPlugin *self, 
                        GSignondSessionData *session_data,
                        GError** error
                              );

static void _process_auth_error(
                                GHashTable* params,
                                GError** error
                               );

static void _process_access_token(GSignondOauthPlugin *self,
                                GHashTable* params,
                                GError** error
                                 );

void _do_reset_oauth2(GSignondOauthPlugin *self)
{
    if (self->oauth2_request) {
        gsignond_dictionary_unref(self->oauth2_request);
        self->oauth2_request = NULL;
    }
    if (self->token_cache) {
        gsignond_dictionary_unref(self->token_cache);
        self->token_cache = NULL;
    }
}

gboolean _is_active_oauth2_session(GSignondOauthPlugin *self)
{
    if (self->oauth2_request)
        return TRUE;
    else
        return FALSE;
}

void _oauth2_http_authenticate(GSignondOauthPlugin *self, SoupAuth *auth)
{
    if (self->oauth2_request == NULL)
        return;
    gboolean force_request_body_auth;
    if (gsignond_dictionary_get_boolean(self->oauth2_request, 
        "ForceClientAuthViaRequestBody",
        &force_request_body_auth) && force_request_body_auth)
        return;

   
    const gchar* client_id = gsignond_dictionary_get_string(self->oauth2_request,
                                                            "ClientId");
    const gchar* client_secret = gsignond_dictionary_get_string(self->oauth2_request,
                                                            "ClientSecret");
    if (client_id != NULL && client_secret != NULL) {
        soup_auth_authenticate(auth, client_id, client_secret);
    }
}

static gboolean _is_scope_subset(const gchar* subset_scope_s, const gchar* superset_scope_s)
{
    gchar** superset_scope = NULL;
    if (superset_scope_s != NULL) {
        superset_scope = g_strsplit(superset_scope_s, " ", 0);
    } else {
        superset_scope = g_malloc0(sizeof(gchar*));
    }

    gchar** subset_scope = NULL;
    if (subset_scope_s != NULL) {
        subset_scope = g_strsplit(subset_scope_s, " ", 0);
    } else {
        subset_scope = g_malloc0(sizeof(gchar*));
    }
        
    //subset_scope must be a subset of superset_scope
    GHashTable* superset_scope_set = g_hash_table_new((GHashFunc)g_str_hash,
                                                    (GEqualFunc)g_str_equal);
    gchar **iter;
    iter = superset_scope;
    while (*iter) {
        g_hash_table_insert(superset_scope_set, *iter, NULL);
        iter++;
    }
    
    iter = subset_scope;
    while (*iter) {
        if (g_hash_table_contains(superset_scope_set, *iter) == FALSE) {
            g_hash_table_unref(superset_scope_set);
            g_strfreev(superset_scope);
            g_strfreev(subset_scope);
            return FALSE;
        }
        iter++;
    }
    
    g_hash_table_unref(superset_scope_set);
    g_strfreev(superset_scope);
    g_strfreev(subset_scope);
    return TRUE;
}


static GSignondDictionary* _respond_with_stored_token(GSignondDictionary *token)
{
    if (token == NULL)
        return FALSE;
    
    gint64 duration;
    gboolean has_duration = gsignond_dictionary_get_int64(token, 
                                                          "Duration",
                                                          &duration);
    gint64 timestamp;
    gboolean has_timestamp = gsignond_dictionary_get_int64(token, 
                                                          "Timestamp",
                                                          &timestamp);
    gint64 expires_in = 0;
    
    if (has_duration && has_timestamp) {
        GDateTime* now = g_date_time_new_now_utc();
        expires_in = duration + timestamp - g_date_time_to_unix(now);
        g_date_time_unref(now);
        if (expires_in < 0)
            return FALSE;
    }
    
    GVariant* token_variant = gsignond_dictionary_get(token, "AccessToken");
    if (token_variant != NULL) {
        GSignondSessionData* response = gsignond_dictionary_new();
        gsignond_dictionary_set(response, "AccessToken", token_variant);
        GVariant* refresh_token = gsignond_dictionary_get(token, "RefreshToken");
        if (refresh_token != NULL)
            gsignond_dictionary_set(response, "RefreshToken", refresh_token);
        GVariant* token_type = gsignond_dictionary_get(token, "TokenType");
        if (token_type != NULL)
            gsignond_dictionary_set(response, "TokenType", token_type);
        GVariant* token_params = gsignond_dictionary_get(token, "TokenParameters");
        if (token_params != NULL)
            gsignond_dictionary_set(response, "TokenParameters", token_params);
        const gchar* token_scope_s = gsignond_dictionary_get_string(token, "Scope");
        if (token_scope_s != NULL) {
            gsignond_dictionary_set_string(response, "Scope", token_scope_s);
        }
        if (has_duration) {
            gsignond_dictionary_set_int64(response, "Duration", duration);
        }
        if (has_timestamp) {
            gsignond_dictionary_set_int64(response, "Timestamp", timestamp);
        }
        return response;
    }
    return NULL;
}

static void _iterate_json_object(JsonObject *object,
                          const gchar *member_name,
                          JsonNode *member_node,
                          gpointer user_data)
{
    GHashTable* params = user_data;
    
    if (json_node_get_node_type(member_node) != JSON_NODE_VALUE)
        return;
    if (json_node_get_value_type(member_node) == G_TYPE_STRING)
        g_hash_table_insert(params, 
                            g_strdup(member_name),
                            g_strdup(json_node_get_string(member_node)));
    else if (json_node_get_value_type(member_node) == G_TYPE_INT64)
        g_hash_table_insert(params, 
                            g_strdup(member_name),
                            g_strdup_printf("%"G_GINT64_FORMAT, json_node_get_int(member_node)));
}

static GHashTable* _get_json_params(JsonObject* object)
{
    GHashTable* params = g_hash_table_new_full((GHashFunc)g_str_hash,
                                          (GEqualFunc)g_str_equal,
                                          (GDestroyNotify)g_free,
                                          (GDestroyNotify)g_free
                                         );
    json_object_foreach_member(object, _iterate_json_object, params);
    return params;
}

static void
_http_token_callback (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
    GError* error = NULL;
    GSignondOauthPlugin *self = GSIGNOND_OAUTH_PLUGIN(user_data);

    if (msg->status_code != SOUP_STATUS_OK && msg->status_code != SOUP_STATUS_BAD_REQUEST) {
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Token endpoint returned an error: %d %s",
                             msg->status_code, msg->reason_phrase);
        goto out;
    }

    SoupBuffer* request = soup_message_body_flatten(msg->response_body);

    JsonParser* parser = json_parser_new();
    gboolean res = json_parser_load_from_data(parser, request->data, -1, NULL);
    soup_buffer_free(request);
    if (res == FALSE) {
        g_object_unref(parser);
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Json parser returned an error");
        goto out;
    }
    
    if (json_node_get_node_type(json_parser_get_root(parser)) != JSON_NODE_OBJECT) {
        g_object_unref(parser);
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Json top-level structure is not an object");
        goto out;
    }
    
    GHashTable* params = _get_json_params(json_node_get_object(json_parser_get_root(parser)));
    g_object_unref(parser);

    // if using a refresh token failed, go back to full authentication process
    // using supplied credentials info
    const gchar* oauth_error = g_hash_table_lookup(params, "error");
    if (oauth_error != NULL && g_strcmp0(oauth_error, "invalid_grant") == 0 &&
            gsignond_dictionary_get(self->oauth2_request, "_Oauth2UseRefresh") != NULL) {
        gsignond_dictionary_remove(self->oauth2_request, "_Oauth2UseRefresh");
        g_hash_table_unref(params);
        _request_new_token(self, self->oauth2_request, &error);
        goto out;
    }
    
    if (oauth_error != NULL) {
        _process_auth_error(params, &error);
        g_hash_table_unref(params);
        goto out;
    }
    
    // "client_credentials" grant type doesn't allow refresh tokens
    // RFC 6749 4.4.3
    if (g_strcmp0(gsignond_dictionary_get_string(self->oauth2_request, "GrantType"),
        "client_credentials") == 0)
        g_hash_table_remove(params, "refresh_token");
    
    _process_access_token(self, params, &error);
    
    g_hash_table_unref(params);

out:
    if (error != NULL) {
        _do_reset_oauth2(self);
        gsignond_plugin_error (GSIGNOND_PLUGIN(self), error);
        g_error_free(error);
   }

}

static void _set_scope(GHashTable *params,
                  GSignondSessionData* session_data)
{
    const gchar* scope_str = gsignond_dictionary_get_string(session_data, "Scope");
    if (scope_str != NULL) {
        g_hash_table_insert(params, "scope", (gchar*)scope_str);
    }
}

static void _do_token_query(GSignondOauthPlugin *self,
                         GSignondSessionData *session_data,
                         GHashTable* params,
                         GError** error)
{
    gboolean force_request_body_auth;
    if (gsignond_dictionary_get_boolean(session_data, 
        "ForceClientAuthViaRequestBody",
        &force_request_body_auth) && force_request_body_auth)
    {
        const gchar* client_id = gsignond_dictionary_get_string(session_data,
                                                            "ClientId");
        const gchar* client_secret = gsignond_dictionary_get_string(session_data,
                                                            "ClientSecret");
        if (client_id != NULL && client_secret != NULL) {
            g_hash_table_insert(params, "client_id", (gchar*)client_id);
            g_hash_table_insert(params, "client_secret", (gchar*)client_secret);
        }
    }
    
    const gchar* host = gsignond_dictionary_get_string(session_data, "TokenHost");
    if (host == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "TokenHost not set");
        return;
    }
    gsignond_oauth_plugin_check_host(host, gsignond_session_data_get_allowed_realms (session_data), error);
    if (*error != NULL)
        return;

    const gchar* token_path = gsignond_dictionary_get_string(session_data, "TokenPath");
    if (token_path == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "TokenPath not set");
        return;
    }
    
    const gchar* token_query_str = gsignond_dictionary_get_string(session_data, "TokenQuery");
    
    SoupURI* open_url = soup_uri_new(NULL);
    soup_uri_set_scheme(open_url, SOUP_URI_SCHEME_HTTPS);
    soup_uri_set_host(open_url, host);
    soup_uri_set_path(open_url, token_path);

    guint port;
    if (gsignond_dictionary_get_uint32(session_data, "TokenPort", &port) != FALSE)
        soup_uri_set_port(open_url, port);    

    if (token_query_str != NULL) {
        soup_uri_set_query(open_url, token_query_str);
    }
    
    SoupMessage *msg = soup_message_new_from_uri ("POST", open_url);
    soup_uri_free(open_url);
    gchar* formdata = soup_form_encode_hash(params);
    soup_message_set_request (msg, "application/x-www-form-urlencoded",
              SOUP_MEMORY_TAKE, formdata, strlen (formdata));
    
    soup_session_queue_message (self->soup_session, msg, _http_token_callback, self);
}


static void _use_refresh_token(GSignondOauthPlugin *self,
                            GSignondSessionData *session_data,
                            const gchar* refresh_token,
                            GError** error)
{
    if (refresh_token == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "No refresh token available");
        return;
    }

    GHashTable* params = g_hash_table_new((GHashFunc)g_str_hash,
                                             (GEqualFunc)g_str_equal);
    g_hash_table_insert(params, "grant_type", "refresh_token");
    g_hash_table_insert(params, "refresh_token", (gchar*)refresh_token);
    _set_scope(params, session_data);

    _do_token_query(self, session_data, params, error);
    g_hash_table_unref(params);
    if (*error == NULL) {
        gsignond_dictionary_set_boolean(self->oauth2_request, "_Oauth2UseRefresh", TRUE);
    }
}

static void _insert_key_value(gpointer key, gpointer value, gpointer table)
{
    g_hash_table_insert(table, key, value);
}

static void _request_new_token(GSignondOauthPlugin *self, 
                        GSignondSessionData *session_data,
                        GError** error)
{
    const gchar* response_type = gsignond_dictionary_get_string(session_data, "ResponseType");
    const gchar* grant_type = gsignond_dictionary_get_string(session_data, "GrantType");
    
    if (response_type != NULL &&
            (g_strcmp0(response_type, "code") == 0 || 
            g_strcmp0(response_type, "token") == 0)) {
        const gchar* host = gsignond_dictionary_get_string(session_data, "AuthHost");
        if (host == NULL) {
            *error = g_error_new(GSIGNOND_ERROR,
                                 GSIGNOND_ERROR_MISSING_DATA,
                                 "AuthHost not set");
            return;
        }

        gsignond_oauth_plugin_check_host(host, gsignond_session_data_get_allowed_realms (session_data), error);
        if (*error != NULL)
            return;
        
        const gchar* auth_path = gsignond_dictionary_get_string(session_data, "AuthPath");
        if (auth_path == NULL) {
            *error = g_error_new(GSIGNOND_ERROR,
                                 GSIGNOND_ERROR_MISSING_DATA,
                                 "AuthPath not set");
            return;
        }
        const gchar* client_id = gsignond_dictionary_get_string(session_data, "ClientId");
        if (client_id == NULL) {
            *error = g_error_new(GSIGNOND_ERROR,
                                 GSIGNOND_ERROR_MISSING_DATA,
                                 "ClientId not set");
            return;
        }

        SoupURI* open_url = soup_uri_new(NULL);
        soup_uri_set_scheme(open_url, SOUP_URI_SCHEME_HTTPS);
        soup_uri_set_host(open_url, host);
        soup_uri_set_path(open_url, auth_path);

        guint port;
        if (gsignond_dictionary_get_uint32(session_data, "AuthPort", &port) != FALSE)
            soup_uri_set_port(open_url, port);

        GHashTable* query = g_hash_table_new((GHashFunc)g_str_hash,
                                             (GEqualFunc)g_str_equal);
        const gchar* auth_query_str = gsignond_dictionary_get_string(session_data, "AuthQuery");
        GHashTable *auth_query = NULL;
        if (auth_query_str != NULL) {
            auth_query = soup_form_decode(auth_query_str);
            if (auth_query)
                // insert all key/values in AuthQuery into final query
                // according to RFC6749 section 3.1
                g_hash_table_foreach(auth_query, _insert_key_value, query);
        }

        g_hash_table_insert(query, "response_type", (gchar*)response_type);
        g_hash_table_insert(query, "client_id", (gchar*)client_id);
        
        const gchar* redirect_uri = gsignond_dictionary_get_string(session_data, "RedirectUri");
        if (redirect_uri != NULL) {
            g_hash_table_insert(query, "redirect_uri", (gchar*)redirect_uri);
        }

        const gchar* scope_str = gsignond_dictionary_get_string(session_data, "Scope");
        if (scope_str != NULL) {
            g_hash_table_insert(query, "scope", (gchar*)scope_str);
        }
        
        gchar* state = gsignond_oauth_plugin_generate_random_data(20);
        g_hash_table_insert(query, "state", state);
        gsignond_dictionary_set_string(self->oauth2_request, "_Oauth2State", state);

        const gchar* username = gsignond_session_data_get_username(session_data);
        const gchar* secret = gsignond_session_data_get_secret(session_data);

        // login_hint is a google extension specified here:
        // https://developers.google.com/accounts/docs/OAuth2InstalledApp#formingtheurl
        gboolean use_login_hint = FALSE;
        if (gsignond_dictionary_get_boolean(session_data, 
            "UseLoginHint", &use_login_hint) && 
            use_login_hint && username != NULL)
            g_hash_table_insert(query, "login_hint", (gchar*)username);
        
        // display is a facebook extension specified here:
        // https://developers.facebook.com/docs/reference/dialogs/oauth/
        const gchar* display = gsignond_dictionary_get_string(session_data, "UseDisplay");
        if (display != NULL) {
            g_hash_table_insert(query, "display", (gchar*)display);
        }
        
        soup_uri_set_query_from_form(open_url, query);
        g_free(state);
        g_hash_table_unref(query);
        if (auth_query)
            g_hash_table_unref(auth_query);

        char* open_url_str = soup_uri_to_string(open_url, FALSE);
        soup_uri_free(open_url);
        
        GSignondSignonuiData* ui_request = gsignond_dictionary_new();
        gsignond_signonui_data_set_open_url(ui_request, open_url_str);
        free(open_url_str);
        
        if (redirect_uri != NULL)
            gsignond_signonui_data_set_final_url(ui_request, redirect_uri);
        
        /* add username and password, for fields initialization (the
         * decision on whether to actually use them is up to the signon UI */
        if (username != NULL)
            gsignond_signonui_data_set_username(ui_request, username);
        if (secret != NULL)
            gsignond_signonui_data_set_password(ui_request, secret);
        
        gsignond_plugin_user_action_required(GSIGNOND_PLUGIN(self), ui_request);
        gsignond_dictionary_unref(ui_request);
        
    } else if (grant_type != NULL &&
            (g_strcmp0(grant_type, "password") == 0)) {
        const gchar* username = gsignond_session_data_get_username(session_data);
        const gchar* secret = gsignond_session_data_get_secret(session_data);
        if (username == NULL || secret == NULL) {
            *error = g_error_new(GSIGNOND_ERROR,
                                 GSIGNOND_ERROR_MISSING_DATA,
                                 "username or password not set");
            return;
        }
        GHashTable* params = g_hash_table_new((GHashFunc)g_str_hash,
                                             (GEqualFunc)g_str_equal);
        g_hash_table_insert(params, "grant_type", "password");
        g_hash_table_insert(params, "username", (gchar*)username);
        g_hash_table_insert(params, "password", (gchar*)secret);
        _set_scope(params, session_data);
    
        _do_token_query(self, session_data, params, error);
        g_hash_table_unref(params);
    } else if (grant_type != NULL &&
            (g_strcmp0(grant_type, "client_credentials") == 0)) {
        GHashTable* params = g_hash_table_new((GHashFunc)g_str_hash,
                                             (GEqualFunc)g_str_equal);
        g_hash_table_insert(params, "grant_type", "client_credentials");
        _set_scope(params, session_data);
    
        _do_token_query(self, session_data, params, error);
        g_hash_table_unref(params);
    } else {
        *error = g_error_new(GSIGNOND_ERROR,
                             GSIGNOND_ERROR_MISSING_DATA,
                             "Unknown ResponseType or GrantType");
    }
}

static gboolean _find_token_by_scope(gpointer token_scope, 
                             gpointer token, 
                             gpointer requested_scope)
{
    return _is_scope_subset(requested_scope, token_scope);
}

static GSignondDictionary* _find_token_in_cache(GSignondDictionary* token_cache,
                                         const gchar* client_id,
                                         const gchar* requested_scope_s)
{
    GVariant* client_tokens_variant = gsignond_dictionary_get(token_cache, client_id);
    if (client_tokens_variant == NULL)
        return NULL;
    
    GSignondDictionary* client_tokens = gsignond_dictionary_new_from_variant(client_tokens_variant);
    if (client_tokens == NULL)
        return NULL;

    //requested_scope must be a subset of token scope
    GVariant* token_v = g_hash_table_find(client_tokens, 
                                                  _find_token_by_scope, 
                                                  (gpointer)requested_scope_s);
    GSignondDictionary* token = NULL;
    if (token_v)
        token = gsignond_dictionary_new_from_variant(token_v);
    gsignond_dictionary_unref(client_tokens);
    return token;
}

static gboolean _remove_tokens_by_scope(gpointer cached_token_scope, 
                                         gpointer cached_token, 
                                         gpointer new_token_scope)
{
    return _is_scope_subset(cached_token_scope, new_token_scope);
}

static void _insert_token_in_cache(GSignondDictionary* token_cache,
                                   GSignondDictionary* token,
                                   const gchar* token_client_id)
{
    const gchar* token_scope_s = gsignond_dictionary_get_string(token, "Scope");
    
    GVariant* client_tokens_variant = gsignond_dictionary_get(token_cache, token_client_id);

    GSignondDictionary* client_tokens = NULL;

    if (client_tokens_variant != NULL)
        client_tokens = gsignond_dictionary_new_from_variant(client_tokens_variant);

    if (client_tokens == NULL)
        client_tokens = gsignond_dictionary_new();
    
    //remove all tokens with scope smaller than the new tokens's scope
    g_hash_table_foreach_remove(client_tokens, _remove_tokens_by_scope, (gpointer)token_scope_s);
    
    GVariant* token_variant = gsignond_dictionary_to_variant(token);
    gsignond_dictionary_set(client_tokens, token_scope_s, token_variant);
    client_tokens_variant = gsignond_dictionary_to_variant(client_tokens);
    gsignond_dictionary_set(token_cache, token_client_id, client_tokens_variant);
    gsignond_dictionary_unref(client_tokens);
}

void _process_oauth2_request(GSignondOauthPlugin *self, 
                             GSignondSessionData *session_data,
                             GSignondDictionary *tokens
                            )
{
    //GSignondPlugin* plugin = GSIGNOND_PLUGIN(self);
    GError* error = NULL;
    
    const gchar* client_id = gsignond_dictionary_get_string(session_data, "ClientId");
    
    if (client_id == NULL) {
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "Client did not supply ClientId");
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

    const gchar* scope = gsignond_dictionary_get_string(session_data, "Scope");
    GSignondDictionary* token = NULL;

    // use old token only if ui policy is not REQUEST_PASSWORD
    if (ui_policy == GSIGNOND_UI_POLICY_DEFAULT) {
        token = _find_token_in_cache(tokens, client_id, scope);
    }

    gboolean force_refresh_token;
    gboolean has_force_refresh_token = gsignond_dictionary_get_boolean(session_data,
                                                              "ForceTokenRefresh",
                                                              &force_refresh_token);
    if (!has_force_refresh_token)
        force_refresh_token = FALSE;

    if (token != NULL && force_refresh_token == FALSE) {
        GSignondDictionary* response = _respond_with_stored_token(token);
        if (response) {
            gsignond_plugin_response_final(GSIGNOND_PLUGIN(self), response);
            gsignond_dictionary_unref(response);
            gsignond_dictionary_unref(token);
            goto out;
        }
    }

    self->oauth2_request = session_data;
    gsignond_dictionary_ref(self->oauth2_request);
    self->token_cache = tokens;
    gsignond_dictionary_ref(self->token_cache);

    if (token != NULL) {
        _use_refresh_token(self, session_data,
                           gsignond_dictionary_get_string(token, "RefreshToken"),
                           &error);
        gsignond_dictionary_unref(token);
        if (error == NULL) {
            goto out;
        } else {
            // do not report an error in using a refresh token
            g_warning("Using refresh token failed: %s\n", error->message);
            g_error_free(error);
            error = NULL;
        }
    }

    _request_new_token(self, session_data, &error);

out:
   if (error != NULL) {
        _do_reset_oauth2(self);
        gsignond_plugin_error (GSIGNOND_PLUGIN(self), error);
        g_error_free(error);
   }
}

static void _process_auth_error(GHashTable* params,
                                GError** error)
{
    const gchar* error_str = g_hash_table_lookup(params, "error");
    const gchar* error_desc = g_hash_table_lookup(params, "error_description");
    const gchar* error_uri = g_hash_table_lookup(params, "error_uri");
    
    gchar* error_complete = g_strdup_printf("%s %s %s", error_str, error_desc ? error_desc : "",
                                error_uri ? error_uri : "");
    
    *error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Authorization server returned an error: %s",
                                error_complete);
    g_free(error_complete);
}

static GHashTable* _get_token_params(GHashTable* params, const gchar* token_type)
{
    GHashTable* token_params = NULL;
    // 'bearer' is used by microsoft: 
    // http://msdn.microsoft.com/en-us/library/live/hh243641.aspx#signin
    if (g_strcmp0(token_type, "Bearer") == 0 || g_strcmp0(token_type, "bearer") == 0) {
        token_params = g_hash_table_new((GHashFunc)g_str_hash,
                                         (GEqualFunc)g_str_equal);
    }
    return token_params;
}



static void _process_access_token(GSignondOauthPlugin *self,
                                GHashTable* params,
                                GError** error
                                 )
{
    const gchar* access_token = g_hash_table_lookup(params, "access_token");
    const gchar* token_type = g_hash_table_lookup(params, "token_type");
    if (access_token == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "No access token in response");
        return;
    }
    GHashTable* additional_token_params = _get_token_params(params, token_type);
    if (additional_token_params == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Unknown access token type %s", token_type);
        return;
    }
    GSignondDictionary* token_dict = gsignond_dictionary_new();
    gsignond_dictionary_set_string(token_dict, "AccessToken", access_token);
    gsignond_dictionary_set_string(token_dict, "TokenType", token_type);
    gsignond_dictionary_set(token_dict, "TokenParameters", 
                            gsignond_dictionary_to_variant(
                                additional_token_params));
    g_hash_table_unref(additional_token_params);

    GDateTime* now = g_date_time_new_now_utc();
    gsignond_dictionary_set_int64(token_dict, "Timestamp", g_date_time_to_unix(now));
    g_date_time_unref(now);

    const gchar* duration_s = g_hash_table_lookup(params, "expires_in");
    if (duration_s != NULL) {
        gchar* endptr;
        gint64 duration = g_ascii_strtoll(duration_s, &endptr, 10);
        if (endptr[0] == '\0')
            gsignond_dictionary_set_int64(token_dict, "Duration", duration);
    }

    const gchar* scope_s = g_hash_table_lookup(params, "scope");
    if (scope_s != NULL) {
        gsignond_dictionary_set_string(token_dict, "Scope", scope_s);
    } else {
        GVariant* scope_v = gsignond_dictionary_get(self->oauth2_request, 
                                                    "Scope");
        if (scope_v != NULL)
            gsignond_dictionary_set(token_dict, "Scope", scope_v);
        else
            gsignond_dictionary_set_string(token_dict, "Scope", "");
    }
    
    const gchar* client_id = gsignond_dictionary_get_string(self->oauth2_request, "ClientId");

    const gchar* refresh_token = g_hash_table_lookup(params, "refresh_token");
    if (refresh_token != NULL)
        gsignond_dictionary_set_string(token_dict, "RefreshToken", refresh_token);
    else {
        // reuse previously issued refresh token
        GSignondDictionary* old_token = _find_token_in_cache(self->token_cache,
                                                             client_id,
                                                             NULL);
        if (old_token != NULL) {
            const gchar* old_refresh_token = gsignond_dictionary_get_string(
                old_token, "RefreshToken");
            if (old_refresh_token != NULL)
                gsignond_dictionary_set_string(token_dict, "RefreshToken",
                                                   old_refresh_token);
        }
        gsignond_dictionary_unref(old_token);
    }
    _insert_token_in_cache(self->token_cache, token_dict, client_id);
    
    gsignond_plugin_store(GSIGNOND_PLUGIN(self), self->token_cache);
    
    _do_reset_oauth2(self);
    gsignond_plugin_response_final(GSIGNOND_PLUGIN(self), token_dict);
    gsignond_dictionary_unref(token_dict);
}

static void _request_token_using_auth_code(GSignondOauthPlugin* self,
                                           const gchar* auth_code,
                                           GError** error
                                          )
{
    if (auth_code == NULL) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Authorization endpoint didn't issue an\
 authorization code");
        return;
    }

    GHashTable* params = g_hash_table_new((GHashFunc)g_str_hash,
                                             (GEqualFunc)g_str_equal);
    g_hash_table_insert(params, "grant_type", "authorization_code");
    g_hash_table_insert(params, "code", (gchar*)auth_code);
    g_hash_table_insert(params, "redirect_uri", 
                        (gchar*)gsignond_dictionary_get_string(self->oauth2_request, 
                                                       "RedirectUri"));
    // explicitly insert client id if
    // a) we are not forcing client auth via request body and
    // b) client id is supplied but client password is not
    gboolean force_request_body_auth;
    if (gsignond_dictionary_get_boolean(self->oauth2_request, 
        "ForceClientAuthViaRequestBody",
        &force_request_body_auth) == FALSE || !force_request_body_auth)
    {
        if (gsignond_dictionary_get_string(self->oauth2_request, 
            "ClientSecret") == NULL) {
            g_hash_table_insert(params, "client_id", 
                            (gchar*)gsignond_dictionary_get_string(self->oauth2_request,
                                                           "ClientId"));
        }
    }
    _do_token_query(self, self->oauth2_request, params, error);
    if (*error == NULL) {
        //nothing to do; session is already active
    }
    g_hash_table_unref(params);
}

void _process_oauth2_user_action_finished(GSignondOauthPlugin *self, 
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
    const gchar* redirect_uri = gsignond_dictionary_get_string(
        self->oauth2_request, "RedirectUri");
    if (response_url == NULL || redirect_uri == NULL ||
        g_str_has_prefix(response_url, redirect_uri) == FALSE) {
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Redirect URI and URI supplied by UI don't match");
        goto out;
    }
    
    SoupURI* response = soup_uri_new(response_url);
    GHashTable* params;
    const gchar* response_type = gsignond_dictionary_get_string(
        self->oauth2_request, "ResponseType");
    if (g_strcmp0(response_type, "code") == 0) {
        const gchar* query = soup_uri_get_query(response);
        if (query == NULL) {
            soup_uri_free(response);
            error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "No query in returned redirect URI");
            goto out;
        }
        params = soup_form_decode(query);
    } else if (g_strcmp0(response_type, "token") == 0) {
        const gchar* fragment = soup_uri_get_fragment(response);
        if (fragment == NULL) {
            soup_uri_free(response);
            error = g_error_new(GSIGNOND_ERROR,
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "No fragment in returned redirect URI");
            goto out;
        }
        params = soup_form_decode(fragment);
    } else {
        soup_uri_free(response);
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Unknown response type in session data");
        goto out;
    }
    soup_uri_free(response);
    
    if (g_strcmp0(g_hash_table_lookup(params, "state"),
        gsignond_dictionary_get_string(self->oauth2_request, "_Oauth2State")) != 0) {
        g_hash_table_unref(params);
        error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Returned state and generated state don't match");
        goto out;
    }
    
    if (g_hash_table_contains(params, "error") == TRUE) {
        _process_auth_error(params, &error);
        g_hash_table_unref(params);
        goto out;
    }
    
    if (g_strcmp0(response_type, "code") == 0) {
        _request_token_using_auth_code(self, g_hash_table_lookup(params, "code"), &error);
    } else {
        // implicit grant should not contain a refresh token, RFC 6749 4.2.2
        g_hash_table_remove(params, "refresh_token");
        _process_access_token(self, params, &error);
    }
    g_hash_table_unref(params);

out:
    if (error != NULL) {
        _do_reset_oauth2(self);
        gsignond_plugin_error (GSIGNOND_PLUGIN(self), error);
        g_error_free(error);
   }
}
