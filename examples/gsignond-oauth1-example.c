/* PLEASE NOTE: this example is meant for OAuth plugin developers. If you're
 * an application developer who wants to use this plugin, please refer to
 * libgsignon-glib documentation here:
 * http://gsignon-docs.accounts-sso.googlecode.com/git/libgsignon-glib/index.html
 */
/*
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

#include <gsignond/gsignond-session-data.h>
#include <gsignond/gsignond-plugin-interface.h>
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-utils.h>
#include "gsignond-oauth-plugin.h"

// this function returns a token for the token cache
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

//this function makes a token cache with one unrelated token
//(because it belongs to a different consumer key)
static GSignondDictionary* make_token_cache()
{
    GSignondDictionary* tokens = gsignond_dictionary_new();
    gsignond_dictionary_set(tokens, "someotherclient", make_normal_token());
    return tokens;
}

//this callback prints the received token and exits the mainloop
static void response_callback(GSignondPlugin* plugin, GSignondSessionData* result,
                     gpointer user_data)
{
    GVariant* token_variant = gsignond_dictionary_to_variant(result);
    gchar* token_str = g_variant_print(token_variant, TRUE);
    g_print("Authenticated successfully, got token:\n%s\n",
             token_str);
    g_free(token_str);
    g_variant_unref(token_variant);
    g_main_loop_quit(user_data);    
}

//this function prints the content of the updated token cache
static void store_callback(GSignondPlugin* plugin, GSignondSessionData* result,
                     gpointer user_data)
{
    GVariant* token_variant = gsignond_dictionary_to_variant(result);
    gchar* token_str = g_variant_print(token_variant, TRUE);
    g_print("Should replace the token cache with the following:\n%s\n",
             token_str);
    g_free(token_str);
    g_variant_unref(token_variant);
}

//this function shows what the UI interaction component needs to do
static void user_action_required_callback(GSignondPlugin* plugin, 
                                          GSignondSignonuiData* ui_request, 
                                          gpointer user_data)
{
    // ui_request typically contains a URI that needs to be opened, 
    // and a redirect URI that needs to be 'captured' by the user-agent and 
    // reported back to the plugin
    // in practice the ui_request needs to be handed over to a user-agent
    // but here we simply print it    
    GVariant* token_variant = gsignond_dictionary_to_variant(ui_request);
    gchar* token_str = g_variant_print(token_variant, TRUE);
    g_print("Got a UI interaction request:\n%s\n",
             token_str);
    g_free(token_str);
    g_variant_unref(token_variant);
    
    // in practice the following should be received from a user-agent,
    // but in this example for the sake of simplicity we report the hardcoded redirect
    // URI (with additional parameters) immidiately back to the plugin
    GSignondSignonuiData* ui_data = gsignond_dictionary_new();
    gsignond_signonui_data_set_url_response(ui_data, 
"http://somehost/somegsignondoauthcallback?oauth_token=somerandomtoken&oauth_verifier=somerandomverifier");
    gsignond_signonui_data_set_query_error(ui_data, SIGNONUI_ERROR_NONE);

    gsignond_plugin_user_action_finished(plugin, ui_data);
    gsignond_dictionary_unref(ui_data);
}

// print an error and exit the mainloop
static void error_callback(GSignondPlugin* plugin, GError* error,
                     gpointer user_data)
{
    g_print("Got an error: %s\n", error->message);
    g_main_loop_quit(user_data);
}


int main (void)
{
#if !GLIB_CHECK_VERSION (2, 36, 0)
    g_type_init ();
#endif

    gpointer plugin = g_object_new(gsignond_oauth_plugin_get_type(), NULL);

    GMainLoop *main_loop = g_main_loop_new (NULL, FALSE);    

    //connect to various signals of the plugin object
    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), main_loop);
    g_signal_connect(plugin, "user-action-required", 
                     G_CALLBACK(user_action_required_callback), NULL);
    g_signal_connect(plugin, "store", G_CALLBACK(store_callback), NULL);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), main_loop);

    GSignondSessionData* data = gsignond_dictionary_new();
    GSignondDictionary* token_cache = make_token_cache();

    //fill in necessary data for OAuth1 authorization
    gsignond_dictionary_set_string(data, "ConsumerKey", "megaclient");
    gsignond_dictionary_set_string(data, "ConsumerSecret", "megasecret");
    gsignond_dictionary_set_string(data, "Realm", "megarealm");
    gsignond_session_data_set_ui_policy(data, GSIGNOND_UI_POLICY_DEFAULT);
    
    const gchar *realm_list[] = { "somehost", NULL };
    GSequence *allowed_realms = gsignond_copy_array_to_sequence(realm_list);
    gsignond_session_data_set_allowed_realms(data, allowed_realms);
    g_sequence_free(allowed_realms);
    
    // can also be HMAC-SHA1, or RSA-SHA1 (in the latter case, also RSAPrivateKey
    // needs to be set
    gsignond_dictionary_set_string(data, "SignatureMethod", "PLAINTEXT");
    
    gsignond_dictionary_set_string(data, "RequestEndpoint", "https://somehost/temporarytokenpath");
    gsignond_dictionary_set_string(data, "AuthorizationEndpoint", "https://somehost/authorization");
    gsignond_dictionary_set_string(data, "Callback", "http://somehost/somegsignondoauthcallback");
    gsignond_dictionary_set_string(data, "TokenEndpoint", "https://somehost/accesstokenpath");
 
    //start the authorization and run the mainloop
    //any further processing happens in signal callbacks
    gsignond_plugin_request_initial(plugin, data, token_cache, "oauth1");
    gsignond_dictionary_unref(data);
    gsignond_dictionary_unref(token_cache);
    
    g_main_loop_run (main_loop);
    
    g_object_unref(plugin);
    g_main_loop_unref(main_loop);
    
    return 0;
}
