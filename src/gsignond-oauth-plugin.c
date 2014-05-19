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

/**
 * SECTION:gsignond-oauth-plugin
 * @short_description: OAuth1/OAuth2 authentication plugin for gSSO single sign-on service
 * @see_also: #GSignondPlugin
 *
 * The OAuth plugin provides a client-side implementation of OAuth 1 and OAuth 2
 * authorization protocols. The overall flow is that the plugin is requested to
 * perform authorization using supplied authorization parameters, and if it has
 * succeeded in doing so, it returns a token string to the application that can
 * be used to access protected resources over https. The plugin is not involved
 * in accessing protected resources, only in initial authorization.
 * 
 * OAuth1 is specified in <ulink url="http://tools.ietf.org/html/rfc5849">RFC 5849</ulink>,
 * OAuth2 is specified in <ulink url="http://tools.ietf.org/html/rfc6749">RFC 6749</ulink>
 * (with additional info regarding the basic bearer token type in <ulink 
 * url="http://tools.ietf.org/html/rfc6750">RFC6750</ulink>). The two versions are
 * not compatible and specify significantly different authorization sequences, for
 * that reason they are implemented as separate mechanisms in the plugin.
 * 
 * The plugin implements the standard #GSignondPlugin interface, and after instantiating
 * a plugin object all interactions happen through that interface.
 * 
 * #GSignondPlugin:type property of the plugin object is set to "oauth".
 * 
 * #GSignondPlugin:mechanisms property of the plugin object is a list of "oauth1" and "oauth2".
 *
 * <refsect1><title>Authorization sequence</title></refsect1>
 * 
 * The authorization sequence begins with issuing gsignond_plugin_request_initial().
 * The @mechanism parameter should be set to "oauth1" or "oauth2", and
 * the contents of @session_data and @identity_method_cache parameters depend 
 * on the mechanism and are described in detail below.
 * 
 * The plugin responds to the request with one of the following signals:
 * - #GSignondPlugin::response-final This means the authorization sequence ended
 * successfully, and the authorization token is delivered in @session_data parameter
 * of the signal. This signal concludes the sequence.
 * - #GSignondPlugin::user-action-required The plugin is requesting to perform a 
 * user authorization procedure by opening a webpage in a user-agent (browser) where the user is expected
 * to enter her credentials. Parameters for this step are specified in @ui_data.
 * After the user interaction has completed, the results are returned to the 
 * plugin with gsignond_plugin_user_action_finished() method, and the authorization
 * process continues.
 * - #GSignondPlugin::store The plugin is requesting to replace the token cache
 * with the contents of @identity_method_cache parameter. There is no need to respond to this
 * signal; the authorization process continues immediately.
 * - #GSignondPlugin::error An error has happened in the authorization sequence 
 * and it stops.
 * Typical errors are %GSIGNOND_ERROR_MISSING_DATA which means there wasn't enough
 * data provided in gsignond_plugin_request_initial() to perform the authorization,
 * %GSIGNOND_ERROR_NOT_AUTHORIZED which means the server rejected the 
 * authorization attempt, %GSIGNOND_ERROR_USER_INTERACTION which means there
 * was an error during interaction with the user.
 *
 * At any point the application can request to stop the authorization by calling
 * gsignond_plugin_cancel(). The plugin responds with an #GSignondPlugin::error signal
 * containing a %GSIGNOND_ERROR_SESSION_CANCELED error.
 * 
 * <refsect1><title>Code examples</title></refsect1>
 * 
 * <example>
 * <title>Using OAuth1</title>
 * <programlisting>
 * <xi:include href="../gsignond-oauth1-example.listing" parse="text" xmlns:xi="http://www.w3.org/2001/XInclude"/>
 * </programlisting>
 * </example>
 * 
 * <example>
 * <title>Using OAuth2</title>
 * <programlisting>
 * <xi:include href="../gsignond-oauth2-example.listing" parse="text" xmlns:xi="http://www.w3.org/2001/XInclude"/>
 * </programlisting>
 * </example>
 *
 * <refsect1><title>HTTP-related parameters in requests</title></refsect1>
 * 
 * Both OAuth1 and OAuth2 are using HTTP requests for authorization. It's possible
 * to use the following entries in gsignond_plugin_request_initial() @session_data
 * parameter to influence those requests:
 * - gsignond_session_data_set_network_proxy() provides a HTTP proxy to use.
 * If this parameter is not set, the system proxy configuration is used.
 * - "SslStrict" key whose value is a gboolean. If set to FALSE, then server
 * certificates which are invalid (for example, expired, or self-signed) 
 * will not be rejected. If set to TRUE or not set, then server certificates
 * have to be valid.
 * 
 * <refsect1><title>OAuth version 1 parameters for authorization</title></refsect1>
 *
 * Where not specified otherwise, parameters are strings.
 *
 * <refsect2><title>Parameters in gsignond_plugin_request_initial() @identity_method_cache</title></refsect2>

 * This parameter contains a cache of previously received tokens in the form of
 * a #GSignondDictionary. Tokens are indexed by a ConsumerKey in the dictionary,
 * and each token is itself a #GSignondDictionary, with keys and values described
 * below in the token format section.
 * 
 * <refsect2><title>Parameters in gsignond_plugin_request_initial() @session_data</title></refsect2>
 * 
 * - "ConsumerKey" (mandatory) - the identifier portion of the client 
 * credentials (equivalent to a username). Refer to <ulink url=
 * "http://tools.ietf.org/html/rfc5849#section-3.1">RFC5849 section 3.1</ulink>
 * - gsignond_session_data_set_ui_policy() (mandatory) - if set to %GSIGNOND_UI_POLICY_DEFAULT
 * a default authorization sequence is used, which may involve re-using a
 * previously cached token without making any authorization server requests at all.
 * If set to %GSIGNOND_UI_POLICY_REQUEST_PASSWORD any cached token corresponding
 * to the ConsumerKey is discarded and the authorization procedure is started
 * from the beginning.
 * - gsignond_session_data_set_allowed_realms (mandatory) - a list of domains that
 * RequestEndpoint, AuthorizationEndpoint and TokenEndpoint hosts must be in. There
 * authorization sequence will fail if any of the endpoints is not in this list.
 * - "Realm" (optional) - a requested realm for the token, as specified in
 * <ulink url="http://tools.ietf.org/html/rfc5849#section-3.5.1">RFC5849 section 3.5.1.</ulink>
 * - "RequestEndpoint" (mandatory) - a URL that specifies an endpoint used by 
 * the plugin to obtain a set of temporary credentials, as specified in 
 * <ulink url="http://tools.ietf.org/html/rfc5849#section-2">RFC5849 section 2.</ulink>
 * The endpoint must use HTTPS scheme.
 * - "Callback" (mandatory) - a callback URI where the user is redirected after
 * completing the Resource Owner Authorization step, as specified in 
 * <ulink url="http://tools.ietf.org/html/rfc5849#section-2">RFC5849 section 2.</ulink>
 * - "SignatureMethod" (mandatory) - one of "PLAINTEXT", "HMAC-SHA1", or 
 * "RSA-SHA1" - a method used used by the plugin to sign the requests. 
 * Specified in <ulink url="http://tools.ietf.org/html/rfc5849#section-3.4">RFC5849 section 3.4.</ulink>
 * - "ConsumerSecret" (optional) - the shared secret portion of the client
 * credentials, used to sign requests to the server when using PLAINTEXT or
 * HMAC-SHA1 signature methods. An empty consumer secret is used if it's not supplied.
 * - "RSAPrivateKey" (mandatory, if RSA-SHA1 signature method is used) - PEM
 * formatted X.509 private key, used to sign requests to the server when using
 * RSA-SHA1 signature methods.
 * - "AuthorizationEndpoint" (mandatory) - Resource Owner Authorization endpoint,
 * to which the user (resource owner) is redirected to grant authorization, as specified in 
 * <ulink url="http://tools.ietf.org/html/rfc5849#section-2">RFC5849 section 2.</ulink>
 * - gsignond_session_data_set_username() and gsignond_session_data_set_secret() 
 * (optional) - these two parameters may be used when opening the authorization 
 * endpoint URI to initialize corresponding  fields on the webpage.
 * - "TokenEndpoint" (mandatory) - a URL that specifies an endpoint used by 
 * the plugin to obtain a set of access credentials, as specified in 
 * <ulink url="http://tools.ietf.org/html/rfc5849#section-2">RFC5849 section 2.</ulink>
 * 
 * <refsect2><title>Parameters for #GSignondPlugin::user-action-required signal issued by plugin</title></refsect2>
 * - gsignond_signonui_data_set_open_url() (mandatory) - a URI that should be opened in a 
 * user-agent (browser) for the user (resource owner) to authenticate herself. 
 * This URI is taken from "AuthorizationEndpoint" parameter of gsignond_plugin_request_initial()
 * and additional parameters may be appended to the query component.
 * - gsignond_signonui_data_set_final_url() (mandatory) - a URI where the user-agent should 
 * be redirected after a successfull authentication by the resource owner. This
 * expected URI is taken from the "Callback" parameter of gsignond_plugin_request_initial() call
 * to the plugin.The actual (vs. expected) URI may contain additional parameters in the query 
 * component of the URI that are used to continue the authorization process.
 * - gsignond_signonui_data_set_username() and gsignond_signonui_data_set_password() 
 * (optional) - these two parameters may be used when opening the URI to initialize 
 * corresponding fields on the webpage.
 * 
 * <refsect2><title>Parameters in gsignond_plugin_user_action_finished() @ui_data </title></refsect2>
 * 
 * - gsignond_signonui_data_set_query_error() (mandatory) - indicates if there
 * was an error in UI interaction and what it was. May be %SIGNONUI_ERROR_NONE
 * (which means no error), %SIGNONUI_ERROR_CANCELED or any other error.
 * - gsignond_signonui_data_get_url_response() (mandatory) - the URI that the user-agent
 * was redirected to. The callback URI supplied in parameters of
 * gsignond_plugin_request_initial() must be a prefix of this URI. The URI also
 * has to contain parameters in the query component that are necessary to continue
 * the authorization sequence.
 * 
 * <refsect2><title>Token and its parameters in #GSignondPlugin::response-final signal</title></refsect2>
 * gsignond_plugin_response_final() signal concludes the authorization process
 * and returns a #GSignondDictionary parameter that contains the access token
 * and some token parameters:
 * 
 * - "AccessToken" (mandatory) - the token itself
 * - "TokenSecret" (mandatory) - the token shared-secret, used by the application
 * to sign requests for protected resources
 * - "Realm" (optional) - the token realm, as specified in
 * <ulink url="http://tools.ietf.org/html/rfc5849#section-3.5.1">RFC5849 section 3.5.1.</ulink>
 * - "TokenParameters" (mandatory) - a #GSignondDictionary containing any
 * additional parameters returned by the server together with the access token. 
 * This dictionary may be empty, or
 * if it's not, it typically contains service-specific, non-standardized keys and
 * values.
 * 
 * <refsect1><title>OAuth version 2 parameters for authorization</title></refsect1>
 *
 * Where not specified otherwise, parameters are strings.
 *
 * <refsect2><title>Parameters in gsignond_plugin_request_initial() @identity_method_cache</title></refsect2>
 *
 * This parameter contains a cache of previously received tokens in the form of
 * a #GSignondDictionary. The keys are tokens' ClientId and values are also
 * #GSignondDictionary. Those second-level dictionaries contain token scopes as keys
 * and tokens as values. This two-level approach is done to allow caching several
 * tokens with unrelated scopes per client.
 *
 * Finally, each token is itself a #GSignondDictionary, with keys and values described
 * below in the token format section.
 *
 * <refsect2><title>Parameters in gsignond_plugin_request_initial() @session_data</title></refsect2>
 *
 * - "ClientId" (mandatory) - client identifier as described in 
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-2.2">RFC6749 section 2.2.</ulink>
 * - "ClientSecret" (optional) - client password as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-2.3">RFC6749 section 2.3.</ulink>
 * - gsignond_session_data_set_ui_policy() (mandatory) - if set to %GSIGNOND_UI_POLICY_DEFAULT
 * a default authorization sequence is used, which may involve re-using a
 * previously cached token without making any authorization server requests at all.
 * If set to %GSIGNOND_UI_POLICY_REQUEST_PASSWORD any cached token information 
 * (including a refresh token) corresponding to the ClientId is discarded and 
 * the authorization procedure is started from the beginning.
 * - gsignond_session_data_set_allowed_realms (mandatory) - a list of domains that
 * AuthHost and TokenHost must be in. The authorization sequence will fail if 
 * either of the hosts is not in this list.
 * - "Scope" (optional) - a space-separated list of scopes that are requested 
 * for the token, as specified in 
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.3">RFC6749 section 3.3.</ulink>
 * - "ForceClientAuthViaRequestBody" (optional) - by default the clients are authenticated via
 * HTTP Basic authorization mechanism, as described in 
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-2.3.1">RFC6749 section 2.3.1.</ulink>
 * The RFC stipulates that all OAuth 2 servers must support this, however, it 
 * was discovered that at least Google and Facebook require
 * client authorization in the request body (which is, according to standard,
 * optional and not recommended). If set to TRUE, this parameter forces this
 * non-compliant client authorization to be used.
 * - "ForceTokenRefresh" (optional) - normally if the token cache contains a
 * suitable token, it is returned immediately. If this parameter is set to TRUE,
 * then a refresh token is always used instead to obtain a new token.
 *
 * <refsect3><title>Parameters used for authorization code grant or implicit grant flows</title></refsect3>
 * - "ResponseType" (mandatory) - should be set to "code" or "token" as described in 
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.1.1">RFC6749 section 3.1.1.</ulink>
 * - "AuthHost" (mandatory) - hostname component of the authorization endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.1">RFC6749 section 3.1.</ulink> 
 * - "AuthPath" (mandatory) - pathname component of the authorization endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.1">RFC6749 section 3.1.</ulink> 
 * - "AuthPort" (optional) - port component of the authorization endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.1">RFC6749 section 3.1.</ulink>
 * If not specified, standard https port is used.
 * - "AuthQuery" (optional) - query component of the authorization endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.1">RFC6749 section 3.1.</ulink>
 * - "RedirectUri" (optional) - redirection endpoint as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.1.2">RFC6749 section 3.1.2.</ulink>
 * - gsignond_session_data_set_username() and gsignond_session_data_set_secret() 
 * (optional) - these two parameters may be used by UI implementation to 
 * initialize corresponding  fields on the webpage when opening the authorization 
 * endpoint URI. Also see "UseLoginHint".
 * - "UseLoginHint" (optional) - if set to TRUE, add the username (see above) to 
 * the authorization URI as a "login_hint" parameter, so that the authorization 
 * endpoint can pre-fill the login box, or selecte the proper multi-login session. 
 * This is a Google extension specified at 
 * <ulink url="https://developers.google.com/accounts/docs/OAuth2InstalledApp#formingtheurl">
 * https://developers.google.com/accounts/docs/OAuth2InstalledApp#formingtheurl</ulink>.
 * - "UseDisplay" (optional) - if set to a string, the parameter value is added to the authorization
 * URI as a "display" parameter. This is a Facebook extension specified at
 * <ulink url="https://developers.facebook.com/docs/reference/dialogs/oauth/">
 * https://developers.facebook.com/docs/reference/dialogs/oauth/</ulink>
 * and it affects the way the authorization page looks. Typical values are "page",
 * "popup" and "touch".
 *
 * <refsect3><title>Parameters used for resource owner password credentials grant flow</title></refsect3>
 * Refer to <ulink url="http://tools.ietf.org/html/rfc6749#section-4.3">RFC6749 section 4.3.</ulink>
 * - "GrantType" (mandatory) - must be set to "password"
 * - gsignond_session_data_set_username() and gsignond_session_data_set_secret() 
 * (mandatory) - resource owner username and password
 *
 * <refsect3><title>Parameters used for client credentials grant flow</title></refsect3>
 * Refer to <ulink url="http://tools.ietf.org/html/rfc6749#section-4.4">RFC6749 section 4.4.</ulink>
 * - "GrantType" (mandatory) - must be set to "client_credentials"
 *
 * <refsect3><title>Parameters used for authorization code, resource owner 
 * password or client credentials grant flows (but not implicit grant flow) </title></refsect3>
 *
 * - "TokenHost" (mandatory) - hostname component of the token endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.2">RFC6749 section 3.2.</ulink> 
 * - "TokenPath" (mandatory) - pathname component of the token endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.2">RFC6749 section 3.2.</ulink> 
 * - "TokenPort" (optional) - port component of the token endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.2">RFC6749 section 3.2.</ulink>
 * If not specified, standard https port is used.
 * - "TokenQuery" (optional) - query component of the token endpoint URI, as described in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.2">RFC6749 section 3.2.</ulink>
 *
 * <refsect2><title>Parameters for #GSignondPlugin::user-action-required signal issued by plugin</title></refsect2>
 * This signal is issued only when using authorization code grant or implicit code grant flows,
 * and contains the following parameters:
 * - gsignond_signonui_data_set_open_url() (mandatory) - an authorization endpoint URI that should be opened in a 
 * user-agent (browser) for the user (resource owner) to authenticate herself. 
 * This URI is constructed using parameters of gsignond_plugin_request_initial()
 * and additional parameters may be appended to the query component.
 * - gsignond_signonui_data_set_final_url() (optional) - a redirection endpoint URI where the user-agent should 
 * be redirected after authentication by the resource owner has finished. This
 * expected URI is taken from the "RedirectUri" parameter of gsignond_plugin_request_initial() call
 * to the plugin. The actual (vs. expected) URI may contain additional parameters in the query or fragment
 * components of the URI that are used to determine the outcome of the authorization process.
 * - gsignond_signonui_data_set_username() and gsignond_signonui_data_set_password() 
 * (optional) - these two parameters may be used when opening the authorization endpoint URI to initialize 
 * corresponding fields on the webpage.
 * 
 * <refsect2><title>Parameters in gsignond_plugin_user_action_finished() @ui_data </title></refsect2>
 * 
 * This function is called when UI interaction has completed and only when using
 * authorization code grant or implicit code grant flows.
 * 
 * - gsignond_signonui_data_set_query_error() (mandatory) - indicates if there
 * was an error in UI interaction and what it was. May be %SIGNONUI_ERROR_NONE
 * (which means no error), %SIGNONUI_ERROR_CANCELED or any other error.
 * - gsignond_signonui_data_get_url_response() (mandatory) - the URI that the user-agent
 * was redirected to. The redirection endpoint URI supplied in parameters of
 * gsignond_plugin_request_initial() must be a prefix of this URI. The URI also
 * has to contain parameters in the query component (if using authorization code grant) 
 * or in the fragment component (if using implicit code grant) that are necessary to continue
 * the authorization sequence. Specific information is provided at 
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-4.1.2">RFC6749 section 4.1.2</ulink>
 * and <ulink url="http://tools.ietf.org/html/rfc6749#section-4.2.2">RFC6749 section 4.2.2</ulink>
 * respectively.
 *
 * <refsect2><title>Token and its parameters in #GSignondPlugin::response-final signal</title></refsect2>
 * gsignond_plugin_response_final() signal concludes the authorization process
 * and returns a #GSignondDictionary parameter that contains the access token
 * and some token parameters:
 * 
 * - "AccessToken" (mandatory) - the token itself
 * - "TokenType" (mandatory) - the token type, as specified in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-7.1">RFC6749 section 7.1</ulink>.
 * Currently only one token type is supported (the bearer token, standardizied in
 * <ulink url="http://tools.ietf.org/html/rfc6750">RFC6750</ulink>).
 * - "TokenParameters" (mandatory) - a #GSignondDictionary containing any
 * additional parameters returned by the server together with the access token. 
 * The contents of this parameter is specific to the token type, and for bearer
 * tokens it's empty.
 * - "Scope" (optional) - the scopes of the issued token, a space separated list
 * as specified in 
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-3.3">RFC6749 section 3.3.</ulink>
 * - "Timestamp" (mandatory) - a gint64 Unix time specifying the time when token was issued.
 * A Unix time is the number of seconds that have elapsed since 1970-01-01 00:00:00 UTC.
 * - "Duration" (optional) - the lifetime in seconds of the access token. If specified, the token
 * will expire at Timestamp+Duration point in time.
 * - "RefreshToken" (optional) - refresh token as specified in
 * <ulink url="http://tools.ietf.org/html/rfc6749#section-6">RFC6749 section 6.</ulink>
 *
 * <refsect1><title>Plugin API common to OAuth1 and Oauth2</title></refsect1>
 *
 * <refsect2><title>Parameters of #GSignondPlugin::store signal</title></refsect2>
 * This signal is issued by the plugin when the token cache needs to be updated.
 * The parameter is a #GSignondDictionary of tokens. The specific cache format 
 * is same as @identity_method_cache parameter of gsignond_plugin_request_initial()
 * and is desribed in detail in corresponding OAuth1 and OAuth2 sections.
 * 
 * The token cache should be entirely replaced with the parameter of the signal;
 * the plugin preserves existing tokens that were supplied to 
 * gsignond_plugin_request_initial() in @identity_method_cache parameter.
 * 
 * <refsect2><title>Errors issued via #GSignondPlugin::error signal</title></refsect2>
 * At any point in the authorization process the plugin may issue this signal
 * with an @error parameter that is a #GError. The @error has <literal>domain</literal> field set to
 * %GSIGNOND_ERROR. <literal>code</literal> field can be one of %GSIGNOND_ERROR_MISSING_DATA 
 * (not enough data was supplied in gsignond_plugin_request_initial()),
 * %GSIGNOND_ERROR_NOT_AUTHORIZED (there was an error in the authorization
 * process), %GSIGNOND_ERROR_USER_INTERACTION (there was an error in the interaction
 * with the user), %GSIGNOND_ERROR_SESSION_CANCELED (the authorization process
 * was canceled). <literal>message</literal> field tells additional details about the exact cause of the
 * error, and it's intended to help programming and debugging, but not meant
 * to be understood by end users directly (although it can be shown to them).
 *
 */


#include <gsignond/gsignond-plugin-interface.h>
#include "gsignond-oauth-plugin.h"
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-log.h>
#include <stdlib.h>
#include "gsignond-oauth-plugin-oauth1.h"
#include "gsignond-oauth-plugin-oauth2.h"


static void gsignond_plugin_interface_init (GSignondPluginInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GSignondOauthPlugin, gsignond_oauth_plugin, 
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GSIGNOND_TYPE_PLUGIN,
                                                gsignond_plugin_interface_init));

static void _do_reset(GSignondOauthPlugin *self)
{
    if (self->soup_session)
        soup_session_abort(self->soup_session);
    _do_reset_oauth2(self);
    _do_reset_oauth1(self);
}


static void gsignond_oauth_plugin_cancel (GSignondPlugin *self)
{
    _do_reset(GSIGNOND_OAUTH_PLUGIN(self));
    GError* error = g_error_new(GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_SESSION_CANCELED,
                                "Session canceled");
    gsignond_plugin_error (self, error); 
    g_error_free(error);
}

static void gsignond_oauth_plugin_request (
    GSignondPlugin *plugin, GSignondSessionData *session_data)
{
    GError* error = g_error_new(GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_WRONG_STATE,
                                "Oauth plugin doesn't support request");
    gsignond_plugin_error (plugin, error); 
    g_error_free(error);
    return;    
}

static void gsignond_oauth_plugin_request_initial (
    GSignondPlugin *plugin, GSignondSessionData *session_data, 
    GSignondDictionary *token_cache,
    const gchar *mechanism)
{
    GSignondOauthPlugin *self = GSIGNOND_OAUTH_PLUGIN (plugin);

    _do_reset(self);
    
    const gchar* proxy = gsignond_session_data_get_network_proxy(session_data);
    SoupURI* uri = NULL;
    if (proxy != NULL) {
        uri = soup_uri_new(proxy);
        g_object_set(self->soup_session, "proxy-uri", uri, NULL);
        soup_uri_free(uri);
    }
    
    gboolean ssl_strict;
    gboolean res = gsignond_dictionary_get_boolean(session_data,
                                                   "SslStrict",
                                                   &ssl_strict);
    if (res == FALSE)
        ssl_strict = TRUE;
    g_object_set(self->soup_session, "ssl-strict", ssl_strict, NULL);
    
    if (g_strcmp0(mechanism, "oauth2") == 0)
        _process_oauth2_request(self, session_data, token_cache);
    else if (g_strcmp0(mechanism, "oauth1") == 0)
        _process_oauth1_request(self, session_data, token_cache);
    else {
        GError* error = g_error_new(GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_MECHANISM_NOT_AVAILABLE,
                                "Requested mechanism is not available");
        gsignond_plugin_error (plugin, error); 
        g_error_free(error);
    }
}

static void gsignond_oauth_plugin_user_action_finished (
    GSignondPlugin *plugin, 
    GSignondSignonuiData *session_data)
{
    GSignondOauthPlugin *self = GSIGNOND_OAUTH_PLUGIN (plugin);
    
    if (_is_active_oauth2_session(self) == TRUE)
        _process_oauth2_user_action_finished(self, session_data);
    else if (_is_active_oauth1_session(self) == TRUE)
        _process_oauth1_user_action_finished(self, session_data);
    else {
        GError* error = g_error_new(GSIGNOND_ERROR, 
                            GSIGNOND_ERROR_WRONG_STATE,
                            "Oauth plugin doesn't support user actions");
        gsignond_plugin_error (plugin, error); 
        g_error_free(error);
    }
}

static void gsignond_oauth_plugin_refresh (
    GSignondPlugin *plugin, 
    GSignondSignonuiData *session_data)
{
    GError* error = g_error_new(GSIGNOND_ERROR, 
                            GSIGNOND_ERROR_WRONG_STATE,
                            "Oauth plugin doesn't support refresh");
    gsignond_plugin_error (plugin, error); 
    g_error_free(error);
    return;
}

static void
gsignond_plugin_interface_init (GSignondPluginInterface *iface)
{
    iface->cancel = gsignond_oauth_plugin_cancel;
    iface->request_initial = gsignond_oauth_plugin_request_initial;
    iface->request = gsignond_oauth_plugin_request;
    iface->user_action_finished = gsignond_oauth_plugin_user_action_finished;
    iface->refresh = gsignond_oauth_plugin_refresh;
}

static void
_http_authenticate (SoupSession *session, SoupMessage *msg,
              SoupAuth *auth, gboolean retrying, gpointer data)
{
    GSignondOauthPlugin *self = GSIGNOND_OAUTH_PLUGIN (data);
    
    if (!retrying)
        if (_is_active_oauth2_session(self) == TRUE)
            _oauth2_http_authenticate (self, auth);
}

static void _log_http_traffic(SoupLogger *logger,
                              SoupLoggerLogLevel level,
                              char direction,
                              const char *data,
                              gpointer user_data)
{
    g_debug ("%c %s", direction, data);
}

static void
gsignond_oauth_plugin_init (GSignondOauthPlugin *self)
{
    self->oauth2_request = NULL;
    self->oauth1_request = NULL;
    self->token_cache = NULL;

    self->soup_session = soup_session_async_new_with_options (
        SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_PROXY_RESOLVER_DEFAULT,
        SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, TRUE,
        NULL);

    SoupLogger *logger = soup_logger_new (SOUP_LOGGER_LOG_BODY, -1);
    soup_logger_set_printer(logger, _log_http_traffic, NULL, NULL);
    soup_session_add_feature (self->soup_session, SOUP_SESSION_FEATURE (logger));
    g_object_unref (logger);    
    
    g_signal_connect (self->soup_session, "authenticate",
                          G_CALLBACK (_http_authenticate), self);    
}

static void
gsignond_oauth_plugin_finalize (GObject *gobject)
{
    GSignondOauthPlugin *self = GSIGNOND_OAUTH_PLUGIN (gobject);

    if (self->oauth2_request)
        gsignond_dictionary_unref(self->oauth2_request);
    if (self->oauth1_request)
        gsignond_dictionary_unref(self->oauth1_request);
    if (self->token_cache)
        gsignond_dictionary_unref(self->token_cache);
    if (self->soup_session)
        g_object_unref(self->soup_session);

    /* Chain up to the parent class */
    G_OBJECT_CLASS (gsignond_oauth_plugin_parent_class)->finalize (gobject);
}

enum
{
    PROP_0,
    
    PROP_TYPE,
    PROP_MECHANISMS
};

static void
gsignond_oauth_plugin_set_property (GObject      *object,
                                       guint         property_id,
                                       const GValue *value,
                                       GParamSpec   *pspec)
{
    switch (property_id)
    {
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
            break;
    }
}

static void
gsignond_oauth_plugin_get_property (GObject    *object,
                                       guint       prop_id,
                                       GValue     *value,
                                       GParamSpec *pspec)
{

    gchar *mechanisms[] = {"oauth1", "oauth2", NULL };
    
    switch (prop_id)
    {
        case PROP_TYPE:
            g_value_set_string (value, "oauth");
            break;
        case PROP_MECHANISMS:
            g_value_set_boxed (value, mechanisms);
            break;
            
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

static void
gsignond_oauth_plugin_class_init (GSignondOauthPluginClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
    gobject_class->set_property = gsignond_oauth_plugin_set_property;
    gobject_class->get_property = gsignond_oauth_plugin_get_property;
    gobject_class->finalize = gsignond_oauth_plugin_finalize;

    g_object_class_override_property (gobject_class, PROP_TYPE, "type");
    g_object_class_override_property (gobject_class, PROP_MECHANISMS, 
                                      "mechanisms");
}
