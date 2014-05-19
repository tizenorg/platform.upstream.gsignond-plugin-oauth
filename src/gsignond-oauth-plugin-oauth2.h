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

#ifndef __GSIGNOND_OAUTH_PLUGIN_OAUTH2_H__
#define __GSIGNOND_OAUTH_PLUGIN_OAUTH2_H__

void _do_reset_oauth2(GSignondOauthPlugin *self);

gboolean _is_active_oauth2_session(GSignondOauthPlugin *self);

void _oauth2_http_authenticate(GSignondOauthPlugin *self, SoupAuth *auth);

void _process_oauth2_request(GSignondOauthPlugin *self, 
                             GSignondSessionData *session_data,
                             GSignondDictionary *tokens
                            );

void _process_oauth2_user_action_finished(GSignondOauthPlugin *self, 
                                         GSignondSignonuiData *ui_data);

#endif