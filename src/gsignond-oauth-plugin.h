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

#ifndef __GSIGNOND_OAUTH_PLUGIN_H__
#define __GSIGNOND_OAUTH_PLUGIN_H__

#include <glib-object.h>
#include <gsignond/gsignond-session-data.h>
#include <libsoup/soup.h>



#define GSIGNOND_TYPE_OAUTH_PLUGIN             (gsignond_oauth_plugin_get_type ())
#define GSIGNOND_OAUTH_PLUGIN(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GSIGNOND_TYPE_OAUTH_PLUGIN, GSignondOauthPlugin))
#define GSIGNOND_IS_OAUTH_PLUGIN(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GSIGNOND_TYPE_OAUTH_PLUGIN))
#define GSIGNOND_OAUTH_PLUGIN_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GSIGNOND_TYPE_OAUTH_PLUGIN, GSignondOauthPluginClass))
#define GSIGNOND_IS_OAUTH_PLUGIN_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GSIGNOND_TYPE_OAUTH_PLUGIN))
#define GSIGNOND_OAUTH_PLUGIN_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GSIGNOND_TYPE_OAUTH_PLUGIN, GSignondOauthPluginClass))

/**
 * GSignondOauthPlugin:
 * 
 * Opaque structure for the OAuth plugin object
 */
typedef struct _GSignondOauthPlugin        GSignondOauthPlugin;

/**
 * GSignondOauthPluginClass:
 * 
 * Opaque structure for the OAuth plugin class
 */
typedef struct _GSignondOauthPluginClass   GSignondOauthPluginClass;

struct _GSignondOauthPlugin
{
    GObject parent_instance;
    
    GSignondSessionData* oauth2_request;
    GSignondSessionData* oauth1_request;
    GSignondDictionary* token_cache;
    SoupSession* soup_session;
};

struct _GSignondOauthPluginClass
{
    /*< private >*/
    GObjectClass parent_class;
};

GType gsignond_oauth_plugin_get_type (void);

#endif /* __GSIGNOND_OAUTH_PLUGIN_H__ */
