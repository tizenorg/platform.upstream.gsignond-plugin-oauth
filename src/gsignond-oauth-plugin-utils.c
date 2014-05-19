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


 
#include <glib.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "gsignond-oauth-plugin-utils.h"
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-utils.h>
#include <stdlib.h>

gchar* gsignond_oauth_plugin_generate_random_data(size_t len)
{
    void* random_data = malloc(len);

    int res = gnutls_rnd(GNUTLS_RND_NONCE, random_data, len);
    if (res != 0) {
        free(random_data);
        return NULL;
    }
    
    gchar* out = g_base64_encode(random_data, len);
    free(random_data);    
    return out;
}

void gsignond_oauth_plugin_check_host(const gchar* host,
                        GSequence* allowed_domains,
                        GError** error)
{
    GSequenceIter* iter;

    if (!allowed_domains) {
        *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_MISSING_DATA,
                            "Missing realm list");
        return;
    }

    for (iter = g_sequence_get_begin_iter (allowed_domains);
         iter != g_sequence_get_end_iter (allowed_domains);
         iter = g_sequence_iter_next (iter)) {
        if (gsignond_is_host_in_domain(host, g_sequence_get(iter))) {
            g_sequence_free(allowed_domains);
            return;
        }
    }
    g_sequence_free (allowed_domains);
    *error = g_error_new(GSIGNOND_ERROR,
                            GSIGNOND_ERROR_NOT_AUTHORIZED,
                            "Unauthorized host");
}
