//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include <virgil/iot/messenger/internal/enjabberd.h>
#include <strophe.h>
#include "private/visibility.h"


/* hardcoded TCP keepalive timeout and interval */
#define KA_TIMEOUT 60
#define KA_INTERVAL 1

static vs_messenger_enjabberd_rx_encrypted_cb_t _rx_encrypted_cb = NULL;
static xmpp_ctx_t *_ctx;
static xmpp_conn_t *_conn;
static char *_host = NULL;
static bool _is_ready = false;

/******************************************************************************/
static int
_version_handler(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza, void *const userdata) {
    xmpp_stanza_t *reply, *query, *name, *version, *text;
    const char *ns;
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    int default_res = 1;

    // Check input parameters
    VS_IOT_ASSERT(conn);
    VS_IOT_ASSERT(stanza);
    VS_IOT_ASSERT(userdata);
    CHECK_NOT_ZERO_RET(conn, default_res);
    CHECK_NOT_ZERO_RET(stanza, default_res);
    CHECK_NOT_ZERO_RET(userdata, default_res);

    VS_LOG_DEBUG("Received version request from %s", xmpp_stanza_get_from(stanza));

    reply = xmpp_stanza_reply(stanza);
    xmpp_stanza_set_type(reply, "result");

    query = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(query, "query");
    ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza));
    if (ns) {
        xmpp_stanza_set_ns(query, ns);
    }

    name = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(name, "name");
    xmpp_stanza_add_child(query, name);
    xmpp_stanza_release(name);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "Virgil IoT Messenger");
    xmpp_stanza_add_child(name, text);
    xmpp_stanza_release(text);

    version = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(version, "version");
    xmpp_stanza_add_child(query, version);
    xmpp_stanza_release(version);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "0.1.5");
    xmpp_stanza_add_child(version, text);
    xmpp_stanza_release(text);

    xmpp_stanza_add_child(reply, query);
    xmpp_stanza_release(query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);

    return 1;
}

/******************************************************************************/
static int
_message_handler(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza, void *const userdata) {
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    xmpp_stanza_t *body;
    const char *type;
    char *intext;
    char *sender = NULL;
    char *at_symbol = NULL;
    int default_res = 1;

    // Check input parameters
    VS_IOT_ASSERT(conn);
    VS_IOT_ASSERT(stanza);
    VS_IOT_ASSERT(userdata);
    CHECK_NOT_ZERO_RET(conn, default_res);
    CHECK_NOT_ZERO_RET(stanza, default_res);
    CHECK_NOT_ZERO_RET(userdata, default_res);

    // Do not process message if callback function is not set
    if (!_rx_encrypted_cb) {
        VS_LOG_WARNING("Message callback is not present");
        return 1;
    }

    // Check is message body present
    body = xmpp_stanza_get_child_by_name(stanza, "body");
    if (body == NULL) {
        return 1;
    }

    // Check is not an error
    type = xmpp_stanza_get_type(stanza);
    if (type != NULL && 0 == strcmp(type, "error")) {
        return 1;
    }

    // Get message body
    intext = xmpp_stanza_get_text(body);

    // Get sender's identity
    sender = strdup(xmpp_stanza_get_from(stanza));
    at_symbol = strchr(sender, '@');
    if (at_symbol) {
        *at_symbol = 0;
    }

    // Pass received message to a callback function
    _rx_encrypted_cb(sender, intext);

    // Clean-up
    free(sender);
    xmpp_free(ctx, intext);

    return 1;
}

/******************************************************************************/
static void
_conn_handler(xmpp_conn_t *const conn,
              const xmpp_conn_event_t status,
              const int error,
              xmpp_stream_error_t *const stream_error,
              void *const userdata) {
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    // Check input parameters
    VS_IOT_ASSERT(conn);
    VS_IOT_ASSERT(userdata);

    if (status == XMPP_CONN_CONNECT) {
        xmpp_stanza_t *pres;
        VS_LOG_INFO("connected");
        xmpp_handler_add(conn, _version_handler, "jabber:iq:version", "iq", NULL, ctx);
        xmpp_handler_add(conn, _message_handler, NULL, "message", NULL, ctx);

        // Send initial <presence/> so that we appear online to contacts
        pres = xmpp_presence_new(ctx);
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);

        _is_ready = true;
    } else {
        VS_LOG_INFO("disconnected");
        xmpp_stop(ctx);
    }
}

/******************************************************************************/
static char *
_jid_from_identity(const char *identity) {
    char *jid = NULL;
    size_t jid_sz = 0;

    // Check input parameters
    CHECK_NOT_ZERO_RET(identity && identity[0], NULL);

    jid_sz = strlen(identity) + strlen(_host) + 2; // 2 is zero-terminator + '@'
    jid = (char *)(calloc(1, jid_sz));
    sprintf(jid, "%s@%s", identity, _host);

    return jid;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_enjabberd_connect(const char *host,
                               uint16_t port,
                               const char *identity,
                               const char *pass,
                               vs_messenger_enjabberd_rx_encrypted_cb_t rx_cb) {

    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    xmpp_log_t *log;
    char *jid = NULL;

    // Check input parameters
    CHECK_NOT_ZERO(host && host[0]);
    CHECK_NOT_ZERO(identity && identity[0]);
    CHECK_NOT_ZERO(pass && pass[0]);
    CHECK_NOT_ZERO(rx_cb);

    _rx_encrypted_cb = rx_cb;

    // Save host name
    free(_host);
    _host = strdup(host);
    CHECK_NOT_ZERO_RET(_host, VS_CODE_ERR_NO_MEMORY);

    // init library
    _is_ready = false;
    xmpp_initialize();

    // pass NULL instead to silence output
    log = xmpp_get_default_logger(XMPP_LEVEL_WARN);

    // create a context
    _ctx = xmpp_ctx_new(NULL, log);

    // create a connection
    _conn = xmpp_conn_new(_ctx);

    // configure TCP keepalive (optional)
    xmpp_conn_set_keepalive(_conn, KA_TIMEOUT, KA_INTERVAL);

    // setup authentication information
    jid = _jid_from_identity(identity);
    CHECK_NOT_ZERO_RET(jid, VS_CODE_ERR_NO_MEMORY);
    xmpp_conn_set_jid(_conn, jid);
    xmpp_conn_set_pass(_conn, pass);
    free(jid);

    // initiate connection
    if (XMPP_EOK != xmpp_connect_client(_conn, host, port, _conn_handler, _ctx)) {
        VS_LOG_ERROR("Cannot connect to enjabberd");
        return VS_CODE_ERR_MSGR_INTERNAL;
    }

    // enter the event loop - our connect handler will trigger an exit
    xmpp_run(_ctx);

    // release our connection and context
    xmpp_conn_release(_conn);
    xmpp_ctx_free(_ctx);

    // final shutdown of the library
    xmpp_shutdown();

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_enjabberd_send(const char *identity, const char *message) {
    vs_status_e res = VS_CODE_ERR_MSGR_INTERNAL;
    xmpp_stanza_t *msg, *body, *text;
    char *jid = NULL;

    // Check input parameters
    CHECK_NOT_ZERO(identity && identity[0]);
    CHECK_NOT_ZERO(message);

    // Check is correctly connected
    CHECK(_is_ready, "Enjabberd connection is not ready.");

    // Create JID for identity
    jid = _jid_from_identity(identity);
    CHECK_NOT_ZERO_RET(jid, VS_CODE_ERR_NO_MEMORY);

    // Set message information
    msg = xmpp_stanza_new(_ctx);
    xmpp_stanza_set_name(msg, "message");
    xmpp_stanza_set_type(msg, "chat");
    xmpp_stanza_set_attribute(msg, "to", jid);
    free(jid);

    // Set message body
    body = xmpp_stanza_new(_ctx);
    xmpp_stanza_set_name(body, "body");
    text = xmpp_stanza_new(_ctx);
    xmpp_stanza_set_text(text, message);
    xmpp_stanza_add_child(body, text);
    xmpp_stanza_add_child(msg, body);

    // Send message
    xmpp_send(_conn, msg);

    // Clean data
    xmpp_stanza_release(msg);

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_enjabberd_set_status(void) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
DLL_PUBLIC vs_status_e
vs_messenger_enjabberd_disconnect(void) {
    _is_ready = false;

    // terminate connection
    if (_conn) {
        xmpp_conn_release(_conn);
        _conn = NULL;
    }

    // Clean data
    free(_host);
    _host = NULL;

    return VS_CODE_OK;
}

/******************************************************************************/