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

#include <iostream>
#include <private/enjabberd.h>
#include <strophe.h>

using namespace VirgilIoTKit;

/* hardcoded TCP keepalive timeout and interval */
#define KA_TIMEOUT 60
#define KA_INTERVAL 1

// URLConstants.ejabberdHost
// URLConstants.ejabberdHostPort
//
// xmppStreamWillConnect(_ sender: XMPPStream)
// xmppStreamDidConnect(_ stream: XMPPStream)
// xmppStreamConnectDidTimeout(_ sender: XMPPStream)
// xmppStreamDidDisconnect(_ sender: XMPPStream, withError error: Error?)
// xmppStreamDidAuthenticate(_ sender: XMPPStream)
// xmppStream(_ sender: XMPPStream, didNotAuthenticate error: DDXMLElement)
// xmppStream(_ sender: XMPPStream, didSend message: XMPPMessage)
// xmppStream(_ sender: XMPPStream, didFailToSend message: XMPPMessage, error: Error)
// xmppStream(_ sender: XMPPStream, didReceive message: XMPPMessage)

static vs_messenger_enjabberd_rx_encrypted_cb_t _rx_encrypted_cb = NULL;

/******************************************************************************/
extern "C" int
version_handler(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza, void *const userdata) {
    xmpp_stanza_t *reply, *query, *name, *version, *text;
    const char *ns;
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    printf("Received version request from %s\n", xmpp_stanza_get_from(stanza));

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
    xmpp_stanza_set_text(text, "libstrophe example bot");
    xmpp_stanza_add_child(name, text);
    xmpp_stanza_release(text);

    version = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(version, "version");
    xmpp_stanza_add_child(query, version);
    xmpp_stanza_release(version);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "1.0");
    xmpp_stanza_add_child(version, text);
    xmpp_stanza_release(text);

    xmpp_stanza_add_child(reply, query);
    xmpp_stanza_release(query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    return 1;
}

/******************************************************************************/
extern "C" int
message_handler(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza, void *const userdata) {
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    xmpp_stanza_t *body, *reply;
    const char *type;
    char *intext, *replytext;
    int quit = 0;
    char *sender = NULL;
    char *at_symbol = NULL;

    body = xmpp_stanza_get_child_by_name(stanza, "body");
    if (body == NULL)
        return 1;
    type = xmpp_stanza_get_type(stanza);
    if (type != NULL && strcmp(type, "error") == 0)
        return 1;

    intext = xmpp_stanza_get_text(body);

    printf("Incoming message from %s: %s\n", xmpp_stanza_get_from(stanza), intext);

    // Process received message
    if (_rx_encrypted_cb) {
        // Get sender's identity
        sender = strdup(xmpp_stanza_get_from(stanza));
        at_symbol = strchr(sender, '@');
        if (at_symbol) {
            *at_symbol = 0;
        }
        _rx_encrypted_cb(sender, intext);

        free(sender);
        sender = NULL;
    }

    reply = xmpp_stanza_reply(stanza);
    if (xmpp_stanza_get_type(reply) == NULL)
        xmpp_stanza_set_type(reply, "chat");

    if (strcmp(intext, "quit") == 0) {
        replytext = strdup("bye!");
        quit = 1;
    } else {
        replytext = (char *)malloc(strlen(" to you too!") + strlen(intext) + 1);
        strcpy(replytext, intext);
        strcat(replytext, " to you too!");
    }
    xmpp_free(ctx, intext);
    xmpp_message_set_body(reply, replytext);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    free(replytext);

    if (quit)
        xmpp_disconnect(conn);

    return 1;
}

/******************************************************************************/
extern "C" void
conn_handler(xmpp_conn_t *const conn,
             const xmpp_conn_event_t status,
             const int error,
             xmpp_stream_error_t *const stream_error,
             void *const userdata) {
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    if (status == XMPP_CONN_CONNECT) {
        xmpp_stanza_t *pres;
        fprintf(stderr, "DEBUG: connected\n");
        xmpp_handler_add(conn, version_handler, "jabber:iq:version", "iq", NULL, ctx);
        xmpp_handler_add(conn, message_handler, NULL, "message", NULL, ctx);

        /* Send initial <presence/> so that we appear online to contacts */
        pres = xmpp_presence_new(ctx);
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);
    } else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_enjabberd_connect(const char *host,
                               uint16_t port,
                               const char *identity,
                               const char *pass,
                               vs_messenger_enjabberd_rx_encrypted_cb_t rx_cb) {

    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    long flags = 0;
    int tcp_keepalive = 1;
    char *jid = NULL;
    size_t jid_sz = 0;

    _rx_encrypted_cb = rx_cb;

    /* init library */
    xmpp_initialize();

    /* pass NULL instead to silence output */
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);

    /* create a context */
    ctx = xmpp_ctx_new(NULL, log);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* configure connection properties (optional) */
    //    xmpp_conn_set_flags(conn, flags);
    /* configure TCP keepalive (optional) */
    if (tcp_keepalive)
        xmpp_conn_set_keepalive(conn, KA_TIMEOUT, KA_INTERVAL);

    /* setup authentication information */
    jid_sz = strlen(identity) + strlen(host) + 2; // 2 is zero-terminator + '@'
    jid = (char *)(calloc(1, jid_sz));
    sprintf(jid, "%s@%s", identity, host);

    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);

    /* initiate connection */
    if (XMPP_EOK != xmpp_connect_client(conn, host, port, conn_handler, ctx)) {
        std::cerr << "Cannot connect to enjabberd" << std::endl;
        exit(-1);
    }

    /* enter the event loop -
       our connect handler will trigger an exit */
    xmpp_run(ctx);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* final shutdown of the library */
    xmpp_shutdown();

    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_enjabberd_send(const char *identity, const char *message) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_enjabberd_set_status(void) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
extern "C" vs_status_e
vs_messenger_enjabberd_disconnect(void) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/