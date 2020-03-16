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

#include <private/enjabberd.h>

using namespace VirgilIoTKit;

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

/******************************************************************************/
vs_status_e
vs_messenger_enjabberd_connect(const char *host, uint16_t port, const char *identity, vs_messenger_rx_cb_t rx_cb) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
vs_status_e
vs_messenger_enjabberd_send(const char *identity, const char *message) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
vs_status_e
vs_messenger_enjabberd_set_status(void) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
vs_status_e
vs_messenger_enjabberd_disconnect(void) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/