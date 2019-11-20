//   Copyright (C) 2015-2019 Virgil Security Inc.
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       (1) Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//       (2) Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//
//       (3) Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGE.
//
//   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package converters

/*
#cgo LDFLAGS: -L${SRCDIR}/../lib -lmbedcrypto -led25519 -lconverters
#include <virgil/iot/converters/crypto_format_converters.h>
*/
import "C"
import (
    "fmt"
    "unsafe"
)

// Convert Virgil signature to raw format
func VirgilSignToRaw(virgilSign []byte, ecType uint8) ([]byte, error) {
    const signatureBufSize = 512
    var rawSignBuf [signatureBufSize]uint8

    virgilSignPointer := (*C.uchar)(unsafe.Pointer(&virgilSign[0]))
    rawSignSize := C.uint16_t(0)
    rawSignPointer := (*C.uchar)(unsafe.Pointer(&rawSignBuf[0]))
    keyType := C.vs_secmodule_keypair_type_e(ecType)
    signSize := C.uint16_t(len(virgilSign))
    bufSize := C.uint16_t(signatureBufSize)

    convertRes := C.vs_converters_virgil_sign_to_raw(keyType,
                                                     virgilSignPointer,
                                                     signSize,
                                                     rawSignPointer,
                                                     bufSize,
                                                     &rawSignSize)
    if !convertRes {
        return nil, fmt.Errorf("failed to convert virgil signature to raw format")
    }
    return rawSignBuf[:rawSignSize], nil
}

// Convert Virgil pub key to Raw format
func VirgilPubKeyToRaw(virgilPubKey []byte, ecType uint8) ([]byte, error) {
    const pubKeyBufSize = 512
    var pubKeyBuf [pubKeyBufSize]uint8

    keyType := C.vs_secmodule_keypair_type_e(ecType)
    virgilPubKeyPtr := (*C.uchar)(unsafe.Pointer(&virgilPubKey[0]))
    virgilPubKeySize := C.uint16_t(len(virgilPubKey))
    rawPubKeyPointer := (*C.uchar)(unsafe.Pointer(&pubKeyBuf[0]))
    rawKeySize := C.uint16_t(0)
    bufSize := C.uint16_t(pubKeyBufSize)

    convertRes := C.vs_converters_pubkey_to_raw(keyType,
                                                virgilPubKeyPtr,
                                                virgilPubKeySize,
                                                rawPubKeyPointer,
                                                bufSize,
                                                &rawKeySize)
    if !convertRes {
        return nil, fmt.Errorf("failed to convert public key in Virgil format to raw")
    }
    return pubKeyBuf[:rawKeySize], nil
}
