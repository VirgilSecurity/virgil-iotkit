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

package request

import (
    "encoding/hex"
    "encoding/json"
    "fmt"
    "time"

    "../common"
    "../converters"
    "../snap"

    "gopkg.in/virgil.v5/sdk"
)

type Builder struct {
    Signer          common.SignerInterface
    DeviceProcessor *snap.DeviceProcessor

    deviceInfo      *DeviceInfoJson
}

type DeviceInfoJson struct {
    Manufacturer  string      `json:"manufacturer"`
    Model         string      `json:"model"`
    Roles         []string    `json:"roles"`
    Mac           string      `json:"mac"`
    Serial        []byte      `json:"serial"`
    PublicKeyTiny []byte      `json:"publicKeyTiny"`
    Signature     []byte      `json:"signature"`
    KeyType       uint8       `json:"key_type"`
    ECType        uint8       `json:"ec_type"`
}

type CardSnapshotJson struct {
    Device        string      `json:"device"`
    DeviceName    string      `json:"device_name"`
    *DeviceInfoJson
}

func (b Builder) BuildRequest() (string, error) {
    var err error

    identity := hex.EncodeToString(b.DeviceProcessor.Serial[:])

    // Convert raw public key to Virgil format
    var virgilPubKey []byte
    virgilPubKey, err = converters.RawPubKeyToVirgil(b.DeviceProcessor.DevicePublicKey.RawPubKey,
                                                     b.DeviceProcessor.DevicePublicKey.ECType)
    if err != nil {
        return "", err
    }

    // Prepare card content snapshot
    cardContent := sdk.RawCardContent{
        Identity:       identity,
        PublicKey:      virgilPubKey,
        CreatedAt:      time.Now().UTC().Unix(),
        Version:        sdk.CardVersion,
    }
    cardContentSnapshot, err := sdk.TakeSnapshot(cardContent)
    if err != nil {
        return "", fmt.Errorf("failed to take content snapshot: %v", err)
    }

    // Create card
    rawCard := sdk.RawSignedModel{
        ContentSnapshot: cardContentSnapshot,
    }

    // Sign combined snapshot inside device
    extraContent, err := b.GetCardSnapshot()
    if err != nil {
        return "", fmt.Errorf("failed to get device info: %v", err)
    }
    combinedSnapshot := append(rawCard.ContentSnapshot, extraContent...)
    signature, err := b.Signer.Sign(combinedSnapshot)
    if err != nil {
        return "", err
    }
    rawSignature := sdk.RawCardSignature{
        Signer:    "self",
        Signature: signature,
        Snapshot:  extraContent,
    }

    // Append signature to card
    rawCard.Signatures = append(rawCard.Signatures, &rawSignature)

    // Export card as base64
    rawCardBase64, err := rawCard.ExportAsBase64EncodedString()
    if err != nil {
        return "", fmt.Errorf("failed to export card as base64: %v", err)
    }
    return rawCardBase64, nil
}

func (b *Builder) GetDeviceInfo() ([]byte, error) {
    mac := b.DeviceProcessor.DeviceMacAddr
    info := &DeviceInfoJson{
        Manufacturer:    fmt.Sprintf("%#x", b.DeviceProcessor.Manufacturer),
        Model:           fmt.Sprintf("%#x", b.DeviceProcessor.Model),
        Mac:             fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
        Serial:          b.DeviceProcessor.Serial[:],
        PublicKeyTiny:   b.DeviceProcessor.DevicePublicKey.RawPubKey,
        Signature:       b.DeviceProcessor.Signature.RawSignature,
        KeyType:         b.DeviceProcessor.DevicePublicKey.KeyType,
        ECType:          b.DeviceProcessor.DevicePublicKey.ECType,
        Roles:           b.DeviceProcessor.Roles,
    }
    b.deviceInfo = info
    marshaled, err := json.Marshal(info)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal DeviceInfoJson: %v", err)
    }
    return marshaled, nil
}

func (b *Builder) GetCardSnapshot() ([]byte, error) {
    deviceInfo := CardSnapshotJson{
        Device:         "",
        DeviceName:     fmt.Sprint(b.DeviceProcessor.Model),
        DeviceInfoJson: b.deviceInfo,
    }
    marshaled, err := json.Marshal(deviceInfo)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal CardSnapshotJson: %v", err)
    }
    return marshaled, nil
}
