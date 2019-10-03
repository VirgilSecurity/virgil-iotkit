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

package devices

import (
    "fmt"
    "sync"
    "time"
)

type DeviceInfo struct {
	ID            string `json:"id"`
	ManufactureID string `json:"manufacture_id"`
	DeviceType    string `json:"device_type"`
	Version       string `json:"version"`
	MAC           string `json:"mac"`
	lastTime      int32

}

type ConcurrentDevices struct {
	sync.RWMutex
	Items map[string]DeviceInfo
}

func (d *ConcurrentDevices) UpdateDevice(info DeviceInfo) error {
    fmt.Printf("Update device\n")
    info.lastTime = int32(time.Now().Unix())
    d.Items[info.MAC] = info
    return nil
}

func (d *ConcurrentDevices) CleanList(cleanTimeout int32) error {
    utime := int32(time.Now().Unix())

    // Collect keys to delete
    keyToDelete := []string{};
    for _, d := range d.Items {
        if utime - d.lastTime > cleanTimeout {
            keyToDelete = append(keyToDelete, d.MAC)
        }
    }

    // Remove old devices from map
    for _, k := range keyToDelete {
        delete(d.Items, k)
    }

    return nil
}

func NewDevices() *ConcurrentDevices {
    var d ConcurrentDevices
    d.Items = make(map[string]DeviceInfo)
    return &d
}