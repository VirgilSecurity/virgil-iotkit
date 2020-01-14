//   Copyright (C) 2015-2020 Virgil Security Inc.
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
    "sync"
    "time"
)

type DeviceInfo struct {
	ID            string `json:"id"`
	ManufactureID string `json:"manufacture_id"`
	DeviceType    string `json:"device_type"`
	Roles       []string `json:"roles"`
	FWVersion     string `json:"fw_version"`
	TLVersion     string `json:"tl_version"`
	MAC           string `json:"mac"`
	Sent          uint32 `json:"sent"`
	Received      uint32 `json:"received"`
	lastTime      int32

}

type ConcurrentDevices struct {
	sync.RWMutex
	items map[string]DeviceInfo
}

func (d *ConcurrentDevices) UpdateDeviceGeneralInfo(info DeviceInfo) error {
    d.Lock()
    defer d.Unlock()

    cd := d.items[info.MAC]
    cd.ManufactureID = info.ManufactureID
    cd.DeviceType = info.DeviceType
    cd.FWVersion = info.FWVersion
    cd.TLVersion = info.TLVersion
    cd.MAC = info.MAC
    cd.Roles = info.Roles
    cd.lastTime = int32(time.Now().Unix())
    d.items[info.MAC] = cd
    return nil
}

func (d *ConcurrentDevices) UpdateDeviceStatistics(info DeviceInfo) error {
    d.Lock()
    defer d.Unlock()

    info.lastTime = int32(time.Now().Unix())
    cd := d.items[info.MAC]
    cd.MAC = info.MAC
    cd.Sent = info.Sent
    cd.Received = info.Received
    cd.lastTime = int32(time.Now().Unix())
    d.items[info.MAC] = cd
    return nil
}

func (d *ConcurrentDevices) CleanList(cleanTimeout int32) error {
    d.Lock()
    defer d.Unlock()

    utime := int32(time.Now().Unix())

    // Collect keys to delete
    keyToDelete := []string{};
    for _, d := range d.items {
        if utime - d.lastTime > cleanTimeout {
            keyToDelete = append(keyToDelete, d.MAC)
        }
    }

    // Remove old devices from map
    for _, k := range keyToDelete {
        delete(d.items, k)
    }

    return nil
}

func (d *ConcurrentDevices) GetItems() map[string]DeviceInfo {
    d.RLock()
    defer d.RUnlock()

    // Copy map
    copy := make(map[string]DeviceInfo)

    for key, value := range d.items {
      copy[key] = value
    }

    return copy
}

func NewDevices() *ConcurrentDevices {
    var d ConcurrentDevices
    d.items = make(map[string]DeviceInfo)
    return &d
}