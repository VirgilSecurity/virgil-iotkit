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

package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"os"
	"strconv"
	"time"
	"sort"
	"strings"

	"./snap"
	"./devices"
	"./utils"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var devicesInfo *devices.ConcurrentDevices

func GeneralInfoCb(generalInfo devices.DeviceInfo) error {
    return devicesInfo.UpdateDeviceGeneralInfo(generalInfo)
}

func StatCb(stat devices.DeviceInfo) error {
    return devicesInfo.UpdateDeviceStatistics(stat)
}

func CleanupProcessStart() {
    ticker := time.NewTicker(5 * time.Second)
    quit := make(chan struct{})
    go func() {
        for {
           select {
            case <- ticker.C:
                devicesInfo.CleanList(5)
            case <- quit:
                ticker.Stop()
                return
            }
        }
     }()
}


func main() {
    // Initialize logs
    utils.NewLog()

   	// first - read from run params,  second from SNAPD_SERVICE_PORT env, third - set default 8080
	listeningPort := readListeningPort(os.Args)

	devicesInfo = devices.NewDevices()

	// Start SNAP:INFO communication
	err :=  snap.ConnectToDeviceNetwork()
	if err != nil {
    	utils.Log.Println(err)
    	return
    }

    // Test SNAP:_CFG:CONF
//     err = snap.UploadTestConfig()
//     if err != nil {
//         utils.Log.Println(err)
//         return
//     }

    err = snap.SetupPolling(GeneralInfoCb, StatCb)
    if err != nil {
        utils.Log.Println(err)
        return
    }

    CleanupProcessStart()

	http.HandleFunc("/ws/devices", func(w http.ResponseWriter, r *http.Request) {

		conn, err := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity
		if err != nil {
			utils.Log.Println(err)
			return
		}

		for t := range time.NewTicker(2 * time.Second).C {

			table := createStatusTable(t)
			if err = conn.WriteMessage(1, []byte(table)); err != nil {
				utils.Log.Println(err)
				return
			}
		}

	})

	http.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {

	    devices := devicesInfo.GetItems()

		if r.Method == "GET" {
			keys, ok := r.URL.Query()["key"]

			if ok {
				respBody, err := json.Marshal(devices[keys[0]])
				if err != nil {
					utils.Log.Println(err)
				}

				_, err = w.Write(respBody)
				if err != nil {
					utils.Log.Println("err writing resp  body: " + err.Error())
				}
				return
			}


			respBody, err := json.Marshal(devices)
			if err != nil {
				utils.Log.Println(err)
			}
			_, err = w.Write(respBody)
			if err != nil {
				utils.Log.Println("err writing resp  body: " + err.Error())
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprint(w, HtmlPage)
		if err != nil {
			fmt.Println(err)
		}
	})

	utils.Log.Println(fmt.Sprintf("Service started. Web SNAPD interface located here: http://localhost:%d", listeningPort))

	err = http.ListenAndServe(fmt.Sprintf(":%d", listeningPort), nil)
	if err != nil {
		utils.Log.Println(err)
	}
}

func createStatusTable(t time.Time) string {
	table := "<tr> <td>MAC</td> <td>ManufactureID</td> <td>DeviceType</td> <td>Firmware Version</td> <td>Trust List Version</td> <td>Sent</td>  <td>Received</td> <td>Device Roles</td> </tr>"

    devices := devicesInfo.GetItems()

    // Sorted keys
    keys := make([]string, 0, len(devices))
    for k := range devices {
	    keys = append(keys, k)
    }
    sort.Strings(keys)

	for _, k := range keys {
        d := devices[k]
        table += fmt.Sprintf("<tr><td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> <td>%d</td> <td>%d</td> <td>%s</td>  </tr>",
			d.MAC,
			d.ManufactureID,
			d.DeviceType,
			d.FWVersion,
			d.TLVersion,
			d.Sent,
			d.Received,
			strings.Trim(strings.Join(strings.Fields(fmt.Sprint(d.Roles)), ", "), "[]"),
		)
	}

	return table
}

func readListeningPort(args []string) int {
	if len(args) > 2 {
		intPort, err := strconv.Atoi(os.Args[1])
		if err == nil {
			return intPort
		}
		utils.Log.Println("err reading port from args : " + err.Error())

	}
	port, ok := os.LookupEnv("SNAPD_SERVICE_PORT")
	if ok {
		intPort, err := strconv.Atoi(port)
		if err == nil {
			return intPort
		}
		utils.Log.Println("err reading port from env : " + err.Error())

	}
	return 8080
}


var HtmlPage = `

<table id='tbl' border=1></table>
<p id="date"></p>

<script>

    tbl = document.getElementById('tbl');

    var url = document.URL
    url = url.replace("http","ws")


    var table_output = document.getElementById("tbl");
    table_output.innerHTML = "<tr> <td>MAC</td> <td>ManufactureID</td> <td>DeviceType</td> <td>Firmware Version</td> <td>Trust List Version</td> <td>Sent</td>  <td>Received</td> <td>Device Roles</td> </tr>"

    var device_table_socket = new WebSocket(url + "ws/devices");
   
    device_table_socket.onmessage = function (e) {
        table_output.innerHTML = e.data;
        document.getElementById("date").innerHTML = Date();
    };

</script>
`
