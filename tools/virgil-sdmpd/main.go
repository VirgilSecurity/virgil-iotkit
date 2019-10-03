package main

/*
#cgo LDFLAGS: -lsdmp-factory -ltools-hal -llogger
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/info-client.h>
#include <virgil/iot/tools/hal/ti_netif_udp_bcast.h>
#include <virgil/iot/tools/hal/sdmp/ti_info_impl.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"os"
	"strconv"
	"time"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

const (
    DEFAULT_TIMEOUT_MS = 7000
)

type DeviceInfo struct {
	ID            string `json:"id"`
	ManufactureID string `json:"manufacture_id"`
	DeviceType    string `json:"device_type"`
	Version       string `json:"version"`
	MAC           string `json:"mac"`
}

var devices []DeviceInfo

func main() {

// Use UDP Broadcast as transport
fmt.Printf(">>> 1\n")
    if 0 != C.vs_sdmp_init(C.vs_hal_netif_udp_bcast()) {
        fmt.Errorf("can't start SDMP communication")
    }

fmt.Printf(">>> 2\n")
    if 0 != C.vs_sdmp_register_service(C.vs_sdmp_info_client(C.vs_info_impl())) {
        fmt.Errorf("can't register SDMP:INFO client service")
    }

fmt.Printf(">>> 3\n")
    var list [20]C.vs_sdmp_info_device_t
    var cnt C.size_t

fmt.Printf(">>> 4\n")
    if 0 != C.vs_sdmp_info_enum_devices(nil, &list[0], 20, &cnt, DEFAULT_TIMEOUT_MS) {
        fmt.Errorf("can't find SDMP:PRVS uninitialized devices")
    }

fmt.Printf(">>> 5\n")
    fmt.Printf("Found devices: %d\n\n\n", cnt)

	// first - read from run params,  second from SDMPD_SERVICE_PORT env, third - set default 8080
	listeningPort := readListeningPort(os.Args)

	devices = []DeviceInfo{
		{ID: "1", ManufactureID: "manuf 1", Version: "1.0.3", DeviceType: "df", MAC: "45:e2:86:a3:2a:84"},
		{ID: "3", ManufactureID: "manuf sn,anm", Version: "1.0.43mn", MAC: "90:e2:23:a3:231:99"},
	}

	http.HandleFunc("/ws/devices", func(w http.ResponseWriter, r *http.Request) {

		conn, err := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity
		if err != nil {
			fmt.Println(err)
			return
		}

		for t := range time.NewTicker(2 * time.Second).C {

			table := createStatusTable(t)
			if err = conn.WriteMessage(1, []byte(table)); err != nil {
				fmt.Println(err)
				return
			}
		}

	})

	http.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {

		if r.Method == "GET" {
			keys, ok := r.URL.Query()["key"]

			if ok {
				respBody, err := json.Marshal(keys)
				if err != nil {
					fmt.Println(err)
				}

				_, err = w.Write(respBody)
				if err != nil {
					fmt.Println("err writing resp  body: " + err.Error())
				}
				return
			}


			respBody, err := json.Marshal(devices)
			if err != nil {
				fmt.Println(err)
			}
			_, err = w.Write(respBody)
			if err != nil {
				fmt.Println("err writing resp  body: " + err.Error())
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

	fmt.Println(fmt.Sprintf("Service started. Web SDMPD interface located here: http://localhost:%d", listeningPort))

	err := http.ListenAndServe(fmt.Sprintf(":%d", listeningPort), nil)
	if err != nil {
		fmt.Println(err)
	}
}

func createStatusTable(t time.Time) string {
	table := "<tr> <td>ID</td> <td>ManufactureID</td> <td>DeviceType</td> <td>Version</td> <td>MAC</td> </tr>"
	for _, d := range devices {

		table += fmt.Sprintf("<tr> <td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> </tr>",
			d.ID,
			d.ManufactureID,
			d.DeviceType,
			d.Version,
			d.MAC,
		)
	}
	// some random data
	table += fmt.Sprintf("<tr> <td>%v</td> <td>%v</td> <td>%v</td> <td>%v</td> <td>%v</td> </tr>",
		t.String(),
		t.Nanosecond(),
		t.Minute(),
		"hello",
		t.Minute(),
	)
	return table
}

func readListeningPort(args []string) int {
	if len(args) > 2 {
		intPort, err := strconv.Atoi(os.Args[1])
		if err == nil {
			return intPort
		}
		fmt.Println("err reading port from args : " + err.Error())

	}
	port, ok := os.LookupEnv("SDMPD_SERVICE_PORT")
	if ok {
		intPort, err := strconv.Atoi(port)
		if err == nil {
			return intPort
		}
		fmt.Println("err reading port from env : " + err.Error())

	}
	return 8080
}


var HtmlPage = `

<table id='tbl' border=1></table>


<script>

    tbl = document.getElementById('tbl');

    var url = document.URL
    url = url.replace("http","ws")
    
    
    var table_output = document.getElementById("tbl");
    table_output.innerHTML = "<tr> <td>ID</td> <td>ManufactureID</td> <td>DeviceType</td> <td>Version</td> <td>MAC</td> </tr>"
  
    var device_table_socket = new WebSocket(url + "ws/devices");
   
    device_table_socket.onmessage = function (e) {
        table_output.innerHTML = e.data;
    };

   

</script>


`
