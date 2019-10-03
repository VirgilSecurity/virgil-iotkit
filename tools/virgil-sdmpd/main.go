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

	"./sdmp"
	"./devices"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

var devicesInfo *devices.ConcurrentDevices

func GeneralInfoCb(generalInfo devices.DeviceInfo) error {
    return devicesInfo.UpdateDevice(generalInfo)
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
	// first - read from run params,  second from SDMPD_SERVICE_PORT env, third - set default 8080
	listeningPort := readListeningPort(os.Args)

	devicesInfo = devices.NewDevices()

	// Start SDMP:INFO communication
	err :=  sdmp.ConnectToDeviceNetwork()
	if err != nil {
    	fmt.Println(err)
    	return
    }

    err = sdmp.SetupPolling(GeneralInfoCb)
    if err != nil {
        fmt.Println(err)
        return
    }

    CleanupProcessStart()

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
				respBody, err := json.Marshal(devicesInfo.Items[keys[0]])
				if err != nil {
					fmt.Println(err)
				}

				_, err = w.Write(respBody)
				if err != nil {
					fmt.Println("err writing resp  body: " + err.Error())
				}
				return
			}


			respBody, err := json.Marshal(devicesInfo.Items)
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

	err = http.ListenAndServe(fmt.Sprintf(":%d", listeningPort), nil)
	if err != nil {
		fmt.Println(err)
	}
}

func createStatusTable(t time.Time) string {
	table := "<tr> <td>ID</td>  <td>MAC</td> <td>ManufactureID</td> <td>DeviceType</td> <td>Version</td></tr>"

    // Sorted keys
    keys := make([]string, 0, len(devicesInfo.Items))
    for k := range devicesInfo.Items {
	    keys = append(keys, k)
    }
    sort.Strings(keys)

	for _, k := range keys {
        d := devicesInfo.Items[k]
		table += fmt.Sprintf("<tr> <td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> <td>%s</td> </tr>",
			d.ID,
			d.MAC,
			d.ManufactureID,
			d.DeviceType,
			d.Version,
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
<p id="date"></p>

<script>

    tbl = document.getElementById('tbl');

    var url = document.URL
    url = url.replace("http","ws")
    
    
    var table_output = document.getElementById("tbl");
    table_output.innerHTML = "<tr> <td>ID</td> <td>MAC</td> <td>ManufactureID</td> <td>DeviceType</td> <td>Version</td> <td>MAC</td> </tr>"

    var device_table_socket = new WebSocket(url + "ws/devices");
   
    device_table_socket.onmessage = function (e) {
        table_output.innerHTML = e.data;
        document.getElementById("date").innerHTML = Date();
    };

</script>
`
