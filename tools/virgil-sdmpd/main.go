package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/hpcloud/tail"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("config file is not specified")
		return
	}
	confData, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panicError("error reading config file", err)
	}
	var conf Config
	err = json.Unmarshal(confData, &conf)
	if err != nil {
		panicError("error parsing config file", err)
	}
	dropDownDescriber := ""
	for i, f := range conf.LogFiles {
		dropDownDescriber += fmt.Sprintf(` <option value="%d">%s</option> `, i, f.Name)
	}
	http.HandleFunc("/log/", func(w http.ResponseWriter, r *http.Request) {

		conn, err := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity
		if err != nil {
			fmt.Println("can't upgrade connection %s to int")
			fmt.Println(err)
			return
		}

		id := strings.TrimPrefix(r.URL.Path, "/log/")

		i, err := strconv.Atoi(id)
		if err != nil {
			fmt.Println(fmt.Sprintf("can't convert %s to int", id))
			fmt.Println(err)
			return
		}
		ll, err := fileTail(conf.LogFiles[i%len(conf.LogFiles)].Path)
		if err != nil {
			fmt.Println(err)
			return
		}

		for s := range ll {
			if err = conn.WriteMessage(1, []byte(s.Text)); err != nil {
				return
			}
		}
	})

	template := strings.Replace(HtmlPage, "{{dd}}", dropDownDescriber, 4)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprint(w, template)
		if err != nil {
			fmt.Println(err)
		}
	})

	fmt.Println("Service started. Web log located here: http://localhost:8080")

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}

type Config struct {
	LogFiles []LogFile `json:"log_files"`
}
type LogFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func fileTail(filePath string) (chan *tail.Line, error) {
	t, err := tail.TailFile(filePath, tail.Config{
		Follow: true,
		ReOpen: true,
	})
	if err != nil {
		return nil, err
	}
	return t.Lines, nil
}

//
// panicError panics with an error.
//
func panicError(msg string, err error) {
	panic(fmt.Sprintf("%s: %+v", msg, err))
}

var HtmlPage = `
<div class="row1">
    <select id="upper_left_dropdown"
            style="float: left;height:4%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans, Serif;overflow:auto;"
            onchange="send1()"
    >
        {{dd}}
    </select>
    <select id="upper_right_dropdown"
            style="float: right;height:4%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans, Serif;overflow:auto;"
            onchange="send2()"
    >
        {{dd}}
    </select>

    <div id="upper_left_log" align="left"
         style="float: left;white-space: pre-wrap;height:45.5%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans, Serif;overflow:auto;">
    </div>

    <div id="upper_right_log" align="left"
         style="float: right;white-space: pre-wrap;height:45.5%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans, Serif;overflow:auto;"
    >
    </div>
</div>

<div class="row2">
    <select id="lower_left_dropdown"
            style="float: left;height:4%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans;overflow:auto;"
            onchange="send3()"
    >
        {{dd}}
    </select>
    <select id="lower_right_dropdown"
            style="float: right;height:4%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans;overflow:auto;"
            onchange="send4()"
    >
        {{dd}}
    </select>
    <div id="lower_left_log" align="left"
         style="float: left;white-space: pre-wrap;height:45.5%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans, Serif;overflow:auto;">
    </div>


    <div id="lower_right_log" align="left"
         style="float: right;white-space: pre-wrap;height:45.5%;width:49.5%;border:1px solid #ccc;font:16px/26px Open Sans, Serif;overflow:auto;"
    >
    </div>
</div>

<pre id="output"></pre>
<script>
    function updateScroll() {
        var element = document.getElementById("first_log");
        element.scrollTop = element.scrollHeight;
    }

    var max_log_size = 1000
    var url = document.URL
    url = url.replace("http","ws")
    
    
    var upper_left_output = document.getElementById("upper_left_log");
    upper_left_output.innerHTML = ""
    var upper_right_output = document.getElementById("upper_right_log");
    upper_right_output.innerHTML = ""
    var lower_left_output = document.getElementById("lower_left_log");
    lower_left_output.innerHTML = ""
    var lower_right_output = document.getElementById("lower_right_log");
    lower_right_output.innerHTML = ""

    var upper_left_socket = new WebSocket(url + "log/0");
    var upper_right_socket = new WebSocket(url + "log/1");
    var lower_left_socket = new WebSocket(url + "log/2");
    var lower_right_socket = new WebSocket(url + "log/3");

    upper_left_socket.onmessage = function (e) {
        while (upper_left_output.getElementsByTagName("a").length > max_log_size) {
            fl = upper_left_output.getElementsByTagName("a").item(0)
            fl.parentNode.removeChild(fl)
        }
        upper_left_output.innerHTML += "<a> " + e.data + "\n</a>";
    };

    upper_right_socket.onmessage = function (e) {
        while (upper_right_output.getElementsByTagName("a").length > max_log_size) {
            fl = upper_right_output.getElementsByTagName("a").item(0)
            fl.parentNode.removeChild(fl)
        }
        upper_right_output.innerHTML += "<a> " + e.data + "\n</a>";
    };

    lower_left_socket.onmessage = function (e) {
        while (lower_left_output.getElementsByTagName("a").length > max_log_size) {
            fl = lower_left_output.getElementsByTagName("a").item(0)
            fl.parentNode.removeChild(fl)
        }
        lower_left_output.innerHTML += "<a> " + e.data + "\n</a>";
    };

    lower_right_socket.onmessage = function (e) {
        while (lower_right_output.getElementsByTagName("a").length > max_log_size) {
            fl = lower_right_output.getElementsByTagName("a").item(0)
            fl.parentNode.removeChild(fl)
        }
        lower_right_output.innerHTML += "<a> " + e.data + "\n</a>";
    };

    dd1 = document.getElementById("upper_left_dropdown")
    dd2 = document.getElementById("upper_right_dropdown")
    dd2.selectedIndex = 1 % dd2.length
    dd3 = document.getElementById("lower_left_dropdown")
    dd3.selectedIndex = 2 % dd3.length
    dd4 = document.getElementById("lower_right_dropdown")
    dd4.selectedIndex = 3 % dd4.length


    function send1() {
        upper_left_output.innerHTML = ""
        upper_left_socket = new WebSocket(url + "log/" + dd1.selectedIndex);
        upper_left_socket.onmessage = function (e) {
            while (upper_left_output.getElementsByTagName("a").length > max_log_size) {
                fl = upper_left_output.getElementsByTagName("a").item(0)
                fl.parentNode.removeChild(fl)
            }
            upper_left_output.innerHTML += "<a> " + e.data + "\n</a>";
        };
    }

    function send2() {
        upper_right_output.innerHTML = ""
        upper_right_socket = new WebSocket(url + "log/" + dd2.selectedIndex);
        upper_right_socket.onmessage = function (e) {
            while (upper_right_output.getElementsByTagName("a").length > max_log_size) {
                fl = upper_right_output.getElementsByTagName("a").item(0)
                fl.parentNode.removeChild(fl)
            }
            upper_right_output.innerHTML += "<a> " + e.data + "\n</a>";
        };
    }

    function send3() {
        lower_left_output.innerHTML = ""
        lower_left_socket = new WebSocket(url + "log/" + dd3.selectedIndex);
        lower_left_socket.onmessage = function (e) {
            while (lower_left_output.getElementsByTagName("a").length > max_log_size) {
                fl = lower_left_output.getElementsByTagName("a").item(0)
                fl.parentNode.removeChild(fl)
            }
            lower_left_output.innerHTML += "<a> " + e.data + "\n</a>";
        };
    }

    function send4() {
        lower_right_output.innerHTML = ""
        lower_right_socket = new WebSocket(url + "log/" + dd4.selectedIndex);
        lower_right_socket.onmessage = function (e) {
            while (lower_right_output.getElementsByTagName("a").length > max_log_size) {
                fl = lower_right_output.getElementsByTagName("a").item(0)
                fl.parentNode.removeChild(fl)
            }
            lower_right_output.innerHTML += "<a> " + e.data + "\n</a>";
        };

    }

</script>


`
