package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	SERVER_NAME    string
	SERVER_VERSION string
	LISTEN_ADDRESS string

	h bool
)

var gStat *Stat

type DemoHttp struct{}

func (*DemoHttp) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	defer req.Body.Close()

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	gStat.Add(len(body), 0)

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(body))
}

func init() {
	flag.StringVar(&SERVER_NAME, "name", "demohttp", "set the service name.")
	flag.StringVar(&SERVER_VERSION, "ver", "1", "set the service version.")
	flag.StringVar(&LISTEN_ADDRESS, "p", "127.0.0.1:8001", "set the service listen addr.")

	flag.BoolVar(&h, "h", false, "this help.")
}

func main() {

	flag.Parse()
	if h {
		flag.Usage()
		return
	}
	gStat = NewStat(5)
	gStat.Prefix(SERVER_NAME + SERVER_VERSION + " " + LISTEN_ADDRESS)

	err := http.ListenAndServe(LISTEN_ADDRESS, &DemoHttp{})
	if err != nil {
		log.Println(err.Error())
	}
}
