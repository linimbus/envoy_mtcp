package main

import (
	"bytes"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	SERVER_URL   string
	SERVER_ADD   string
	HEADER       string
	PARALLEL_NUM int
	RUNTIME      int
	BODY_LENGTH  int
	LIMITE_RATE  int
	h            bool
)

type Header struct {
	key   string
	value string
}

func init() {
	flag.IntVar(&LIMITE_RATE, "limit", 0, "limit number per second to send every goroutine. as[0,1000].")
	flag.IntVar(&PARALLEL_NUM, "par", 10, "the parallel numbers to request.")
	flag.IntVar(&RUNTIME, "runtime", 120, "total run time.")
	flag.IntVar(&BODY_LENGTH, "body", 128, "transport body length.")
	flag.StringVar(&SERVER_ADD, "addr", "127.0.0.1:8001", "set the service address.")
	flag.StringVar(&SERVER_URL, "url", "/", "set request url. as[/abc/123]")
	flag.StringVar(&HEADER, "head", "", "set request head. as[key1=value1,key2=value2]")
	flag.BoolVar(&h, "h", false, "this help.")
}

var gStat *Stat
var gBody []byte

func newTransport() http.RoundTripper {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConnsPerHost:   10,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func NewHttpClient() *http.Client {
	return &http.Client{
		Transport: newTransport(),
		Timeout:   10 * time.Second,
	}
}

func HttpBenchMark(addr string, url string, header []Header, runtime int) {

	var stop bool
	var wait sync.WaitGroup
	wait.Add(PARALLEL_NUM)

	gStat = NewStat(5)
	gStat.Prefix(os.Args[0])

	path := "http://" + addr + url
	for i := 0; i < PARALLEL_NUM; i++ {
		go func() {
			defer wait.Done()
			client := NewHttpClient()
			for {
				timestamp, err := HttpRequest(client, path, header, gBody)
				if err != nil {
					log.Println(err.Error())
					time.Sleep(5 * time.Second)
					continue
				}
				gStat.Add(len(gBody), uint64(timestamp))
				if stop {
					break
				}
				if LIMITE_RATE != 0 && LIMITE_RATE < 1000 {
					time.Sleep(time.Second / time.Duration(LIMITE_RATE))
				}
			}
		}()
	}
	time.Sleep(time.Duration(runtime) * time.Second)
	stop = true
	wait.Wait()

	gStat.Delete()
}

func HttpRequest(client *http.Client, path string, header []Header, body []byte) (time.Duration, error) {

	request, err := http.NewRequest("GET", path, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}

	for _, v := range header {
		request.Header.Add(v.key, v.value)
	}

	tmBefore := time.Now()

	rsp, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		return 0, errors.New("response " + rsp.Status)
	}

	body, err = ioutil.ReadAll(rsp.Body)
	if err != nil {
		return 0, err
	}

	tmAfter := time.Now()

	return tmAfter.Sub(tmBefore), nil
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()
	if h {
		flag.Usage()
		return
	}
	log.Printf("Request : http://%s%s \r\n", SERVER_ADD, SERVER_URL)
	log.Printf("BodyLen : %d\r\n", BODY_LENGTH)
	log.Printf("PARAL   : %d\r\n", PARALLEL_NUM)

	header := make([]Header, 0)
	if HEADER != "" {
		list := strings.Split(HEADER, ",")
		for _, v := range list {
			keyvalue := strings.Split(v, "=")
			if len(keyvalue) == 2 {
				header = append(header, Header{key: keyvalue[0], value: keyvalue[1]})
			}
		}
	}
	for _, v := range header {
		log.Printf("Header  : [%s:%s] \r\n", v.key, v.value)
	}

	body := make([]byte, 0)
	for i := 0; i < BODY_LENGTH; i++ {
		body = append(body, byte('A'))
	}
	gBody = body

	log.Println("Http Benchmark Start!")
	HttpBenchMark(SERVER_ADD, SERVER_URL, header, RUNTIME)
	log.Println("Http Benchmark Stop!")
}
