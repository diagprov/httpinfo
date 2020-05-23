package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

var (
	LogInfo  *log.Logger
	LogWarn  *log.Logger
	LogError *log.Logger
)

func getUserAgent(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<p>Browser User Agent: %s</p>", r.Header.Get("User-Agent"))
}

func getIP(w http.ResponseWriter, req *http.Request) {

	ip, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		fmt.Fprintf(w, "<p>userip: %q is not IP:port</p>", req.RemoteAddr)
	}

	userIP := net.ParseIP(ip)
	if userIP == nil {
		fmt.Fprintf(w, "userip: %q is not IP:port</p>", req.RemoteAddr)
		return
	}

	forward := req.Header.Get("X-Forwarded-For")
	fmt.Fprintf(w, "<p>IP: %s</p>", ip)
	fmt.Fprintf(w, "<p>Port: %s</p>", port)
	fmt.Fprintf(w, "<p>Forwarded for: %s</p>", forward)
}

func getHeaders(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "\r\n<pre>\r\n")
	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v=%v", name, h)
			fmt.Fprintf(w, "\r\n")
		}
	}
	fmt.Fprintf(w, "</pre>")
}

func writeHeader(w http.ResponseWriter, title string) {
	fmt.Fprintf(w, "<html><head><Title>%s</title><style>body { font-family: Helvetica,Arial; }</style></head>", title)
	fmt.Fprintf(w, "<body>")
	fmt.Fprintf(w, "<h1>%s</h1>", title)
}

func writeFooter(w http.ResponseWriter) {
	fmt.Fprintf(w, "</body></html>")
	fmt.Fprintf(w, "\n\n")
}

func HttpUA(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Request for user agent.")
	writeHeader(w, "Http: User Agent")
	getUserAgent(w, r)
	writeFooter(w)
}

func HttpHeaders(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Request for headers.")

	writeHeader(w, "Http: Headers")
	getHeaders(w, r)
	writeFooter(w)
}

func HttpSummary(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving default request")
	writeHeader(w, "Http: Summary")
	getIP(w, r)
	getUserAgent(w, r)
	getHeaders(w, r)
	writeFooter(w)
}

func main() {

	LogInfo = log.New(os.Stderr, "[INFO] ", log.Ldate|log.Ltime)
	LogWarn = log.New(os.Stderr, "[WARN] ", log.Ldate|log.Ltime)
	LogError = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime)

	mux := http.NewServeMux()
	mux.HandleFunc("/ua", HttpUA)
	mux.HandleFunc("/h", HttpHeaders)
	mux.HandleFunc("/", HttpSummary)
	LogInfo.Println("Starting Up")
	err := http.ListenAndServe(":9119", mux)
	if err != nil {
		LogError.Fatalln(err)
		return
	}
	LogInfo.Println("Exiting Application")
}
