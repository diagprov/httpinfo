package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var (
	LogInfo  *log.Logger
	LogWarn  *log.Logger
	LogError *log.Logger
)

func getUserAgent(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<pre>Browser User Agent: %s</pre>", r.Header.Get("User-Agent"))
}

func getHttpConnInfo(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "<pre>\n")
	fmt.Fprintf(w, "HTTP Protocol Version: %v.%v\n", req.ProtoMajor, req.ProtoMinor)
	fmt.Fprintf(w, "</pre>\n")
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
	fmt.Fprintf(w, "<pre>\n")
	fmt.Fprintf(w, "IP: %s\n", ip)
	fmt.Fprintf(w, "Port: %s\n", port)
	fmt.Fprintf(w, "Forwarded for: %s\n", forward)
	fmt.Fprintf(w, "</pre>\n")
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

func HttpIP(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Request for user agent.")
	writeHeader(w, "Http: IP Address")
	getIP(w, r)
	writeFooter(w)
}

func HttpProtoInfo(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Request for user agent.")
	writeHeader(w, "Http: Protocol Information")
	getHttpConnInfo(w, r)
	writeFooter(w)
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
	getHttpConnInfo(w, r)
	getUserAgent(w, r)
	getHeaders(w, r)
	writeFooter(w)
}

func main() {

	LogInfo = log.New(os.Stderr, "[INFO] ", log.Ldate|log.Ltime)
	LogWarn = log.New(os.Stderr, "[WARN] ", log.Ldate|log.Ltime)
	LogError = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime)

	router := http.NewServeMux()
	router.HandleFunc("/ua", HttpUA)
	router.HandleFunc("/h", HttpHeaders)
	router.HandleFunc("/ip", HttpIP)
	router.HandleFunc("/proto", HttpProtoInfo)
	router.HandleFunc("/", HttpSummary)

	server := &http.Server{
		Addr:    ":9119",
		Handler: router,
	}

	servertls := &http.Server{
		Addr:    ":9120",
		Handler: router,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		LogInfo.Println("Server is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			LogWarn.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	LogInfo.Println("Starting Up")
	if err := servertls.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		LogError.Fatalln(err)
		return
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		LogError.Fatalln(err)
		return
	}
	LogInfo.Println("Exiting Application")
}
