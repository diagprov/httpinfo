package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/mileusna/useragent"
)

var (
	LogInfo  *log.Logger
	LogWarn  *log.Logger
	LogError *log.Logger
)

func writeLinks(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<nav><ul>")
	fmt.Fprintf(w, "<li><a href=\"/ip\">IP Address</a></li>")
	fmt.Fprintf(w, "<li><a href=\"/tls\">TLS Connection Information</a></li>")
	fmt.Fprintf(w, "<li><a href=\"/proto\">HTTP Protocol Information</a></li>")
	fmt.Fprintf(w, "<li><a href=\"/h\">HTTP Headers</a></li>")
	fmt.Fprintf(w, "<li><a href=\"/ua\">User Agent</a></li>")
	fmt.Fprintf(w, "</ul></nav>")
}

func getUserAgent(w http.ResponseWriter, r *http.Request) {
	uastr := r.Header.Get("User-Agent")
	fmt.Fprintf(w, "<pre>Browser User Agent: %s</pre>", uastr)

	ua := useragent.Parse(uastr)

	devtype := ""
	if ua.Mobile {
		devtype = devtype + "Mobile;"
	}
	if ua.Desktop {
		devtype = devtype + "Desktop;"
	}
	if ua.Tablet {
		devtype = devtype + "Tablet;"
	}
	if ua.Bot {
		devtype = devtype + "Bot;"
	}

	fmt.Fprintf(w, "<pre>")
	fmt.Fprintf(w, "Browser: %s\n", ua.Name)
	fmt.Fprintf(w, "Browser: %s\n", ua.Version)
	fmt.Fprintf(w, "OS Name: %s\n", ua.OS)
	fmt.Fprintf(w, "OS Version: %s\n", ua.OSVersion)
	fmt.Fprintf(w, "Device: %s\n", ua.Device)
	fmt.Fprintf(w, "Agent Type: %s\n", devtype)
	fmt.Fprintf(w, "URL: %s\n", ua.URL)

	fmt.Fprintf(w, "</pre>")
}

func getHttpConnInfo(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "<pre>\n")
	fmt.Fprintf(w, "HTTP Protocol Version: %v.%v\n", req.ProtoMajor, req.ProtoMinor)
	fmt.Fprintf(w, "</pre>\n")
}

func getTls(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "<pre>\n")
	tlsconn := req.TLS
	if tlsconn != nil {
		fmt.Fprintf(w, "TLS: Yes\n")

		var tlsver string
		switch tlsconn.Version {
		case tls.VersionTLS10:
			tlsver = "TLS 1.0"
		case tls.VersionTLS11:
			tlsver = "TLS 1.1"
		case tls.VersionTLS12:
			tlsver = "TLS 1.2"
		case tls.VersionTLS13:
			tlsver = "TLS 1.3"
		case tls.VersionSSL30:
			tlsver = "SSL 3.0"
		default:
			tlsver = "Unknown"
		}
		tlsresume := "No"
		if tlsconn.DidResume {
			tlsresume = "Yes"
		}
		fmt.Fprintf(w, "TLS Version: %s\n", tlsver)
		fmt.Fprintf(w, "TLS Ciphersuite: %d\n", tlsconn.CipherSuite)
		fmt.Fprintf(w, "TLS SNI: %s\n", tlsconn.ServerName)
		fmt.Fprintf(w, "TLS ALPN: %s\n", tlsconn.NegotiatedProtocol)
		fmt.Fprintf(w, "TLS Resumption: %s\n", tlsresume)

		if tlsconn.PeerCertificates != nil {
			for _, p := range tlsconn.PeerCertificates {
				fmt.Fprintf(w, "Peer Certificate: %s", p.Subject.String())
			}
		}
	} else {
		fmt.Fprintf(w, "TLS: No\n")
	}

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
	LogInfo.Println("Serving Request for IP.")
	writeHeader(w, "HTTP: IP Address")
	getIP(w, r)
	writeFooter(w)
}

func HttpProtoInfo(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Request for Protocol Info.")
	writeHeader(w, "HTTP: Protocol Information")
	getHttpConnInfo(w, r)
	writeFooter(w)
}

func HttpUA(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Request for user agent.")
	writeHeader(w, "HTTP: User Agent")
	getUserAgent(w, r)
	writeFooter(w)
}

func HttpHeaders(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Request for headers.")

	writeHeader(w, "HTTP: Headers")
	getHeaders(w, r)
	writeFooter(w)
}

func HttpSummary(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving Summary request")
	writeHeader(w, "HTTP: Summary")
	writeLinks(w, r)
	getIP(w, r)
	getTls(w, r)
	getHttpConnInfo(w, r)
	getUserAgent(w, r)
	getHeaders(w, r)
	writeFooter(w)
}

func TlsSummary(w http.ResponseWriter, r *http.Request) {
	LogInfo.Println("Serving TLS request")
	writeHeader(w, "TLS: Summary")
	getTls(w, r)
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
	router.HandleFunc("/tls", TlsSummary)
	router.HandleFunc("/", HttpSummary)

	cert, err := tls.LoadX509KeyPair("cert.pem", "private.key")
	if err != nil {
		log.Println(err)
		return
	}

	tlsconfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS10,
		MaxVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	servercleartext := &http.Server{
		Addr:    ":9119",
		Handler: router,
	}

	servertls := &http.Server{
		Addr:      ":9120",
		TLSConfig: tlsconfig,
		//TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
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

		servercleartext.SetKeepAlivesEnabled(false)
		if err := servercleartext.Shutdown(ctx); err != nil {
			LogWarn.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		servertls.SetKeepAlivesEnabled(false)
		if err := servertls.Shutdown(ctx); err != nil {
			LogWarn.Fatalf("Could not gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	go func() {
		LogInfo.Println("Starting Up HTTPS")
		if err := servertls.ListenAndServeTLS("cert.pem", "private.key"); err != nil && err != http.ErrServerClosed {
			LogError.Fatalln(err)
			return
		}
	}()
	go func() {
		LogInfo.Println("Starting Up HTTP")
		if err := servercleartext.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			LogError.Fatalln(err)
			return
		}
	}()

	<-done
	LogInfo.Println("Exiting Application")
}
