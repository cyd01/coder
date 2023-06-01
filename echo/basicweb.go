package main

/*
go:generate go-bindata-assetfs wwwroot/get2fa.dev/...
*/
import (
	"bufio"
	"bytes"
	"context"

	//	"crypto/ecdsa"
	//	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	random "math/rand"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/cyd01/multihttp"
	//  assetfs "github.com/elazarl/go-bindata-assetfs"
)

var (
	acmeurl   = flag.String("acme", "", "directory URL of ACME server")
	command   = flag.String("cmd", "", "external command (/path1/=cmd1,...)")
	delay     = flag.Int("delay", 0, "delay (in seconds) before response")
	dir       = flag.String("dir", ".", "root directory")
	echo      = flag.Bool("echo", false, "start echo web server")
	follow    = flag.Bool("follow", false, "add a follow redirect (302) from /follow to /")
	nocache   = flag.Bool("nocache", false, "force not to cache")
	ssl       = flag.Bool("ssl", false, "active SSL with key.pem and cert.pem files")
	sslkey    = flag.String("sslkey", "key.pem", "SSL private key")
	sslcert   = flag.String("sslcert", "cert.pem", "SSL certificate")
	http3flag = flag.Bool("http3", false, "active HTTP/3 mode (over TCP)")
	http3udp  = flag.Bool("udp", false, "change UDP mode for HTTP/3")
	tls13     = flag.Bool("tls13", false, "force TLS 1.3")
	password  = flag.String("pass", "", "password for basic authentication (modification only)")
	port      = flag.String("port", "80", "port web server")
	status    = flag.Int("status", 0, "force return code")
	timeout   = flag.Int("timeout", 30, "timeout for external command")
	username  = flag.String("user", "", "username for basic authentication (modification only)")
	headers   = flag.String("headers", "", "add specific headers (header1=value1[,...])")
	typemime  = flag.String("mime", "", "add new type mime (coma separated extention:value list)")
	multi     = flag.Bool("multi", false, "start HTTP and HTTPS on same port")
)

var (
	name     = "basicweb"
	Version  = "undefined"
	hostname = ""
)

func init() {
	if h, err := os.Hostname(); err == nil {
		hostname = h
	}
}

func basicAuth(w http.ResponseWriter, r *http.Request) bool {
	if *username != "" && *password != "" {
		if user, pass, ok := r.BasicAuth(); !ok || user != *username || pass != *password {
			log.Println("Wrong credential")
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			returnCode(w, 401)
			return false
		}
	}
	return true
}
func setnocache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Expires", "0")
}
func returnCode(w http.ResponseWriter, code int) {
	w.WriteHeader(code)
	if code != 204 {
		w.Write([]byte(http.StatusText(code)))
	}
}
func fileHandler(w http.ResponseWriter, r *http.Request) {
	if *delay > 0 {
		time.Sleep(time.Duration(*delay*1000) * time.Millisecond)
	}

	var fullpath string
	if stat, err := os.Stat(*dir + "/" + r.Host); err == nil && stat.IsDir() {
		fullpath = *dir + "/" + r.Host
	} else {
		fullpath = *dir
	}
	log.Println("file", r.Proto, r.Method, r.URL.Path, "from", r.RemoteAddr)
	if *nocache {
		setnocache(w)
	}
	if (r.Method != "GET") && (r.Method != "HEAD") && (r.Method != "OPTIONS") {
		if !basicAuth(w, r) {
			return
		}
	}
	if len(*headers) > 0 {
		h := strings.Split(*headers, ",")
		for i := 0; i < len(h); i++ {
			hh := strings.Split(h[i], "=")
			w.Header().Set(strings.TrimSpace(hh[0]), strings.TrimSpace(hh[1]))
		}
	}
	// Light HSTS management
	//w.Header().Set("Strict-Transport-Security", "enabled=false; max-age=0; includeSubDomains")
	// Light CORS management
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "HEAD POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		}

	}
	if (*status == 204) || (*status == 304) { // no body for these codes
		w.WriteHeader(*status)
	} else if r.Method == "HEAD" { // no body for this method
		if *status > 0 {
			w.WriteHeader(*status)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	} else if *status != 0 { // We force return code
		if str := http.StatusText(*status); str != "" {
			w.WriteHeader(*status)
			if (*status == 301) || (*status == 302) || (*status == 303) {
				w.Header().Set("Location", "/")
			}
		} else {
			returnCode(w, http.StatusInternalServerError)
		}
	} else { // We serve files
		if r.Method == "OPTIONS" {
			return
		} else if (r.Method == "PUT") || (r.Method == "POST") { // Upload file
			if _, err := os.Stat(filepath.Dir(fullpath + r.URL.Path)); err != nil {
				if err := os.MkdirAll(filepath.Dir(fullpath+r.URL.Path), 0755); err != nil {
					returnCode(w, http.StatusInternalServerError)
					return
				}
			}
			if strings.HasSuffix(r.URL.Path, "/") {
				returnCode(w, http.StatusCreated)
				return
			}
			dst, err := os.Create(fullpath + r.URL.Path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer dst.Close()
			defer r.Body.Close()
			if _, err := io.Copy(dst, r.Body); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, ok := r.Header["Exec"]; ok {
				os.Chmod(fullpath+r.URL.Path, 0776)
			}
			returnCode(w, http.StatusCreated)
		} else if r.Method == "DELETE" { // Delete file
			if err := os.Remove(fullpath + r.URL.Path); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			returnCode(w, http.StatusNoContent)
		} else if (r.Method == "GET") || (r.Method == "HEAD") { // Download file or file info
			http.FileServer(http.Dir(fullpath)).ServeHTTP(w, r)
		} else {
			returnCode(w, http.StatusMethodNotAllowed)
		}
	}
}
func cmdHandler(cmm string, w http.ResponseWriter, r *http.Request) {
	log.Println("cmd", r.Proto, r.Method, r.URL.Path, "from", r.RemoteAddr)
	commands := strings.Split(cmm+" 2>&1", " ")
	cmd := exec.Command(commands[0], commands[1:]...)
	//r.ParseForm()
	cmd.Env = append(os.Environ(), "REQUEST_METHOD="+r.Method, "REQUEST_URI="+r.URL.Path, "SCRIPT_NAME="+r.URL.Path, "HTTP_HOST="+r.Host, "SERVER_PROTOCOL="+r.Proto, "REMOTE_ADDR="+r.RemoteAddr, "CONTENT_TYPE="+r.Header.Get("Content-type"), "CONTENT_LENGTH="+r.Header.Get("Content-length"), "QUERY_STRING="+r.URL.RawQuery)
	for key, val := range r.Header {
		cmd.Env = append(cmd.Env, "HTTP_"+strings.ReplaceAll(strings.ToUpper(key), "-", "_")+"="+val[0])
	}
	var err error
	stdinPipe, _ := cmd.StdinPipe()
	defer stdinPipe.Close()
	stdoutPipe, _ := cmd.StdoutPipe()
	defer stdoutPipe.Close()
	if err = cmd.Start(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	timer := time.AfterFunc(time.Duration(*timeout)*time.Second, func() { cmd.Process.Kill(); returnCode(w, http.StatusInternalServerError) })
	if l, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64); l > 0 {
		go func() { io.Copy(stdinPipe, r.Body); stdinPipe.Close() }()
	}
	reader := bufio.NewReader(stdoutPipe)
	setnocache(w)
	if len(*headers) > 0 {
		h := strings.Split(*headers, ",")
		for i := 0; i < len(h); i++ {
			hh := strings.Split(h[i], "=")
			w.Header().Set(strings.TrimSpace(hh[0]), strings.TrimSpace(hh[1]))
		}
	}
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Connection", "Close")
	rc := http.StatusOK
	for {
		var out string
		if out, err = reader.ReadString('\n'); err != nil {
			break
		}
		out = strings.TrimSpace(out)
		if (len(out) > 0) && strings.Contains(out, ":") {
			head := strings.SplitN(out, ":", 2)
			if strings.EqualFold(head[0], "Status") {
				if s, err := strconv.Atoi(strings.TrimSpace(head[1])); err == nil {
					rc = s
					log.Println("Status: " + strconv.Itoa(s))
				}
			}
			w.Header().Set(head[0], strings.TrimSpace(head[1]))
		} else if len(out) > 0 {
			w.Write([]byte(out))
			break
		} else {
			break
		}
	}
	w.WriteHeader(rc)
	for {
		var n int
		out := make([]byte, 512)
		n, err = io.ReadFull(reader, out)
		if n > 0 {
			w.Write(out[:n])
		}
		if err != nil {
			break
		}
	}
	cmd.Wait()
	timer.Stop()
}

type request struct {
	Proto            string      `json:"proto"`
	Path             string      `json:"path"`
	Method           string      `json:"method"`
	Host             string      `json:"host"`
	Headers          http.Header `json:"headers"`
	Trailers         http.Header `json:"trailers"`
	URL              *url.URL    `json:"url"`
	RemoteAddr       string      `json:"remoteaddr"`
	Body             []byte      `json:"body"`
	Server           string      `json:"server"`
	Close            bool        `json:"close"`
	ContentLength    int64       `json:"contentlength"`
	TransferEncoding []string    `json:"transferencoding"`
	RequestURI       string      `json:"requesturi"`
	Form             url.Values  `json:"form"`
	TLS              struct {
		Protocol string `json:"protocol,omitempty"`
		Version  string `json:"version,omitempty"`
		Cipher   string `json:"cipher,omitempty"`
	} `json:"TLS,omitempty"`
}

func echoHandler(rw http.ResponseWriter, r *http.Request) {
	var err error
	// Preparing response structure
	rr := &request{}
	rr.Proto = r.Proto
	rr.Method = r.Method
	rr.Host = r.Host
	rr.Headers = r.Header
	rr.Trailers = r.Trailer
	rr.URL = r.URL
	rr.RemoteAddr = r.RemoteAddr
	rr.Path = r.URL.String()
	rr.Close = r.Close
	rr.ContentLength = r.ContentLength
	rr.TransferEncoding = r.TransferEncoding
	rr.RequestURI = r.RequestURI
	if r.TLS != nil {
		rr.TLS.Protocol = r.TLS.NegotiatedProtocol
		switch r.TLS.Version {
		case tls.VersionTLS10:
			rr.TLS.Version = "TLSv1.0"
		case tls.VersionTLS11:
			rr.TLS.Version = "TLSv1.1"
		case tls.VersionTLS12:
			rr.TLS.Version = "TLSv1.2"
		case tls.VersionTLS13:
			rr.TLS.Version = "TLSv1.3"
		}
		rr.TLS.Cipher = strconv.Itoa(int(r.TLS.CipherSuite))
	}
	r.ParseForm()
	rr.Form = r.Form

	log.Println("echo", r.Proto, r.Method, r.URL.Path, "from", r.RemoteAddr)

	if *delay > 0 {
		time.Sleep(time.Duration(*delay*1000) * time.Millisecond)
	}

	// Reading the request body
	defer r.Body.Close()
	rr.Body, err = io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set server name
	rr.Server = "name"
	if len(Version) > 0 {
		rr.Server = rr.Server + " " + Version
	} else {
		rr.Server = rr.Server + " undefined"
	}
	if len(hostname) > 0 {
		rr.Server = rr.Server + " on " + hostname
	}

	// Preparing the response headers
	rw.Header().Set("X-Hostname", hostname)
	if len(*headers) > 0 {
		h := strings.Split(*headers, ",")
		for i := 0; i < len(h); i++ {
			hh := strings.Split(h[i], "=")
			rw.Header().Set(strings.TrimSpace(hh[0]), strings.TrimSpace(hh[1]))
		}
	}
	// Light HSTS management
	//rw.Header().Set("Strict-Transport-Security", "enabled=false; max-age=0; includeSubDomains")
	// Light CORS management
	if origin := r.Header.Get("Origin"); origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		if r.Method == "OPTIONS" {
			rw.Header().Set("Access-Control-Allow-Credentials", "true")
			rw.Header().Set("Access-Control-Allow-Methods", "HEAD POST, GET, OPTIONS, PUT, DELETE")
			rw.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		}

	}

	// Preparing cache
	if *nocache {
		setnocache(rw)
	}

	if (*status == 204) || (*status == 304) { // no body for these codes
		rw.WriteHeader(*status)
	} else if r.Method == "HEAD" { // no body for this method
		rw.Header().Set("Content-Type", "application/json")
		if *status > 0 {
			rw.WriteHeader(*status)
		} else {
			rw.WriteHeader(http.StatusOK)
		}
	} else if *status < 0 { // Send the request in text mode
		rw.Header().Set("Content-Type", "text/plain")
		if *status < -1 { // Send the request headers
			rw.Write([]byte(rr.Method + " " + rr.Path + "\n"))
			if len(rr.Headers) > 0 {
				for n, v := range rr.Headers {
					rw.Write([]byte(n + ": " + strings.Join(v, ",") + "\n"))
				}
			}
			rw.Write([]byte("\n")) // Send the body
		}
		rw.Write(rr.Body)
	} else { // Send the request in json mode
		rrb, err := json.Marshal(rr)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		if *status > 0 {
			rw.WriteHeader(*status)
		} else {
			if sc, err := strconv.Atoi(r.URL.Path[1:]); err == nil {
				if txt := http.StatusText(sc); len(txt) > 0 {
					rw.WriteHeader(sc)
				}
			}
		}
		rw.Write(rrb)
	}
}
func connStateHook(c net.Conn, state http.ConnState) {
	if state == http.StateActive {
		if cc, ok := c.(*tls.Conn); ok {
			st := cc.ConnectionState()
			version := "unknown"
			switch st.Version {
			case tls.VersionSSL30:
				version = "SSL30"
			case tls.VersionTLS10:
				version = "TLS10"
			case tls.VersionTLS11:
				version = "TLS11"
			case tls.VersionTLS12:
				version = "TLS12"
			case tls.VersionTLS13:
				version = "TLS13"
			}
			cipher := "unknown"
			CipherSuite := st.CipherSuite
			for _, cs := range tls.CipherSuites() {
				if (*cs).ID == CipherSuite {
					cipher = (*cs).Name
				}
			}
			log.Println("TLSVersion:", version, ", Protocol:", st.NegotiatedProtocol, ", Cipher:", cipher, ", Resume:", st.DidResume)
		}
	}
}
func inittlsconfig() *tls.Config {
	TLSMinVersion := uint16(tls.VersionTLS12)
	if *tls13 {
		TLSMinVersion = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion:               TLSMinVersion,
		MaxVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos:             []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
	}
}
func initquicconfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 30 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	}
}
func initserver(port string) *http.Server {
	return &http.Server{
		Addr:              port,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		ConnState:         connStateHook,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}
func Exists(name string) bool {
	_, err := os.Stat(name)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}
func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(1)
	}
	if !strings.Contains(*port, ":") {
		*port = ":" + *port
	}
	if *ssl {
		log.Println("☢ Starting secure web server")
	} else {
		log.Println("☢ Starting web server")
	}
	log.Println("on " + *port + " with directory " + *dir + " with status response " + strconv.Itoa(*status))
	if (len(*acmeurl) == 0) && (*ssl || *http3flag) && (!Exists(*sslkey) || !Exists(*sslcert)) {
		priv, _ := rsa.GenerateKey(rand.Reader, 4096)
		template := x509.Certificate{
			SerialNumber: big.NewInt(random.Int63n(65536)),
			Subject: pkix.Name{
				Organization: []string{"Acme Co"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * 3650),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		log.Println("Generating self signed certificate with rsa key")
		out := &bytes.Buffer{}
		pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		os.WriteFile("cert.pem", out.Bytes(), 0400)
		out.Reset()
		pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		os.WriteFile("key.pem", out.Bytes(), 0600)
	}
	fullpath, _ := filepath.Abs(*dir)
	os.Setenv("ROOTDIR", fullpath)

	mux := http.DefaultServeMux

	commands := strings.Split(*command, ",")
	for _, def := range commands {
		cmd := strings.Split(def, "=")
		path := cmd[0]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		} // if( !strings.HasSuffix(path,"/") ) { path = path+"/" }
		if (len(path) > 1) && (len(cmd[1]) > 0) {
			log.Println("Add dynamic command <" + cmd[1] + "> to " + path + " path")
			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) { cmdHandler(cmd[1], w, r) })
		}
	}
	if *follow {
		log.Println("Add /follow handler for 302 redirect")
		mux.HandleFunc("/follow", func(w http.ResponseWriter, r *http.Request) {
			log.Println(r.Method, r.URL.Path)
			w.Header().Add("Location", "/")
			w.WriteHeader(302)
		})
	}
	if *echo {
		mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			log.Println(r.Method, r.URL.Path)
			w.Write([]byte("pong"))
		})
		mux.Handle("/", http.HandlerFunc(echoHandler))
	} else {
		mux.Handle("/", http.HandlerFunc(fileHandler))
	}
	if len(*typemime) > 0 {
		for _, v := range strings.Split(*typemime, ",") {
			if strings.Contains(v, ":") {
				ext := strings.Split(v, ":")[0]
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				val := strings.Join(strings.Split(v, ":")[1:], ":")
				log.Println("Add mime type", val, "for", ext)
				mime.AddExtensionType(ext, val)
			}
		}
	}
	//mux.Handle("/",http.FileServer(&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo, Prefix: "wwwroot/get2fa.dev"}))
	var server *http.Server = nil
	go func() {
		if *http3flag { // beware: does not work with 127.0.0.1, use localhost
			log.Println("Start HTTP/3 SSL server")
			log.Println("with private key:" + *sslkey + " and certificate:" + *sslcert)
			if *http3udp {
				quicConf := initquicconfig()
				server := http3.Server{
					Handler:    mux,
					Addr:       *port,
					QuicConfig: quicConf,
				}
				log.Println("with UDP")
				err := server.ListenAndServeTLS(*sslcert, *sslkey)
				if err != nil {
					if err != http.ErrServerClosed {
						log.Println(err)
						os.Exit(1)
					}
				}

			} else { // sudo sysctl -w net.core.rmem_max=2500000
				err := http3.ListenAndServe(*port, *sslcert, *sslkey, mux) /* en mode TCP */
				if err != nil {
					if err != http.ErrServerClosed {
						log.Println(err)
						os.Exit(1)
					}
				}
			}

		} else if *ssl {
			server = initserver(*port)
			if len(*acmeurl) > 0 {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				//priv,_ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				m := &autocert.Manager{
					Cache:      autocert.DirCache("secret-dir"),
					Prompt:     autocert.AcceptTOS,
					Email:      "nobody@nowhere.org",
					HostPolicy: nil,
					//HostPolicy: autocert.HostWhitelist("example.org", "www.example.org"),
					Client: &acme.Client{DirectoryURL: *acmeurl, Key: priv},
				}
				server.TLSConfig = m.TLSConfig()
				server.TLSConfig.MinVersion = tls.VersionTLS13
				server.TLSConfig.MaxVersion = tls.VersionTLS13
			} else {
				server.TLSConfig = inittlsconfig()
			}
			server.Handler = mux
			http2.ConfigureServer(server, &http2.Server{})
			log.Println("Start HTTP/2, HTTP/1 SSL server")
			var err error
			if len(*acmeurl) > 0 {
				log.Println("against ACME web server " + *acmeurl)
				err = server.ListenAndServeTLS("", "")
			} else {
				log.Println("with private key:" + *sslkey + " and certificate:" + *sslcert)
				err = server.ListenAndServeTLS(*sslcert, *sslkey)
			}
			if err != nil {
				if err != http.ErrServerClosed {
					log.Println(err)
					os.Exit(1)
				}
			}
		} else if *multi {
			srv := &multihttp.Server{Addr: *port}
			log.Println("Start HTTP+HTTPS server on same port")
			err := srv.MultiListenAndServe(mux, *sslcert, *sslkey)
			if err != nil {
				if err != http.ErrServerClosed {
					log.Println(err)
					os.Exit(1)
				}
			}

		} else {
			h2s := http2.Server{NewWriteScheduler: func() http2.WriteScheduler {
				return http2.NewPriorityWriteScheduler(&http2.PriorityWriteSchedulerConfig{})
			}}
			server = initserver(*port)
			server.Handler = h2c.NewHandler(mux, &h2s)
			log.Println("Start HTTP/1.1 (+ HTTP/2 with h2c) server")
			err := server.ListenAndServe()
			if err != nil {
				if err != http.ErrServerClosed {
					log.Println(err)
					os.Exit(1)
				}
			}
		}
	}()
	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			log.Fatal("Server forced to shutdown:", err)
		}
	}
	log.Println("Server exiting")
}
