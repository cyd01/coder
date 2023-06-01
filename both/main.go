package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

/**
 **      Parameters Definition
 **/
var (
	addr    = flag.String("addr", ":8080", "Listening address")
	def     = flag.String("default", "127.0.0.1:80", "Default target")
	https   = flag.String("https", "", "HTTPS target")
	targets = flag.String("targets", "", "Coma separated list of targets: X-Y-Z:Host:Port[,...]")
)

/**
 **      Protocol Definition
 **/
const (
	nbBytes int = 3
)

type Protocol struct {
	Header  []byte
	Address string
}
type Protocols []Protocol

func (p *Protocols) Match(head []byte) string {
	address := ""
	if len(*p) > 0 {
		for _, v := range *p {
			if bytes.Compare(head, v.Header) == 0 {
				address = v.Address
			}
		}
	}
	return address
}
func (p *Protocols) Add(bytes, host, port string) {
	v := Protocol{}
	if len(bytes) == nbBytes {
		for _, ch := range bytes {
			v.Header = append(v.Header, byte(ch))
		}
	} else {
		b := strings.Split(bytes, "-")
		if len(b) == nbBytes {
			for i := 0; i < nbBytes; i++ {
				if j, err := strconv.Atoi(strings.TrimSpace(b[i])); err != nil {
					v.Header = append(v.Header, []byte(b[i])[0])
				} else {
					v.Header = append(v.Header, byte(j))
				}
			}
		}
	}
	v.Address = strings.TrimSpace(host) + ":" + strings.TrimSpace(port)
	*p = append(*p, v)
}
func (p *Protocols) AddOne(bytes, target string) {
	t := strings.Split(target, ":")
	p.Add(bytes, t[0], t[1])
}
func (p *Protocols) Print() {
	for _, v := range *p {
		fmt.Println(v.Header, " => ", v.Address)
	}
}

var protocols Protocols

/**
 **      Shovel Definition
 **/
// copy between pipes, sending errors to channel
func chanCopy(e chan error, dst, src io.ReadWriter) {
	_, err := io.Copy(dst, src)
	e <- err
}

// proxy between two sockets
func Shovel(local, remote io.ReadWriteCloser) error {
	errch := make(chan error, 1)
	go chanCopy(errch, local, remote)
	go chanCopy(errch, remote, local)
	for i := 0; i < 2; i++ {
		if err := <-errch; err != nil {
			// If this returns early the second func will push into the
			// buffer, and the GC will clean up
			return err
		}
	}
	return nil
}

func raw(b []byte) string {
	st := "["
	if len(b) > 0 {
		for _, c := range b {
			if (c >= 32) && (c <= 126) {
				st = st + string(c)
			} else {
				st = st + "?"
			}
		}
	}
	return st + "]"
}

/**
 **      Main procedure
 **/
func main() {
	flag.Parse()
	server, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to start listener on", *addr, ":", err)
		os.Exit(1)
	}
	fmt.Println("Default target is", *def)

	if len(*targets) > 0 {
		t := strings.Split(strings.TrimSpace(*targets), ",")
		for _, p := range t {
			b := strings.Split(strings.TrimSpace(p), ":")
			if len(b) == 3 {
				protocols.Add(b[0], b[1], b[2])
			}
		}
	}
	if len(*https) > 0 {
		protocols.AddOne("22-3-1", *https) // HTTPS
	}
	//protocols.Add("S-S-H", "test", "22")    //SSH

	if len(protocols) > 0 {
		fmt.Println("Protocols definitions:")
		protocols.Print()
	}

	fmt.Println("Start listener on", *addr)
	for {
		conn, err := server.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to accept connection:", err)
			os.Exit(1)
		}
		go func() {
			defer func() {
				conn.Close()
			}()
			header := make([]byte, nbBytes)
			if _, err := io.ReadAtLeast(conn, header, nbBytes); err != nil {
				fmt.Fprintln(os.Stderr, "Unable to read first digit:", err)
				return
			}
			address := protocols.Match(header)
			if len(address) > 0 {
				fmt.Println("Found", header, "=>", address)
			} else {
				address = *def
				fmt.Println("Default", header, "=>", address)
			}
			// connect to remote
			remote, err := net.Dial("tcp", address)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to join target", address, ":", err)
				return
			}
			fmt.Println("Successfully connect to target", address)
			defer func() {
				remote.Close()
			}()
			remote.Write(header)
			// proxy between us and remote server
			if err := Shovel(conn, remote); err != nil {
				fmt.Fprintln(os.Stderr, "Unable to proxy:", err)
			}
			fmt.Println("End of connection")
		}()
	}
}
