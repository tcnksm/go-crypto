package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
)

func main() {
	certFile, _ := filepath.Abs("../certificate/x509/certs/server.pem")
	keyFile, _ := filepath.Abs("../certificate/x509/certs/server-key.pem")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("Err: %s\n", err)
		return
	}

	config := tls.Config{
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", "localhost:443", &config)
	if err != nil {
		log.Printf("Err: %s\n", err)
		return
	}
	log.Println("[INFO] Server listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("Err: %s\n", err)
			return
		}
		log.Printf("[INFO] Request from %s", conn.RemoteAddr())

		go func(c net.Conn) {
			defer c.Close()

			tlsconn, ok := c.(*tls.Conn)
			if !ok {
				log.Printf("[ERROR] Connection should be TLS")
				return
			}

			buf := make([]byte, 1024)
			n, err := tlsconn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[ERROR] Read: %s", err)
					return
				}
			}
			log.Printf("[INFO] Message from client (%d byte): %s", n, string(buf[:n]))

			state := tlsconn.ConnectionState()
			log.Printf("[INFO] Handshake complete: %v", state.HandshakeComplete)

			if _, err := tlsconn.Write([]byte("Hello with TLS\n")); err != nil {
				log.Printf("[ERROR] Write: %s", err)
				return
			}
		}(conn)
	}
}
