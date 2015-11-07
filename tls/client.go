package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
)

func main() {
	// Read CA certificate
	caFile, _ := filepath.Abs("../certificate/x509/ecdsa/certs/ca.pem")
	rootPem, err := ioutil.ReadFile(caFile)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(rootPem); !ok {
		fmt.Printf("Err: failed to parse root certificate")
		return
	}

	config := tls.Config{
		RootCAs: roots,
	}

	conn, err := tls.Dial("tcp", "127.0.0.1:443", &config)
	if err != nil {
		log.Printf("[ERROR] %s\n", err)
		return
	}
	defer conn.Close()

	log.Printf("[INFO] Connect to %s", conn.RemoteAddr())

	state := conn.ConnectionState()
	log.Printf("[INFO] Handshake complete: %v", state.HandshakeComplete)
	for _, c := range state.PeerCertificates {
		k, _ := x509.MarshalPKIXPublicKey(c.PublicKey)
		log.Printf("[INFO] Cert: Public key: %x...", k[:20])
		log.Printf("[INFO] Cert: Organization: %s", c.Subject.Organization[0])
	}

	message := []byte("Hello")
	if _, err := conn.Write(message); err != nil {
		log.Printf("[ERROR] Write: %s", err)
		return
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, conn); err != nil {
		log.Printf("[ERROR] Read: %s", err)
		return
	}
	log.Printf("[INFO] Reply: %s", buf.String())
}
