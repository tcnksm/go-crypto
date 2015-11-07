package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	// Read CA certificate
	rootPem, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPem)
	if !ok {
		fmt.Printf("Err: failed to parse root certificate")
		return
	}

	serverPem, err := ioutil.ReadFile("certs/server.pem")
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	serverBlock, _ := pem.Decode(serverPem)
	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	// Server cert is signed by ca private key.
	// Now we can check its sign by ca certs (public key).
	if _, err := serverCert.Verify(opts); err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	fmt.Printf("Valified!\n")
}
