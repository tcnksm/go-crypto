package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {

	rootPem, err := ioutil.ReadFile("cert/ca.pem")
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

	serverPem, err := ioutil.ReadFile("cert/server.pem")
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

	chain, err := serverCert.Verify(opts)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	fmt.Printf("%#v\n", chain[0][0].Subject.Organization)
	fmt.Printf("%#v\n", chain[0][1].Subject.Organization)
}
