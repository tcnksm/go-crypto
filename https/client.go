package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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

	tr := http.Transport{
		TLSClientConfig: &config,
	}

	client := http.Client{
		Transport: &tr,
	}

	res, err := client.Get("https://127.0.0.1:3000")
	if err != nil {
		log.Printf("[ERROR] %s", err)
	}
	defer res.Body.Close()

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("[ERROR] %s", err)
	}
	log.Printf("[INFO] response: %q", string(buf))
}
