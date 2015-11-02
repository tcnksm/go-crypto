package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

// Generate server cert (server.pem) signed by ca.pem
// and private key (serverkey.pem)
func main() {

	// Generate pub & priv key pair by RSA
	size := 2024
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		fmt.Printf("Err: %s", err)
		return
	}

	// Create CA certificate template
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Organization: []string{"TCNKSM WEB Inc."},
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	rootPem, err := ioutil.ReadFile("cert/ca.pem")
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	rootBlock, _ := pem.Decode(rootPem)
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	rootKeyPem, err := ioutil.ReadFile("cert/cakey.pem")
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	rootKeyBlock, _ := pem.Decode(rootKeyPem)
	rootPriv, err := x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)

	// Create Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, rootCert, &priv.PublicKey, rootPriv)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	certOut, err := os.Create("cert/server.pem")
	if err != nil {
		fmt.Printf("Err: %s", err)
		return
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		fmt.Printf("Err: %s", err)
		return
	}

	keyOut, err := os.Create("cert/serverkey.pem")
	if err != nil {
		fmt.Printf("Err: %s", err)
		return
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		fmt.Printf("Err: %s", err)
		return
	}
}
