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
	// Read CA certificate pem file
	caPem, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	caBlock, _ := pem.Decode(caPem)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	// Read CA private key pem file
	caKeyPem, err := ioutil.ReadFile("certs/ca-key.pem")
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	caKeyBlock, _ := pem.Decode(caKeyPem)
	caPriv, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	// Generate pub & priv key pair for server certs by RSA
	size := 2024
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	// Create CA certificate template
	cert := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Country:      []string{"Japan"},
			Organization: []string{"TCNKSM WEB Inc."},
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create Server Certificate. Sign by CA private key.
	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, caCert, &priv.PublicKey, caPriv)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	certOut, err := os.Create("certs/server.pem")
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	keyOut, err := os.OpenFile("certs/server-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
}
