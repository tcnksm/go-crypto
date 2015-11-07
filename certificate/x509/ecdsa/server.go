package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
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
	caPriv, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	// Generate pub & priv key pair for server certs by Elliptic Curve DSA
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	// Create CA certificate template
	cert := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Country:      []string{"Japan"},
			Organization: []string{"TCNKSM WEB ECDSA Inc."},
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},

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

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
}
