package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

func main() {
	// 224-255 bits length key is same strenght with 2048 bits RSA
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	hashed := []byte("This is message.")
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	if ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
		fmt.Printf("Verified!\n")
	}
}
