package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
)

func main() {
	size := 2024
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	msg := []byte("This is message.")
	hashed := sha512.Sum512(msg)
	s, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA512, hashed[:])
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	fmt.Printf("Sign: %x\n", s)

	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, hashed[:], s); err != nil {
		fmt.Printf("Failed to verify: %s\n", err)
		return
	}
}
