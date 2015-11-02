package main

import (
	"crypto/dsa"
	"crypto/rand"
	"fmt"
)

func main() {
	var privateKey dsa.PrivateKey
	params := &privateKey.Parameters

	// L2048N224 is length of L and N
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L2048N224); err != nil {
		fmt.Printf("Err: %s", err)
		return
	}

	if err := dsa.GenerateKey(&privateKey, rand.Reader); err != nil {
		fmt.Printf("Err: %s", err)
		return
	}

	hashed := []byte("This is test hashed message")

	// It returns the signature as a pair of integers.
	r, s, err := dsa.Sign(rand.Reader, &privateKey, hashed)
	if err != nil {
		fmt.Printf("Err: %s", err)
		return
	}

	// Check signnature can be verified
	publicKey := &privateKey.PublicKey
	if dsa.Verify(publicKey, hashed, r, s) {
		fmt.Printf("Verified\n")
	}
}
