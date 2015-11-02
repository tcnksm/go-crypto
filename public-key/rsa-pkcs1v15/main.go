package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// (plain)^E mod N = cipher
// public key = {E,N}
// E means 'Encription', N means 'Number'

// (cipher)^D mod N = plain
// plivate key = {D,N}
// D means 'Decription'
func main() {

	// Generate key pair. public key {E,N} and private key {D,N}
	// E is 64437 https://en.wikipedia.org/wiki/65537_(number))

	// size of key (bits)
	size := 2048

	// nprimes is the number of prime of which N consists
	// e.g., if nprimes is 2, N = p*q. If nprimes is 3, N = p*q*r
	nprimes := 2

	privateKey, err := rsa.GenerateMultiPrimeKey(rand.Reader, nprimes, size)
	if err != nil {
		fmt.Printf("err: %s", err)
		return
	}

	plain := []byte("Bob loves Alice.")

	// Get public key from private key and encrypt
	publicKey := &privateKey.PublicKey

	// Why rand ? It's ude on nonZeroRandomBytes.
	// It fills the given slice with non-zero random octets.
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plain)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	fmt.Printf("Cipher: %x\n", cipherText)

	// Decrypt with private key
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	fmt.Printf("Plain: %s\n", plainText)
}
