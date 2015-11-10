package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"math/big"
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

	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		fmt.Printf("err: %s", err)
		return
	}

	// N = p*q
	var z big.Int
	if privateKey.N.Cmp(z.Mul(privateKey.Primes[0], privateKey.Primes[1])) != 0 {
		panic("shoud not reach here")
	}

	plain := []byte("Bob loves Alice.")

	// A label is a byte string that is effectively bound to the ciphertext in a nonmalleable way.
	// http://crypto.stackexchange.com/questions/2074/rsa-oaep-input-parameters
	label := []byte("test")

	// Get public key from private key and encrypt
	publicKey := &privateKey.PublicKey
	cipherText, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, plain, label)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	fmt.Printf("Cipher: %x\n", cipherText)

	// Decrypt with private key
	plainText, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, cipherText, label)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}

	fmt.Printf("Plain: %s\n", plainText)
}
