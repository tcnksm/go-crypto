package main

import (
	"crypto/rand"
	"crypto/rsa"
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
	size := 1024

	// nprimes is the number of prime of which N consists
	// e.g., if nprimes is 2, N = p*q. If nprimes is 3, N = p*q*r
	nprimes := 2

	privateKey, err := rsa.GenerateMultiPrimeKey(rand.Reader, nprimes, size)
	if err != nil {
		fmt.Printf("err: %s", err)
		return
	}

	// N = p*q
	var z big.Int
	if privateKey.N.Cmp(z.Mul(privateKey.Primes[0], privateKey.Primes[1])) != 0 {
		panic("shoud not reach here")
	}

}
