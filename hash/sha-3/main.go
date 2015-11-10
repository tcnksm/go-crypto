package main

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

func main() {
	msg := []byte("Taichi Nakashima")

	// A MAC with 32 bytes of output has 256-bit security strength
	h := make([]byte, 64)

	// The SHAKE functions are recommended for most new uses.
	// They can produce output of arbitrary length.
	// SHAKE256, with an output length of at least 64 bytes, provides 256-bit security against all attacks.
	d := sha3.NewShake256()
	d.Write(msg)
	d.Read(h)

	fmt.Printf("Length: %d byte (%d bits)\n", len(h), len(h)*8)
	fmt.Printf("Output: %x\n", h)
}
