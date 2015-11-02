package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

func main() {
	msg := []byte("Taichi Nakashima")

	checksum256 := sha256.Sum256(msg)
	fmt.Printf("Length (SHA-256): %d byte (%d bits)\n", len(checksum256), len(checksum256)*8)
	fmt.Printf("Output (SHA-256): %x\n\n", checksum256)

	checksum512 := sha512.Sum512(msg)
	fmt.Printf("Length (SHA-512): %d byte (%d bits)\n", len(checksum512), len(checksum512)*8)
	fmt.Printf("Output (SHA-512): %x\n\n", checksum512)

	checksum512_256 := sha512.Sum512_256(msg)
	fmt.Printf("Length (SHA-512/256): %d byte (%d bits)\n", len(checksum512_256), len(checksum512_256)*8)
	fmt.Printf("Output (SHA-512/256): %x\n\n", checksum512_256)
}
