package main

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	msg := []byte("Taichi Nakashima")

	checksum1 := sha1.Sum(msg)
	fmt.Printf("Length (SHA-1): %d byte (%d bits)\n", len(checksum1), len(checksum1)*8)
	fmt.Printf("Output (SHA-1): %x\n\n", checksum1)
}
