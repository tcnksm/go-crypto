package main

import (
	"crypto/md5"
	"fmt"
	"io"
)

func main() {

	// New hash.Hash computing MD5 checksum.
	h := md5.New()

	msg := "Taichi Nakashima"
	io.WriteString(h, msg)
	checksum := h.Sum(nil)

	fmt.Printf("Length: %d byte\n", len(checksum))
	fmt.Printf("Output: %x\n", checksum)

	fmt.Printf("Output: %x\n", md5.Sum([]byte(msg)))
}
