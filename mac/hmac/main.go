package main

import (
	"crypto/hmac"
	"fmt"
)
import "crypto/sha512"

// hash(opadkey || hash(ipadkey || message))
// ipadkey = key XOR ipad
// opadkey = key XOR opad
func main() {
	msg := []byte("Bob loves Alice.")
	key := []byte("passw0rd")

	h1 := hmac.New(sha512.New, key)
	h1.Write(msg)
	mac1 := h1.Sum(nil)
	fmt.Printf("MAC1: %x\n", mac1)

	h2 := hmac.New(sha512.New, key)
	h2.Write(msg)
	mac2 := h2.Sum(nil)
	fmt.Printf("MAC2: %x\n", mac2)

	fmt.Printf("Valid? %v\n", hmac.Equal(mac1, mac2))
}
