package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func main() {
	plainText := []byte("Bob loves Alice.")
	key := []byte("passw0rdpassw0rdpassw0rdpassw0rd")

	// Create new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	fmt.Println(aead.NonceSize())
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	cipherText := aead.Seal(nil, nonce, plainText, nil)
	fmt.Printf("Cipher text: %x\n", cipherText)

	plainText_, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}
	fmt.Printf("Decrypted text: %s\n", string(plainText_))
}
