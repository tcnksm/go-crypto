package main

import (
	"crypto/aes"
	"fmt"
)

func main() {
	// key length should be 16byte(AES-128), 24byte(AES-192)
	// 32byte (AES-256). In this case, AES-256
	aes256key := []byte("passw0rdpassw0rdpassw0rdpassw0rd")

	block, err := aes.NewCipher(aes256key)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	// Encrypt
	plainText := []byte("This is 16 bytes")
	cipherText := make([]byte, len(plainText))
	block.Encrypt(cipherText, plainText)
	fmt.Printf("Cipher text: %x\n", cipherText)

	// Decrypt
	decryptedText := make([]byte, len(cipherText))
	block.Decrypt(decryptedText, cipherText)
	fmt.Printf("Decrypted text: %s\n", string(decryptedText))
}
