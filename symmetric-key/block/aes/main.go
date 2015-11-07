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

	// key length should be 16byte(AES-128), 24byte(AES-192)
	// 32byte (AES-256). In this case, AES-256
	aes256key := []byte("passw0rdpassw0rdpassw0rdpassw0rd")

	block, err := aes.NewCipher(aes256key)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	// Create initialization vector from rand.reader
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	// Encrypt with CBC mode
	cipherText := make([]byte, len(plainText))
	encryptMode := cipher.NewCBCEncrypter(block, iv)
	encryptMode.CryptBlocks(cipherText, plainText)
	fmt.Printf("Cipher text: %v\n", cipherText)

	// Decrypt with CBC mode
	decryptedText := make([]byte, len(cipherText))
	decryptMode := cipher.NewCBCDecrypter(block, iv)
	decryptMode.CryptBlocks(decryptedText, cipherText)
	fmt.Printf("Decrypted text: %s\n", string(decryptedText))
}
