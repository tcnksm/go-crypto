package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"fmt"
	"io"
)

func main() {
	plainText := []byte("Bob loves Alice.")

	// Key must be 8 bytes
	key := []byte("passw0rd")

	// Create Cipher block for DES
	block, err := des.NewCipher(key)
	if err != nil {
		fmt.Printf("err: %s", err)
	}

	// Create initialization vector from rand.reader
	iv := make([]byte, des.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Printf("err: %s", err)
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
