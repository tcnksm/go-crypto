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
	}

	// The IV (Initialization Vector) need to be unique, but not secure.
	// Therefore, it's common to include it at the beginning of the cipher text.
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	// Fill iv with rand value
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Printf("err: %s\n", err)
	}

	// Encrypt
	encryptMode := cipher.NewCBCEncrypter(block, iv)
	encryptMode.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	fmt.Printf("Cipher text: %v\n", cipherText)

	// Decrypt
	decryptedText := make([]byte, len(cipherText[aes.BlockSize:]))
	decryptMode := cipher.NewCBCDecrypter(block, cipherText[:aes.BlockSize])
	decryptMode.CryptBlocks(decryptedText, cipherText[aes.BlockSize:])
	fmt.Printf("Decrypted text: %s\n", string(decryptedText))
}
