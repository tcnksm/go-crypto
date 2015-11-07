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

	// Key must be 24(8*3) bytes because tdes runs des 3 times
	// plain text -> (DES encrypt) -> (DES decrypt) -> (DES encrypt) -> cipher text
	// DES-EDE2 uses the same key for first and the third encrypt
	// DES-EDE3 uses different key for all encrypt/decrypt
	key := []byte("passw0rdpassw0rdpassw0rd")

	// Create Cipher block for TDES
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		fmt.Printf("err: %s", err)
		return
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
