package main

import (
	"crypto/rc4"
	"fmt"
)

func main() {
	plainText := []byte("Bob loves Alice.")

	key := []byte("passw0rd")
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return
	}

	cipherText := make([]byte, len(plainText))
	cipher.XORKeyStream(cipherText, plainText)
	fmt.Printf("Cipher text: %x\n", cipherText)

	decryptedText := make([]byte, len(cipherText))
	cipher2, _ := rc4.NewCipher(key)
	cipher2.XORKeyStream(decryptedText, cipherText)
	fmt.Printf("Decrypted text: %s\n", string(decryptedText))
}
