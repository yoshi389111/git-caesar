package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func Encrypt(key, plaintext []byte) ([]byte, error) {
	// pad the message with PKCS#7
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, aes.BlockSize+len(padtext))
	iv := ciphertext[:aes.BlockSize]
	encMsg := ciphertext[aes.BlockSize:]

	// generate initialization vector (IV)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// encrypt message (AES-CBC)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block for encryption: %w", err)
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encMsg, padtext)

	return ciphertext, nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	// extract the initial vector (IV)
	iv := ciphertext[:aes.BlockSize]
	encMsg := ciphertext[aes.BlockSize:]

	// create an decrypter in CBC mode
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block for decryption: %w", err)
	}
	cbc := cipher.NewCBCDecrypter(block, iv)

	// decrypt ciphertext
	msgLen := len(encMsg)
	decMsg := make([]byte, msgLen)
	cbc.CryptBlocks(decMsg, encMsg)

	// Unpad the message with PKCS#7
	plaintext := decMsg[:msgLen-int(decMsg[msgLen-1])]
	return plaintext, nil
}
