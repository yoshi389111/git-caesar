package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func Encrypt(version string, key, plaintext []byte) ([]byte, error) {
	switch version {
	case "1":
		return encryptV1(version, key, plaintext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func encryptV1(version string, key, plaintext []byte) ([]byte, error) {
	_ = version // unused parameter
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

func Decrypt(version string, key, ciphertext []byte) ([]byte, error) {
	switch version {
	case "1":
		return decryptV1(version, key, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func decryptV1(version string, key, ciphertext []byte) ([]byte, error) {
	_ = version // unused parameter
	// Check if ciphertext is long enough to contain an IV
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	// Extract the initialization vector (IV) from the beginning of the ciphertext
	iv := ciphertext[:aes.BlockSize]
	encMsg := ciphertext[aes.BlockSize:]

	// Create a new AES cipher block for decryption in CBC mode
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block for decryption: %w", err)
	}
	cbc := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the ciphertext
	msgLen := len(encMsg)
	if msgLen%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}
	decMsg := make([]byte, msgLen)
	cbc.CryptBlocks(decMsg, encMsg)

	// Unpad the message using PKCS#7
	if msgLen == 0 {
		return nil, fmt.Errorf("decrypted message is empty")
	}
	padding := int(decMsg[msgLen-1])
	// Check if the padding size is valid
	if padding == 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding size")
	}
	// Validate PKCS#7 padding bytes
	for i := range padding {
		if decMsg[msgLen-1-i] != byte(padding) {
			return nil, fmt.Errorf("invalid PKCS#7 padding")
		}
	}
	plaintext := decMsg[:msgLen-padding]
	return plaintext, nil
}
