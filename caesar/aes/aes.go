package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/yoshi389111/git-caesar/caesar/common"
)

// Encrypt encrypts a message using AES.
func Encrypt(version string, key, plaintext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return encryptV1(key, plaintext)
	case common.Version2:
		return encryptV2(key, plaintext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

// Encrypt encrypts a message using AES-CBC with PKCS#7 padding.
func encryptV1(key, plaintext []byte) ([]byte, error) {

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

// Encrypt encrypts a message using AES-GCM.
func encryptV2(key, plaintext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block for encryption: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

// Decrypt decrypts a message using AES.
func Decrypt(version string, key, ciphertext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return decryptV1(key, ciphertext)
	case common.Version2:
		return decryptV2(key, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

// Decrypt decrypts a message using AES-CBC with PKCS#7 padding.
func decryptV1(key, ciphertext []byte) ([]byte, error) {

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

// Decrypt decrypts a message using AES-GCM.
func decryptV2(key, ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block for encryption: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	encMsg := ciphertext[gcm.NonceSize():]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, encMsg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}
