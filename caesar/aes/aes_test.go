package aes

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func Test_EncryptDecryptAesCbc32(t *testing.T) {
	message := []byte("hello world AES-256-CBC")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt(key, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_EncryptDecryptAesCbc24(t *testing.T) {
	message := []byte("hello world AES-192-CBC")

	key := make([]byte, 24)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt(key, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_EncryptDecryptAesCbc16(t *testing.T) {
	message := []byte("hello world AES-128-CBC")

	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt(key, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}
