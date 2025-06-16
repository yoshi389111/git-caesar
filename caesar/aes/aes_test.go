package aes

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func Test_Encrypt_Decrypt_AesCbc32_V1(t *testing.T) {
	message := []byte("hello world AES-256-CBC")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt("1", key, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt("1", key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_Encrypt_Decrypt_AesCbc24_V1(t *testing.T) {
	message := []byte("hello world AES-192-CBC")

	key := make([]byte, 24)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt("1", key, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt("1", key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_Encrypt_Decrypt_AesCbc16_V1(t *testing.T) {
	message := []byte("hello world AES-128-CBC")

	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt("1", key, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt("1", key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}
