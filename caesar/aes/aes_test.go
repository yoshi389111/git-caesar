package aes

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func Test_Encrypt_Decrypt_Aes(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"aes256_formatVer1": {32, "1"},

		"aes128_formatVer2": {16, "2"},
		"aes192_formatVer2": {24, "2"},
		"aes256_formatVer2": {32, "2"},
	}

	message := []byte("hello world AES encryption test")
	for name, tc := range cases {
		t.Run("Encrypt_Decrypt_"+name, func(t *testing.T) {
			key := make([]byte, tc.keyLength)
			_, err := rand.Read(key)
			if err != nil {
				t.Fatal(err)
			}

			ciphertext, err := Encrypt(tc.formatVersion, key, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			ciphertext2, err := Encrypt(tc.formatVersion, key, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			// AES encryption should produce non-deterministic ciphertexts due to random padding.
			if bytes.Equal(ciphertext, ciphertext2) {
				t.Fatal("ciphertext should not be equal, but they are")
			}

			plaintext, err := Decrypt(tc.formatVersion, key, ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext) {
				t.Fatal(hex.Dump(plaintext))
			}

			plaintext2, err := Decrypt(tc.formatVersion, key, ciphertext2)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext2) {
				t.Fatal(hex.Dump(plaintext2))
			}
		})
	}
}

func Test_EncryptDecrypt_Aes_InvalidVersion(t *testing.T) {
	key := make([]byte, 32)

	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	octetStream := []byte("test message")

	if _, err := Encrypt("invalid", key, octetStream); err == nil {
		t.Fatal("expected encryption to fail with invalid version, but it succeeded")
	}

	if _, err := Decrypt("invalid", key, octetStream); err == nil {
		t.Fatal("expected decryption to fail with invalid version, but it succeeded")
	}
}

func Test_Encrypt_Decrypt_Aes_WrongKey(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"aes256_formatVer1": {32, "1"},

		"aes128_formatVer2": {16, "2"},
		"aes192_formatVer2": {24, "2"},
		"aes256_formatVer2": {32, "2"},
	}

	message := []byte("hello world AES wrong key test")
	for name, tc := range cases {
		t.Run("Encrypt_Decrypt_WrongKey_"+name, func(t *testing.T) {
			key1 := make([]byte, tc.keyLength)
			if _, err := rand.Read(key1); err != nil {
				t.Fatal(err)
			}

			key2 := make([]byte, tc.keyLength)
			if _, err := rand.Read(key2); err != nil {
				t.Fatal(err)
			}

			ciphertext, err := Encrypt(tc.formatVersion, key1, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			ciphertext2, err := Encrypt(tc.formatVersion, key2, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			if _, err = Decrypt(tc.formatVersion, key2, ciphertext); err == nil {
				t.Fatal("expected decryption to fail with wrong key, but it succeeded")
			}

			if _, err = Decrypt(tc.formatVersion, key1, ciphertext2); err == nil {
				t.Fatal("expected decryption to fail with wrong key, but it succeeded")
			}
		})
	}
}
