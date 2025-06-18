package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_EncryptDecryptRsa(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"rsa2048_formatVer1": {2048, "1"},

		"rsa1024_formatVer2": {1024, "2"},
		"rsa2048_formatVer2": {2048, "2"},
		"rsa4096_formatVer2": {4096, "2"},
	}

	message := []byte("hello world ------------ 32 byte")
	for name, tc := range cases {
		t.Run("Encrypt_Decrypt_"+name, func(t *testing.T) {
			prvKey, err := rsa.GenerateKey(rand.Reader, tc.keyLength)
			if err != nil {
				t.Fatal(err)
			}
			pubKey := &prvKey.PublicKey

			ciphertext, err := Encrypt(tc.formatVersion, pubKey, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			ciphertext2, err := Encrypt(tc.formatVersion, pubKey, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			if bytes.Equal(ciphertext, ciphertext2) {
				t.Fatal("ciphertext should not be equal, but they are")
			}

			plaintext, err := Decrypt(tc.formatVersion, prvKey, ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext) {
				t.Fatal(hex.Dump(plaintext))
			}

			plaintext2, err := Decrypt(tc.formatVersion, prvKey, ciphertext2)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext2) {
				t.Fatal(hex.Dump(plaintext2))
			}
		})
	}
}

func Test_SignVerifyRsa(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"rsa2048_formatVer1": {2048, "1"},

		"rsa1024_formatVer2": {1024, "2"},
		"rsa2048_formatVer2": {2048, "2"},
		"rsa4096_formatVer2": {4096, "2"},
	}

	message := []byte("hello world ------------ 32 byte")
	for name, tc := range cases {
		t.Run("Sign_Verify_"+name, func(t *testing.T) {
			prvKey, err := rsa.GenerateKey(rand.Reader, tc.keyLength)
			if err != nil {
				t.Fatal(err)
			}
			pubKey := &prvKey.PublicKey

			sig, err := Sign(tc.formatVersion, prvKey, message)
			if err != nil {
				t.Fatal(err)
			}

			if !Verify(tc.formatVersion, pubKey, message, sig) {
				t.Fatal("verify failed")
			}
		})
	}
}

func Test_NewEnvelope_ExtractShareKey(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"rsa2048_formatVer1": {2048, "1"},
		"rsa2048_formatVer2": {2048, "2"},
	}

	message := []byte("hello world ------------ 32 byte")
	for name, tc := range cases {
		t.Run("NewEnvelope_ExtractShareKey_"+name, func(t *testing.T) {
			prvKey, err := rsa.GenerateKey(rand.Reader, tc.keyLength)
			if err != nil {
				t.Fatal(err)
			}
			pubKey := &prvKey.PublicKey

			sshPubKey, err := ssh.NewPublicKey(pubKey)
			if err != nil {
				t.Fatal(err)
			}

			rsaPrvKey := NewPrivateKey(*prvKey)
			rsaPubKey := NewPublicKey(*pubKey, sshPubKey)

			addInfo, err := rsaPubKey.NewEnvelope(tc.formatVersion, message)
			if err != nil {
				t.Fatal(err)
			}

			decrypted, err := rsaPrvKey.ExtractShareKey(tc.formatVersion, addInfo)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(message, decrypted) {
				t.Fatal(hex.Dump(decrypted))
			}
		})
	}

}

func Test_PrivateKeySign_PublicKeyVerify(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"rsa2048_formatVer1": {2048, "1"},
		"rsa2048_formatVer2": {2048, "2"},
	}

	message := []byte("hello world --------------- 1024") // 32byte
	for name, tc := range cases {
		t.Run("PrivateKey_PublicKey_"+name, func(t *testing.T) {
			prvKey, err := rsa.GenerateKey(rand.Reader, tc.keyLength)
			if err != nil {
				t.Fatal(err)
			}
			pubKey := &prvKey.PublicKey

			sshPubKey, err := ssh.NewPublicKey(pubKey)
			if err != nil {
				t.Fatal(err)
			}

			rsaPrvKey := NewPrivateKey(*prvKey)
			rsaPubKey := NewPublicKey(*pubKey, sshPubKey)

			sig, err := rsaPrvKey.Sign(tc.formatVersion, message)
			if err != nil {
				t.Fatal(err)
			}

			if !rsaPubKey.Verify(tc.formatVersion, message, sig) {
				t.Fatal("verify failed")
			}
		})
	}
}

func Test_EncryptDecryptRsa_InvalidVersion(t *testing.T) {
	prvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey
	message := []byte("test message")

	_, err = Encrypt("invalid", pubKey, message)
	if err == nil {
		t.Fatal("expected error for invalid version in Encrypt")
	}

	_, err = Decrypt("invalid", prvKey, message)
	if err == nil {
		t.Fatal("expected error for invalid version in Decrypt")
	}
}

func Test_SignVerifyRsa_InvalidVersion(t *testing.T) {
	prvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey
	message := []byte("test message")

	_, err = Sign("invalid", prvKey, message)
	if err == nil {
		t.Fatal("expected error for invalid version in Sign")
	}

	sig, err := Sign("1", prvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if Verify("invalid", pubKey, message, sig) {
		t.Fatal("expected false for invalid version in Verify")
	}
}

func Test_EncryptDecryptRsa_WrongKey(t *testing.T) {
	prvKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	prvKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey1 := &prvKey1.PublicKey
	message := []byte("test message")

	ciphertext, err := Encrypt("1", pubKey1, message)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt("1", prvKey2, ciphertext)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong private key")
	}
}

func Test_SignVerifyRsa_WrongKey(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"rsa2048_formatVer1": {2048, "1"},
		"rsa2048_formatVer2": {2048, "2"},
	}
	for name, tc := range cases {
		t.Run("Sign_Verify_wrong_key_"+name, func(t *testing.T) {

			prvKey1, err := rsa.GenerateKey(rand.Reader, tc.keyLength)
			if err != nil {
				t.Fatal(err)
			}
			prvKey2, err := rsa.GenerateKey(rand.Reader, tc.keyLength)
			if err != nil {
				t.Fatal(err)
			}
			pubKey2 := &prvKey2.PublicKey
			message := []byte("test message")

			sig, err := Sign(tc.formatVersion, prvKey1, message)
			if err != nil {
				t.Fatal(err)
			}

			if Verify(tc.formatVersion, pubKey2, message, sig) {
				t.Fatal("expected verify to fail with wrong public key")
			}
		})
	}
}

func Test_SignVerifyRsa_ModifiedMessage(t *testing.T) {
	cases := map[string]struct {
		keyLength     int
		formatVersion string
	}{
		"rsa2048_formatVer1": {2048, "1"},
		"rsa2048_formatVer2": {2048, "2"},
	}

	for name, tc := range cases {
		t.Run("Sign_Verify_modified_message/"+name, func(t *testing.T) {

			prvKey, err := rsa.GenerateKey(rand.Reader, tc.keyLength)
			if err != nil {
				t.Fatal(err)
			}
			pubKey := &prvKey.PublicKey
			message := []byte("test message")
			sig, err := Sign(tc.formatVersion, prvKey, message)
			if err != nil {
				t.Fatal(err)
			}

			modified := []byte("test message!")
			if Verify(tc.formatVersion, pubKey, modified, sig) {
				t.Fatal("expected verify to fail with modified message")
			}
		})
	}
}
