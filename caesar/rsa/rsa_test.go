package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_EncryptDecryptRsaOaep1024_V1(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	ciphertext, err := Encrypt("1", pubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt("1", prvKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_EncryptDecryptRsaOaep2048_V1(t *testing.T) {
	message := []byte("hello world --------------- 2048") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	ciphertext, err := Encrypt("1", pubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt("1", prvKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_EncryptDecryptRsaOaep4096_V1(t *testing.T) {
	message := []byte("hello world --------------- 4096") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	ciphertext, err := Encrypt("1", pubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt("1", prvKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_SignVerifyRsa_V1(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	prvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	sig, err := Sign("1", prvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify("1", pubKey, message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_SignVerifyRsa_V2(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	prvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	sig, err := Sign("2", prvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify("2", pubKey, message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_NewEnvelope_ExtractShareKey_V1(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 1024)
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

	addInfo, err := rsaPubKey.NewEnvelope("1", message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := rsaPrvKey.ExtractShareKey("1", addInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, decrypted) {
		t.Fatal(hex.Dump(decrypted))
	}
}

func Test_PrivateKeySign_PublickKeyVerify_V1(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 1024)
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

	sig, err := rsaPrvKey.Sign("1", message)
	if err != nil {
		t.Fatal(err)
	}

	if !rsaPubKey.Verify("1", message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_PrivateKeySign_PublickKeyVerify_V2(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 1024)
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

	sig, err := rsaPrvKey.Sign("2", message)
	if err != nil {
		t.Fatal(err)
	}

	if !rsaPubKey.Verify("2", message, sig) {
		t.Fatal("verify failed")
	}
}
