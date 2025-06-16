package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_EncryptDecryptRsaOaep1024(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	ciphertext, err := Encrypt(pubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(prvKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_EncryptDecryptRsaOaep2048(t *testing.T) {
	message := []byte("hello world --------------- 2048") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	ciphertext, err := Encrypt(pubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(prvKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_EncryptDecryptRsaOaep4096(t *testing.T) {
	message := []byte("hello world --------------- 4096") // 32byte

	prvKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	ciphertext, err := Encrypt(pubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(prvKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_SignVerifyRsa(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	prvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	sig, err := Sign(prvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pubKey, message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_NewEnvelope_ExtractShareKey(t *testing.T) {
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

	addInfo, err := rsaPubKey.NewEnvelope(message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := rsaPrvKey.ExtractShareKey(addInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, decrypted) {
		t.Fatal(hex.Dump(decrypted))
	}
}

func Test_PrivateKeySign_PublickKeyVerify(t *testing.T) {
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

	sig, err := rsaPrvKey.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if !rsaPubKey.Verify(message, sig) {
		t.Fatal("verify failed")
	}
}
