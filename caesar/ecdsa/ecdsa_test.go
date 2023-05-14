package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_Encrypt_Decrypt_P256(t *testing.T) {
	message := []byte("hello world --------------- 0256") // 32byte
	alicePrvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey

	ciphertext, bobPubKey, err := Encrypt(alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(alicePrvKey, bobPubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_Encrypt_Decrypt_P384(t *testing.T) {
	message := []byte("hello world --------------- 0384") // 32byte
	alicePrvKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey

	ciphertext, bobPubKey, err := Encrypt(alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(alicePrvKey, bobPubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_Encrypt_Decrypt_P521(t *testing.T) {
	message := []byte("hello world --------------- 0521") // 32byte
	alicePrvKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey

	ciphertext, bobPubKey, err := Encrypt(alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(alicePrvKey, bobPubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_Sing_Verify_P521(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	prvKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
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

	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaPrvKey := NewPrivateKey(*prvKey)
	ecdsaPubKey := NewPublicKey(*pubKey, sshPubKey)

	addInfo, err := ecdsaPubKey.NewEnvelope(message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ecdsaPrvKey.ExtractShareKey(addInfo)
	if !bytes.Equal(message, decrypted) {
		t.Fatal(hex.Dump(decrypted))
	}
}

func Test_PrivateKeySign_PublickKeyVerify(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaPrvKey := NewPrivateKey(*prvKey)
	ecdsaPubKey := NewPublicKey(*pubKey, sshPubKey)

	sig, err := ecdsaPrvKey.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if !ecdsaPubKey.Verify(message, sig) {
		t.Fatal("verify failed")
	}
}
