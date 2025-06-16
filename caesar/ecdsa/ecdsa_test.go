package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
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

func Test_Sign_Verify_P521(t *testing.T) {
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
	if err != nil {
		t.Fatal(err)
	}
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

type sigParam struct {
	R, S *big.Int
}

func Test_Signature_Compatibility(t *testing.T) {
	message := []byte("hello world ------------- compat") // 32byte
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, prvKey, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sigOld, err := asn1.Marshal(sigParam{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(pubKey, message, sigOld) {
		t.Fatal("The signature of the old version is not verified by verifying the new version.")
	}
}

func Test_Verify_Compatibility(t *testing.T) {
	message := []byte("hello world ------------- compat") // 32byte
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	hash := sha256.Sum256(message)
	sigNew, err := Sign(prvKey, message)
	if err != nil {
		t.Fatal(err)
	}
	signature := &sigParam{}
	_, err = asn1.Unmarshal(sigNew, signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.Verify(pubKey, hash[:], signature.R, signature.S) {
		t.Fatal("The signature of the new version is not verified by verifying the old version.")
	}
}
