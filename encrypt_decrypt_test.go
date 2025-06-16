package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"

	"github.com/yoshi389111/git-caesar/caesar"
	ec "github.com/yoshi389111/git-caesar/caesar/ecdsa"
	ed "github.com/yoshi389111/git-caesar/caesar/ed25519"
	rs "github.com/yoshi389111/git-caesar/caesar/rsa"

	"golang.org/x/crypto/ssh"
)

func Test_encrypt_decrypt_rsa_V1(t *testing.T) {

	alicePrvKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey
	aliceSshPubKey, err := ssh.NewPublicKey(alicePubKey)
	if err != nil {
		t.Fatal(err)
	}
	aliceCaesarPubKey := rs.NewPublicKey(*alicePubKey, aliceSshPubKey)
	aliceCaesarPrvKey := rs.NewPrivateKey(*alicePrvKey)
	alicePubKeys := []caesar.PublicKey{aliceCaesarPubKey}

	bobRsaPrvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bobRsaPubKey := &bobRsaPrvKey.PublicKey
	bobRsaSshPubKey, err := ssh.NewPublicKey(bobRsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarRsaPubKey := rs.NewPublicKey(*bobRsaPubKey, bobRsaSshPubKey)
	bobCaesarRsaPrvKey := rs.NewPrivateKey(*bobRsaPrvKey)

	bobEcdsaPrvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEcdsaPubKey := &bobEcdsaPrvKey.PublicKey
	bobEcdsaSshPubKey, err := ssh.NewPublicKey(bobEcdsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarEcdsaPubKey := ec.NewPublicKey(*bobEcdsaPubKey, bobEcdsaSshPubKey)
	bobCaesarEcdsaPrvKey := ec.NewPrivateKey(*bobEcdsaPrvKey)

	bobEd25519PubKey, bobEd25519PrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEd25519SshPubKey, err := ssh.NewPublicKey(bobEd25519PubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarEd25519PubKey := ed.NewPublicKey(bobEd25519PubKey, bobEd25519SshPubKey)
	bobCaesarEd25519PrvKey := ed.NewPrivateKey(bobEd25519PrvKey)

	bobPubKeys := []caesar.PublicKey{bobCaesarRsaPubKey, bobCaesarEcdsaPubKey, bobCaesarEd25519PubKey}

	bobAuthKeyString := ""
	for _, pubKey := range bobPubKeys {
		authKey := pubKey.GetAuthKey()
		bobAuthKeyString += authKey + "\n"
	}

	message := []byte("hello world")

	zipBytes, err := encrypt("1", bobPubKeys, aliceCaesarPrvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	// rsa
	rasMessage, err := decrypt(alicePubKeys, bobCaesarRsaPrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, rasMessage) {
		t.Fatal(hex.Dump(rasMessage))
	}

	// ecdsa
	ecdsaMessage, err := decrypt(alicePubKeys, bobCaesarEcdsaPrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, ecdsaMessage) {
		t.Fatal(hex.Dump(ecdsaMessage))
	}

	// ed25519
	ed25519Message, err := decrypt(alicePubKeys, bobCaesarEd25519PrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, ed25519Message) {
		t.Fatal(hex.Dump(ed25519Message))
	}
}

func Test_encrypt_decrypt_ecdsa_V1(t *testing.T) {

	alicePrvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey
	aliceSshPubKey, err := ssh.NewPublicKey(alicePubKey)
	if err != nil {
		t.Fatal(err)
	}
	aliceCaesarPubKey := ec.NewPublicKey(*alicePubKey, aliceSshPubKey)
	aliceCaesarPrvKey := ec.NewPrivateKey(*alicePrvKey)
	alicePubKeys := []caesar.PublicKey{aliceCaesarPubKey}

	bobRsaPrvKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	bobRsaPubKey := &bobRsaPrvKey.PublicKey
	bobRsaSshPubKey, err := ssh.NewPublicKey(bobRsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarRsaPubKey := rs.NewPublicKey(*bobRsaPubKey, bobRsaSshPubKey)
	bobCaesarRsaPrvKey := rs.NewPrivateKey(*bobRsaPrvKey)

	bobEcdsaPrvKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEcdsaPubKey := &bobEcdsaPrvKey.PublicKey
	bobEcdsaSshPubKey, err := ssh.NewPublicKey(bobEcdsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarEcdsaPubKey := ec.NewPublicKey(*bobEcdsaPubKey, bobEcdsaSshPubKey)
	bobCaesarEcdsaPrvKey := ec.NewPrivateKey(*bobEcdsaPrvKey)

	bobEd25519PubKey, bobEd25519PrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEd25519SshPubKey, err := ssh.NewPublicKey(bobEd25519PubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarEd25519PubKey := ed.NewPublicKey(bobEd25519PubKey, bobEd25519SshPubKey)
	bobCaesarEd25519PrvKey := ed.NewPrivateKey(bobEd25519PrvKey)

	bobPubKeys := []caesar.PublicKey{bobCaesarRsaPubKey, bobCaesarEcdsaPubKey, bobCaesarEd25519PubKey}

	bobAuthKeyString := ""
	for _, pubKey := range bobPubKeys {
		authKey := pubKey.GetAuthKey()
		bobAuthKeyString += authKey + "\n"
	}

	message := []byte("hello world")

	zipBytes, err := encrypt("1", bobPubKeys, aliceCaesarPrvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	// rsa
	rasMessage, err := decrypt(alicePubKeys, bobCaesarRsaPrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, rasMessage) {
		t.Fatal(hex.Dump(rasMessage))
	}

	// ecdsa
	ecdsaMessage, err := decrypt(alicePubKeys, bobCaesarEcdsaPrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, ecdsaMessage) {
		t.Fatal(hex.Dump(ecdsaMessage))
	}

	// ed25519
	ed25519Message, err := decrypt(alicePubKeys, bobCaesarEd25519PrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, ed25519Message) {
		t.Fatal(hex.Dump(ed25519Message))
	}
}

func Test_encrypt_decrypt_ed25519_V1(t *testing.T) {

	alicePubKey, alicePrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceSshPubKey, err := ssh.NewPublicKey(alicePubKey)
	if err != nil {
		t.Fatal(err)
	}
	aliceCaesarPubKey := ed.NewPublicKey(alicePubKey, aliceSshPubKey)
	aliceCaesarPrvKey := ed.NewPrivateKey(alicePrvKey)
	alicePubKeys := []caesar.PublicKey{aliceCaesarPubKey}

	bobRsaPrvKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	bobRsaPubKey := &bobRsaPrvKey.PublicKey
	bobRsaSshPubKey, err := ssh.NewPublicKey(bobRsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarRsaPubKey := rs.NewPublicKey(*bobRsaPubKey, bobRsaSshPubKey)
	bobCaesarRsaPrvKey := rs.NewPrivateKey(*bobRsaPrvKey)

	bobEcdsaPrvKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEcdsaPubKey := &bobEcdsaPrvKey.PublicKey
	bobEcdsaSshPubKey, err := ssh.NewPublicKey(bobEcdsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarEcdsaPubKey := ec.NewPublicKey(*bobEcdsaPubKey, bobEcdsaSshPubKey)
	bobCaesarEcdsaPrvKey := ec.NewPrivateKey(*bobEcdsaPrvKey)

	bobEd25519PubKey, bobEd25519PrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEd25519SshPubKey, err := ssh.NewPublicKey(bobEd25519PubKey)
	if err != nil {
		t.Fatal(err)
	}
	bobCaesarEd25519PubKey := ed.NewPublicKey(bobEd25519PubKey, bobEd25519SshPubKey)
	bobCaesarEd25519PrvKey := ed.NewPrivateKey(bobEd25519PrvKey)

	bobPubKeys := []caesar.PublicKey{bobCaesarRsaPubKey, bobCaesarEcdsaPubKey, bobCaesarEd25519PubKey}

	bobAuthKeyString := ""
	for _, pubKey := range bobPubKeys {
		authKey := pubKey.GetAuthKey()
		bobAuthKeyString += authKey + "\n"
	}

	message := []byte("hello world")

	zipBytes, err := encrypt("1", bobPubKeys, aliceCaesarPrvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	// rsa
	rasMessage, err := decrypt(alicePubKeys, bobCaesarRsaPrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, rasMessage) {
		t.Fatal(hex.Dump(rasMessage))
	}

	// ecdsa
	ecdsaMessage, err := decrypt(alicePubKeys, bobCaesarEcdsaPrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, ecdsaMessage) {
		t.Fatal(hex.Dump(ecdsaMessage))
	}

	// ed25519
	ed25519Message, err := decrypt(alicePubKeys, bobCaesarEd25519PrvKey, zipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, ed25519Message) {
		t.Fatal(hex.Dump(ed25519Message))
	}
}
