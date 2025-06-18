package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_Encrypt_Decrypt_V1(t *testing.T) {
	message := []byte("hello world --------------- 0256") // 32byte

	bobPubKey, bobPrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, alicePubKey, err := Encrypt("1", &bobPubKey, message)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext2, alicePubKey2, err := Encrypt("1", &bobPubKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext, ciphertext2) {
		t.Fatal("ciphertexts should not be equal")
	}

	plaintext, err := Decrypt("1", &bobPrvKey, alicePubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}

	plaintext2, err := Decrypt("1", &bobPrvKey, alicePubKey2, ciphertext2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext2) {
		t.Fatal(hex.Dump(plaintext2))
	}
}

func Test_Sign_Verify_V1(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign("1", &prvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify("1", &pubKey, message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_Sign_Verify_V2(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign("2", &prvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify("2", &pubKey, message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_NewEnvelope_ExtractShareKey_V1(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	ed25519PrvKey := NewPrivateKey(prvKey)
	ed25519PubKey := NewPublicKey(pubKey, sshPubKey)

	addInfo, err := ed25519PubKey.NewEnvelope("1", message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ed25519PrvKey.ExtractShareKey("1", addInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, decrypted) {
		t.Fatal(hex.Dump(decrypted))
	}
}

func Test_PrivateKeySign_PublickKeyVerify_V1(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	ed25519PrvKey := NewPrivateKey(prvKey)
	ed25519PubKey := NewPublicKey(pubKey, sshPubKey)

	sig, err := ed25519PrvKey.Sign("1", message)
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519PubKey.Verify("1", message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_PrivateKeySign_PublickKeyVerify_V2(t *testing.T) {
	message := []byte("hello world --------------- 1024") // 32byte

	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	ed25519PrvKey := NewPrivateKey(prvKey)
	ed25519PubKey := NewPublicKey(pubKey, sshPubKey)

	sig, err := ed25519PrvKey.Sign("2", message)
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519PubKey.Verify("2", message, sig) {
		t.Fatal("verify failed")
	}
}
