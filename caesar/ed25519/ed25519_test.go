package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_Encrypt_Decrypt(t *testing.T) {
	message := []byte("hello world --------------- 0256") // 32byte

	bobPubKey, bobPrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, alicePubKey, err := Encrypt(&bobPubKey, message)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(&bobPrvKey, alicePubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}
}

func Test_Sing_Verify(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := Sign(&prvKey, message)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(&pubKey, message, sig) {
		t.Fatal("verify failed")
	}
}

func Test_NewEnvelope_ExtractShareKey(t *testing.T) {
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

	addInfo, err := ed25519PubKey.NewEnvelope(message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ed25519PrvKey.ExtractShareKey(addInfo)
	if !bytes.Equal(message, decrypted) {
		t.Fatal(hex.Dump(decrypted))
	}
}

func Test_PrivateKeySign_PublickKeyVerify(t *testing.T) {
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

	sig, err := ed25519PrvKey.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519PubKey.Verify(message, sig) {
		t.Fatal("verify failed")
	}
}
