package pubkeylib

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

func generateRSAPublicKey(t *testing.T) ssh.PublicKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func generateECDSAPublicKey(t *testing.T) ssh.PublicKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func generateEd25519PublicKey(t *testing.T) ssh.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func Test_GetPubKeys_MultiType(t *testing.T) {
	pubkeys := []ssh.PublicKey{
		generateRSAPublicKey(t),
		generateECDSAPublicKey(t),
		generateEd25519PublicKey(t),
	}

	var authKeys string
	for _, pk := range pubkeys {
		authKeys += string(ssh.MarshalAuthorizedKey(pk))
	}

	tmpfile, err := os.CreateTemp("", "pubkeys")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if err := os.WriteFile(tmpfile.Name(), []byte(authKeys), 0600); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	keys, err := GetPubKeys(tmpfile.Name())
	if err != nil {
		t.Fatalf("GetPubKeys failed: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("Expected 3 keys, got %d", len(keys))
	}
}
