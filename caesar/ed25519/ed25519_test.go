package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_Encrypt_Decrypt_ed25519(t *testing.T) {
	cases := map[string]struct {
		formatVersion string
	}{
		"ed25519_formatVer1": {"1"},
		"ed25519_formatVer2": {"2"},
	}

	message := []byte("hello world --------------- 0256") // 32byte
	for name, tc := range cases {
		t.Run("Encrypt_Decrypt_"+name, func(t *testing.T) {
			bobPubKey, bobPrvKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			ciphertext, alicePubKey, err := Encrypt(tc.formatVersion, &bobPubKey, message)
			if err != nil {
				t.Fatal(err)
			}

			ciphertext2, alicePubKey2, err := Encrypt(tc.formatVersion, &bobPubKey, message)
			if err != nil {
				t.Fatal(err)
			}

			// encryption should produce non-deterministic ciphertexts due to random padding.
			if bytes.Equal(ciphertext, ciphertext2) {
				t.Fatal("ciphertexts should not be equal")
			}

			plaintext, err := Decrypt(tc.formatVersion, &bobPrvKey, alicePubKey, ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext) {
				t.Fatalf("decrypted message mismatch:\nexpected: %x\nactual: %x", message, plaintext)
			}

			plaintext2, err := Decrypt(tc.formatVersion, &bobPrvKey, alicePubKey2, ciphertext2)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext2) {
				t.Fatalf("decrypted message mismatch:\nexpected: %x\nactual: %x", message, plaintext2)
			}
		})
	}
}

func Test_Sign_Verify_V1(t *testing.T) {
	cases := map[string]struct {
		formatVersion string
	}{
		"ed25519_formatVer1": {"1"},
		"ed25519_formatVer2": {"2"},
	}

	message := []byte("hello world --------------- 0521")
	for name, tc := range cases {
		t.Run("Sign_Verify_"+name, func(t *testing.T) {
			pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			sig, err := Sign(tc.formatVersion, &prvKey, message)
			if err != nil {
				t.Fatal(err)
			}

			if !Verify(tc.formatVersion, &pubKey, message, sig) {
				t.Fatal("verify failed")
			}
		})
	}
}

func Test_NewEnvelope_ExtractShareKey(t *testing.T) {
	cases := map[string]struct {
		formatVersion string
	}{
		"ed25519_formatVer1": {"1"},
		"ed25519_formatVer2": {"2"},
	}

	message := []byte("hello world --------------- 1024") // 32byte
	for name, tc := range cases {
		t.Run("NewEnvelope_ExtractShareKey_"+name, func(t *testing.T) {
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

			addInfo, err := ed25519PubKey.NewEnvelope(tc.formatVersion, message)
			if err != nil {
				t.Fatal(err)
			}

			decrypted, err := ed25519PrvKey.ExtractShareKey(tc.formatVersion, addInfo)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, decrypted) {
				t.Fatalf("decrypted message mismatch:\nexpected: %x\nactual: %x", message, decrypted)
			}
		})
	}
}

func Test_PrivateKeySign_PublicKeyVerify(t *testing.T) {
	cases := map[string]struct {
		formatVersion string
	}{
		"ed25519_formatVer1": {"1"},
		"ed25519_formatVer2": {"2"},
	}

	message := []byte("hello world --------------- 1024") // 32byte
	for name, tc := range cases {
		t.Run("PrivateKeySign_PublicKeyVerify_"+name, func(t *testing.T) {
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

			sig, err := ed25519PrvKey.Sign(tc.formatVersion, message)
			if err != nil {
				t.Fatal(err)
			}

			if !ed25519PubKey.Verify(tc.formatVersion, message, sig) {
				t.Fatal("verify failed")
			}
		})
	}
}
