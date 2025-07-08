package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"

	"github.com/yoshi389111/git-caesar/caesar/aes"
	"golang.org/x/crypto/ssh"
)

func toCurve(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case "P256":
		return elliptic.P256(), nil
	case "P384":
		return elliptic.P384(), nil
	case "P521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unknown curve: %s", curveName)
	}
}

func Test_Encrypt_Decrypt_ecdsa(t *testing.T) {
	cases := map[string]struct {
		curveName     string
		formatVersion string
	}{
		"ecdsa256_formatVer1": {"P256", "1"},
		"ecdsa256_formatVer2": {"P256", "2"},

		"ecdsa256_formatVer3": {"P256", "3"},
		"ecdsa384_formatVer3": {"P384", "3"},
		"ecdsa521_formatVer3": {"P521", "3"},
	}

	message := []byte("hello world --------------- 0256") // 32byte
	for name, tc := range cases {
		t.Run("Encrypt_Decrypt_"+name, func(t *testing.T) {
			curve, err := toCurve(tc.curveName)
			if err != nil {
				t.Fatal(err)
			}

			alicePrvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			alicePubKey := &alicePrvKey.PublicKey

			ciphertext, bobPubKey, err := Encrypt(tc.formatVersion, alicePubKey, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			ciphertext2, bobPubKey2, err := Encrypt(tc.formatVersion, alicePubKey, []byte(message))
			if err != nil {
				t.Fatal(err)
			}

			// encryption should produce non-deterministic ciphertexts due to random padding.
			if bytes.Equal(ciphertext, ciphertext2) {
				t.Fatal("ciphertexts should not be equal")
			}

			plaintext, err := Decrypt(tc.formatVersion, alicePrvKey, bobPubKey, ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext) {
				t.Fatalf("decrypted message mismatch:\nexpected: %x\nactual: %x", message, plaintext)
			}

			plaintext2, err := Decrypt(tc.formatVersion, alicePrvKey, bobPubKey2, ciphertext2)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(message, plaintext2) {
				t.Fatalf("decrypted message mismatch:\nexpected: %x\nactual: %x", message, plaintext2)
			}
		})
	}
}

func Test_Sign_Verify_ecdsa(t *testing.T) {
	cases := map[string]struct {
		curveName     string
		formatVersion string
	}{
		"ecdsa256_formatVer1": {"P256", "1"},
		"ecdsa256_formatVer2": {"P256", "2"},

		"ecdsa256_formatVer3": {"P256", "3"},
		"ecdsa384_formatVer3": {"P384", "3"},
		"ecdsa521_formatVer3": {"P521", "3"},
	}

	message := []byte("hello world --------------- 0521")
	for name, tc := range cases {
		t.Run("Sign_Verify_"+name, func(t *testing.T) {
			curve, err := toCurve(tc.curveName)
			if err != nil {
				t.Fatal(err)
			}
			prvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
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
		curveName     string
		formatVersion string
	}{
		"ecdsa256_formatVer1": {"P256", "1"},
		"ecdsa256_formatVer2": {"P256", "2"},

		"ecdsa256_formatVer3": {"P256", "3"},
		"ecdsa384_formatVer3": {"P384", "3"},
		"ecdsa521_formatVer3": {"P521", "3"},
	}

	message := []byte("hello world --------------- 1024") // 32byte
	for name, tc := range cases {
		t.Run("NewEnvelope_ExtractShareKey_"+name, func(t *testing.T) {
			curve, err := toCurve(tc.curveName)
			if err != nil {
				t.Fatal(err)
			}
			prvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
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

			envelope, err := ecdsaPubKey.NewEnvelope(tc.formatVersion, message)
			if err != nil {
				t.Fatal(err)
			}

			decrypted, err := ecdsaPrvKey.ExtractShareKey(tc.formatVersion, envelope)
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
		curveName     string
		formatVersion string
	}{
		"ecdsa256_formatVer1": {"P256", "1"},
		"ecdsa256_formatVer2": {"P256", "2"},

		"ecdsa256_formatVer3": {"P256", "3"},
		"ecdsa384_formatVer3": {"P384", "3"},
		"ecdsa521_formatVer3": {"P521", "3"},
	}

	message := []byte("hello world --------------- 1024") // 32byte

	for name, tc := range cases {
		t.Run("PrivateKeySign_PublicKeyVerify_"+name, func(t *testing.T) {
			curve, err := toCurve(tc.curveName)
			if err != nil {
				t.Fatal(err)
			}
			prvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
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

			sig, err := ecdsaPrvKey.Sign(tc.formatVersion, message)
			if err != nil {
				t.Fatal(err)
			}

			if !ecdsaPubKey.Verify(tc.formatVersion, message, sig) {
				t.Fatal("verify failed")
			}
		})
	}
}

type sigParam struct {
	R, S *big.Int
}

func Test_Signature_Compatibility_V1(t *testing.T) {
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

	if !Verify("1", pubKey, message, sigOld) {
		t.Fatal("The signature of the old version is not verified by verifying the new version.")
	}
}

func Test_Verify_Compatibility_V1(t *testing.T) {
	message := []byte("hello world ------------- compat") // 32byte
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &prvKey.PublicKey

	hash := sha256.Sum256(message)
	sigNew, err := Sign("1", prvKey, message)
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

func Test_Encrypt_Compatibility_V1(t *testing.T) {
	message := []byte("hello world ------------- compat") // 32byte
	peerPrvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPubKey := &peerPrvKey.PublicKey

	// Encrypt using the new method
	ciphertext, tempPubKey, err := Encrypt("1", peerPubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt using the old method
	curve := peerPrvKey.Curve
	exchangedKey, _ := curve.ScalarMult(tempPubKey.X, tempPubKey.Y, peerPrvKey.D.Bytes())
	sharedKey := sha256.Sum256(exchangedKey.Bytes())
	plaintext, err := aes.Decrypt("1", sharedKey[:], ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatalf("decrypted message mismatch:\nexpected: %x\nactual: %x", message, plaintext)
	}
}

func Test_Decrypt_Compatibility_V1(t *testing.T) {
	message := []byte("hello world ------------- compat") // 32byte
	peerPrvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPubKey := &peerPrvKey.PublicKey

	// Encrypt using the old method
	curve := peerPubKey.Curve
	tempPrvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exchangedKey, _ := curve.ScalarMult(peerPubKey.X, peerPubKey.Y, tempPrvKey.D.Bytes())
	sharedKey := sha256.Sum256(exchangedKey.Bytes())
	ciphertext, err := aes.Encrypt("1", sharedKey[:], message)
	if err != nil {
		t.Fatal(err)
	}
	tempPubKey := &tempPrvKey.PublicKey

	// Decrypt using the new method
	plaintext, err := Decrypt("1", peerPrvKey, tempPubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatalf("decrypted message mismatch:\nexpected: %x\nactual: %x", message, plaintext)
	}
}
