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

	"github.com/yoshi389111/git-caesar/caesar/aes"
	"golang.org/x/crypto/ssh"
)

func Test_Encrypt_Decrypt_P256_V1(t *testing.T) {
	message := []byte("hello world --------------- 0256") // 32byte
	alicePrvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey

	ciphertext, bobPubKey, err := Encrypt("1", alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	ciphertext2, bobPubKey2, err := Encrypt("1", alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext, ciphertext2) {
		t.Fatal("ciphertexts should not be equal")
	}

	plaintext, err := Decrypt("1", alicePrvKey, bobPubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}

	plaintext2, err := Decrypt("1", alicePrvKey, bobPubKey2, ciphertext2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext2) {
		t.Fatal(hex.Dump(plaintext2))
	}
}

func Test_Encrypt_Decrypt_P384_V1(t *testing.T) {
	message := []byte("hello world --------------- 0384") // 32byte
	alicePrvKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey

	ciphertext, bobPubKey, err := Encrypt("1", alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	ciphertext2, bobPubKey2, err := Encrypt("1", alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext, ciphertext2) {
		t.Fatal("ciphertexts should not be equal")
	}

	plaintext, err := Decrypt("1", alicePrvKey, bobPubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}

	plaintext2, err := Decrypt("1", alicePrvKey, bobPubKey2, ciphertext2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext2) {
		t.Fatal(hex.Dump(plaintext2))
	}
}

func Test_Encrypt_Decrypt_P521_V1(t *testing.T) {
	message := []byte("hello world --------------- 0521") // 32byte
	alicePrvKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePubKey := &alicePrvKey.PublicKey

	ciphertext, bobPubKey, err := Encrypt("1", alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	ciphertext2, bobPubKey2, err := Encrypt("1", alicePubKey, []byte(message))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ciphertext, ciphertext2) {
		t.Fatal("ciphertexts should not be equal")
	}

	plaintext, err := Decrypt("1", alicePrvKey, bobPubKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Fatal(hex.Dump(plaintext))
	}

	plaintext2, err := Decrypt("1", alicePrvKey, bobPubKey2, ciphertext2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, plaintext2) {
		t.Fatal(hex.Dump(plaintext2))
	}
}

func Test_Sign_Verify_P521_V1(t *testing.T) {
	message := []byte("hello world --------------- 0521")
	prvKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
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

func Test_NewEnvelope_ExtractShareKey_V1(t *testing.T) {
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

	addInfo, err := ecdsaPubKey.NewEnvelope("1", message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ecdsaPrvKey.ExtractShareKey("1", addInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, decrypted) {
		t.Fatal(hex.Dump(decrypted))
	}
}

func Test_PrivateKeySign_PublickKeyVerify_V1(t *testing.T) {
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

	sig, err := ecdsaPrvKey.Sign("1", message)
	if err != nil {
		t.Fatal(err)
	}

	if !ecdsaPubKey.Verify("1", message, sig) {
		t.Fatal("verify failed")
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
		t.Fatal(hex.Dump(plaintext))
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
		t.Fatal(hex.Dump(plaintext))
	}
}
