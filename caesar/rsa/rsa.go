package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar/common"
)

const (
	LabelV2 = "git-caesar/rsa-encrypt/v2"
)

// Encrypt encrypts a message using RSA OAEP with SHA-256.
func Encrypt(version string, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return encryptV1(pubKey, plaintext)
	case common.Version2:
		return encryptV2(pubKey, plaintext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func encryptV1(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, []byte{})
}

func encryptV2(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, []byte(LabelV2))
}

// Decrypt decrypts a message using RSA OAEP with SHA-256.
func Decrypt(version string, prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return decryptV1(prvKey, ciphertext)
	case common.Version2:
		return decryptV2(prvKey, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func decryptV1(prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, prvKey, ciphertext, []byte{})
}

func decryptV2(prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, prvKey, ciphertext, []byte(LabelV2))
}

// Sign signs a message using RSA.
func Sign(version string, prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return signV1(prvKey, message)
	case common.Version2:
		return signV2(prvKey, message)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func signV1(prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return rsa.SignPKCS1v15(nil, prvKey, crypto.SHA256, hash[:])
}

func signV2(prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return rsa.SignPSS(rand.Reader, prvKey, crypto.SHA256, hash[:], nil)
}

// Verify verifies a signature using RSA.
func Verify(version string, pubKey *rsa.PublicKey, message, sig []byte) bool {
	switch version {
	case common.Version1:
		return verifyV1(pubKey, message, sig)
	case common.Version2:
		return verifyV2(pubKey, message, sig)
	default:
		return false // unknown version
	}
}

func verifyV1(pubKey *rsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig)
	return err == nil
}

func verifyV2(pubKey *rsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	err := rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], sig, nil)
	return err == nil
}
