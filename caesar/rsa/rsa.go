package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar/common"
)

// Encrypt encrypts a message using RSA OAEP with SHA-256.
func Encrypt(version string, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return encryptV1(pubKey, plaintext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func encryptV1(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, []byte{})
}

// Decrypt decrypts a message using RSA OAEP with SHA-256.
func Decrypt(version string, prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return decryptV1(prvKey, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func decryptV1(prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, prvKey, ciphertext, []byte{})
}

// Sign signs a message using RSA PKCS#1 v1.5 with SHA-256.
func Sign(version string, prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return signV1(prvKey, message)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func signV1(prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return rsa.SignPKCS1v15(nil, prvKey, crypto.SHA256, hash[:])
}

// Verify verifies a signature using RSA PKCS#1 v1.5 with SHA-256.
func Verify(version string, pubKey *rsa.PublicKey, message, sig []byte) bool {
	switch version {
	case common.Version1:
		return verifyV1(pubKey, message, sig)
	default:
		return false // unknown version
	}
}

func verifyV1(pubKey *rsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig)
	return err == nil
}
