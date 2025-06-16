package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func Encrypt(version string, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	switch version {
	case "1":
		return encryptV1(version, pubKey, plaintext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func encryptV1(version string, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	_ = version // unused parameter
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, []byte{})
}

func Decrypt(version string, prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	switch version {
	case "1":
		return decryptV1(version, prvKey, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func decryptV1(version string, prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	_ = version // unused parameter
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, prvKey, ciphertext, []byte{})
}

func Sign(version string, prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	switch version {
	case "1":
		return signV1(version, prvKey, message)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func signV1(version string, prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	_ = version // unused parameter
	hash := sha256.Sum256(message)
	return rsa.SignPKCS1v15(nil, prvKey, crypto.SHA256, hash[:])
}

func Verify(version string, pubKey *rsa.PublicKey, message, sig []byte) bool {
	switch version {
	case "1":
		return verifyV1(version, pubKey, message, sig)
	default:
		return false // unknown version
	}
}

func verifyV1(version string, pubKey *rsa.PublicKey, message, sig []byte) bool {
	_ = version // unused parameter
	hash := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig)
	return err == nil
}
