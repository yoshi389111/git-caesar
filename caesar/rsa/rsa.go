package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func Encrypt(pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, []byte{})
}

func Decrypt(prvKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, prvKey, ciphertext, []byte{})
}

func Sign(prvKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, prvKey, crypto.SHA256, hash[:])
}

func Verify(pubKey *rsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig)
	return err == nil
}
