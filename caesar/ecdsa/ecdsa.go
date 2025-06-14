package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/yoshi389111/git-caesar/caesar/aes"
)

// Encrypt encrypts a message using ECDH key exchange and AES-256-CBC.
// Returns the ciphertext and the ephemeral public key.
func Encrypt(peersPubKey *ecdsa.PublicKey, message []byte) ([]byte, *ecdsa.PublicKey, error) {
	curve := peersPubKey.Curve

	// generate temporary private key
	tempPrvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key pair for ecdsa: %w", err)
	}

	// key exchange
	// Perform ECDH key exchange: use only the X coordinate as the shared secret (standard practice).
	exchangedKey, _ := curve.ScalarMult(peersPubKey.X, peersPubKey.Y, tempPrvKey.D.Bytes())
	sharedKey := sha256.Sum256(exchangedKey.Bytes())

	// encrypt AES-256-CBC
	ciphertext, err := aes.Encrypt(sharedKey[:], message)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to AES encryption for ecdsa: %w", err)
	}
	return ciphertext, &tempPrvKey.PublicKey, nil
}

// Decrypt decrypts a message using ECDH key exchange and AES-256-CBC.
func Decrypt(prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
	curve := prvKey.Curve

	// key exchange
	exchangedKey, _ := curve.ScalarMult(peersPubKey.X, peersPubKey.Y, prvKey.D.Bytes())
	sharedKey := sha256.Sum256(exchangedKey.Bytes())

	// decrypt AES-256-CBC
	return aes.Decrypt(sharedKey[:], ciphertext)
}

// sigParam is used for ASN.1 encoding/decoding of ECDSA signatures.
type sigParam struct {
	R, S *big.Int
}

// Sign creates an ECDSA signature for the given message.
func Sign(prvKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, prvKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign ecdsa: %w", err)
	}
	sig, err := asn1.Marshal(sigParam{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("failed to ecdsa signature marshalling: %w", err)
	}
	return sig, nil
}

// Verify checks an ECDSA signature for the given message.
func Verify(pubKey *ecdsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	signature := &sigParam{}
	_, err := asn1.Unmarshal(sig, signature)
	if err != nil {
		return false
	}
	return ecdsa.Verify(pubKey, hash[:], signature.R, signature.S)
}
