package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
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

	ecdhPrvKey, err := tempPrvKey.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ECDH private key for ecdsa: %w", err)
	}

	ecdhPubKey, err := peersPubKey.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ECDH public key for ecdsa: %w", err)
	}

	// key exchange
	exchangedKey, err := ecdhPrvKey.ECDH(ecdhPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform ECDH key exchange for ecdsa: %w", err)
	}

	sharedKey := sha256.Sum256(new(big.Int).SetBytes(exchangedKey).Bytes())

	// encrypt AES-256-CBC
	ciphertext, err := aes.Encrypt(sharedKey[:], message)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to AES encryption for ecdsa: %w", err)
	}
	return ciphertext, &tempPrvKey.PublicKey, nil
}

// Decrypt decrypts a message using ECDH key exchange and AES-256-CBC.
func Decrypt(prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
	ecdhPrvKey, err := prvKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDH private key for ecdsa: %w", err)
	}

	ecdhPubKey, err := peersPubKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDH public key for ecdsa: %w", err)
	}

	// key exchange
	exchangedKey, err := ecdhPrvKey.ECDH(ecdhPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDH key exchange for ecdsa: %w", err)
	}

	sharedKey := sha256.Sum256(new(big.Int).SetBytes(exchangedKey).Bytes())

	// decrypt AES-256-CBC
	return aes.Decrypt(sharedKey[:], ciphertext)
}

// Sign creates an ECDSA signature for the given message.
func Sign(prvKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, prvKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign ecdsa: %w", err)
	}
	return sig, nil
}

// Verify checks an ECDSA signature for the given message.
func Verify(pubKey *ecdsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pubKey, hash[:], sig)
}
