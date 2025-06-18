package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/yoshi389111/git-caesar/caesar/aes"
	"github.com/yoshi389111/git-caesar/caesar/common"
)

// Encrypt encrypts a message using ECDH key exchange and AES-256.
func Encrypt(version string, peersPubKey *ecdsa.PublicKey, message []byte) ([]byte, *ecdsa.PublicKey, error) {
	switch version {
	case common.Version1:
		return encryptV1(version, peersPubKey, message)
	default:
		return nil, nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func encryptV1(version string, peersPubKey *ecdsa.PublicKey, message []byte) ([]byte, *ecdsa.PublicKey, error) {
	curve := peersPubKey.Curve

	// generate ephemeral private key
	ephemeralPrvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key pair for ecdsa: %w", err)
	}

	ecdhPrvKey, err := ephemeralPrvKey.ECDH()
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

	// In the case of ecdh, it is not necessary to delete leading zeros,
	// but they are deleted for backward compatibility.
	exchangedKey = new(big.Int).SetBytes(exchangedKey).Bytes()

	// When using the exchanged key as an encryption key,
	// HKDF or similar should be used instead of SHA-2,
	// but SHA-2 is used for backward compatibility.
	sharedKey := sha256.Sum256(exchangedKey)

	// encrypt AES-256
	ciphertext, err := aes.Encrypt(version, sharedKey[:], message)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to AES encryption for ecdsa: %w", err)
	}
	return ciphertext, &ephemeralPrvKey.PublicKey, nil
}

// Decrypt decrypts a message using ECDH key exchange and AES-256.
func Decrypt(version string, prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return decryptV1(version, prvKey, peersPubKey, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func decryptV1(version string, prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
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

	// In the case of ecdh, it is not necessary to delete leading zeros,
	// but they are deleted for backward compatibility.
	exchangedKey = new(big.Int).SetBytes(exchangedKey).Bytes()

	// When using the exchanged key as an encryption key,
	// HKDF or similar should be used instead of SHA-2,
	// but SHA-2 is used for backward compatibility.
	sharedKey := sha256.Sum256(exchangedKey)

	// decrypt AES-256
	return aes.Decrypt(version, sharedKey[:], ciphertext)
}

// Sign creates an ECDSA signature for the given message.
func Sign(version string, prvKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return signV1(version, prvKey, message)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func signV1(version string, prvKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	_ = version // unused parameter

	hash := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, prvKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign ecdsa: %w", err)
	}
	return sig, nil
}

// Verify checks an ECDSA signature for the given message.
func Verify(version string, pubKey *ecdsa.PublicKey, message, sig []byte) bool {
	switch version {
	case common.Version1:
		return verifyV1(version, pubKey, message, sig)
	default:
		return false // unknown version
	}
}

func verifyV1(version string, pubKey *ecdsa.PublicKey, message, sig []byte) bool {
	_ = version // unused parameter

	hash := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pubKey, hash[:], sig)
}
