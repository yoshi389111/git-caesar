package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/yoshi389111/git-caesar/caesar/aes"
	"github.com/yoshi389111/git-caesar/caesar/common"
)

const (
	infoV2 = "git-caesar/ecdh-key-exchange/v2"
)

// Encrypt encrypts a message using ECDH key exchange and AES-256.
func Encrypt(version string, peersPubKey *ecdsa.PublicKey, message []byte) ([]byte, *ecdsa.PublicKey, error) {
	switch version {
	case common.Version1:
		return encryptV1(version, peersPubKey, message)
	case common.Version2, common.Version3:
		return encryptV2(version, peersPubKey, message)
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

	// key exchange
	exchangedKey, err := keyExchange(ephemeralPrvKey, peersPubKey)
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

func encryptV2(version string, peersPubKey *ecdsa.PublicKey, message []byte) ([]byte, *ecdsa.PublicKey, error) {
	curve := peersPubKey.Curve

	// generate ephemeral private key
	ephemeralPrvKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key pair for ecdsa: %w", err)
	}

	// key exchange
	exchangedKey, err := keyExchange(ephemeralPrvKey, peersPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform ECDH key exchange for ecdsa: %w", err)
	}

	salt := make([]byte, 32) // 32 bytes salt for HKDF
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt for HKDF: %w", err)
	}

	sharedKey, err := hkdf.Key(sha256.New, exchangedKey, salt, infoV2, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HKDF key for ecdsa: %w", err)
	}

	// encrypt AES-256
	ciphertext, err := aes.Encrypt(version, sharedKey[:], message)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to AES encryption for ecdsa: %w", err)
	}

	// prepend salt to ciphertext
	ciphertext = append(salt, ciphertext...)

	return ciphertext, &ephemeralPrvKey.PublicKey, nil
}

// Decrypt decrypts a message using ECDH key exchange and AES-256.
func Decrypt(version string, prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return decryptV1(version, prvKey, peersPubKey, ciphertext)
	case common.Version2, common.Version3:
		return decryptV2(version, prvKey, peersPubKey, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func decryptV1(version string, prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
	// key exchange
	exchangedKey, err := keyExchange(prvKey, peersPubKey)
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

func decryptV2(version string, prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
	// key exchange
	exchangedKey, err := keyExchange(prvKey, peersPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform ECDH key exchange for ecdsa: %w", err)
	}

	if len(ciphertext) < 32 {
		return nil, fmt.Errorf("ciphertext is too short for ecdsa decryption")
	}

	// extract salt from the beginning of the ciphertext
	salt := ciphertext[:32]

	// remove salt from ciphertext
	ciphertext = ciphertext[32:]

	// hash the exchanged key using HKDF
	sharedKey, err := hkdf.Key(sha256.New, exchangedKey, salt, infoV2, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to create HKDF key for ecdsa: %w", err)
	}

	// decrypt AES-256
	return aes.Decrypt(version, sharedKey[:], ciphertext)
}

func keyExchange(prvKey *ecdsa.PrivateKey, peersPubKey *ecdsa.PublicKey) ([]byte, error) {
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
	return exchangedKey, nil
}

// Sign creates an ECDSA signature for the given message.
func Sign(version string, prvKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	switch version {
	case common.Version1, common.Version2:
		return signV1(prvKey, message)
	case common.Version3:
		return signV3(prvKey, message)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func signV1(prvKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, prvKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign ecdsa: %w", err)
	}
	return sig, nil
}

func signV3(prvKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash, err := curveHash(message, prvKey.Curve)
	if err != nil {
		return nil, err
	}
	sig, err := ecdsa.SignASN1(rand.Reader, prvKey, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ecdsa: %w", err)
	}
	return sig, nil
}

// Verify checks an ECDSA signature for the given message.
func Verify(version string, pubKey *ecdsa.PublicKey, message, sig []byte) bool {
	switch version {
	case common.Version1, common.Version2:
		return verifyV1(pubKey, message, sig)
	case common.Version3:
		return verifyV3(pubKey, message, sig)
	default:
		return false // unknown version
	}
}

func verifyV1(pubKey *ecdsa.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pubKey, hash[:], sig)
}

func verifyV3(pubKey *ecdsa.PublicKey, message, sig []byte) bool {
	hash, err := curveHash(message, pubKey.Curve)
	if err != nil {
		return false
	}
	return ecdsa.VerifyASN1(pubKey, hash, sig)
}

func curveHash(message []byte, curve elliptic.Curve) ([]byte, error) {
	switch curve {
	case elliptic.P256():
		h := sha256.Sum256(message)
		return h[:], nil
	case elliptic.P384():
		h := sha512.Sum384(message)
		return h[:], nil
	case elliptic.P521():
		h := sha512.Sum512(message)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", curve.Params().Name)
	}
}
