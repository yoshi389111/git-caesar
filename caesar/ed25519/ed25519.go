package ed25519

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar/aes"
	"github.com/yoshi389111/git-caesar/caesar/common"
)

const (
	infoV2 = "git-caesar/ed25519-key-exchange/v2"
)

// Encrypt encrypts a message using X25519 key exchange and AES-256.
func Encrypt(version string, peerPubKey *ed25519.PublicKey, message []byte) ([]byte, *ed25519.PublicKey, error) {
	switch version {
	case common.Version1:
		return encryptV1(version, peerPubKey, message)
	case common.Version2:
		return encryptV2(version, peerPubKey, message)
	default:
		return nil, nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func encryptV1(version string, peerPubKey *ed25519.PublicKey, message []byte) ([]byte, *ed25519.PublicKey, error) {
	// generate ephemeral key pair
	ephemeralEdPubKey, ephemeralEdPrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key pair for ed25519: %w", err)
	}

	// key exchange
	exchangedKey, err := exchangeKey(&ephemeralEdPrvKey, peerPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to X25519 key exchange: %w", err)
	}

	// When using the exchanged key as an encryption key,
	// HKDF or similar should be used instead of SHA-2,
	// but SHA-2 is used for backward compatibility.
	sharedKey := sha256.Sum256(exchangedKey)

	// encrypt AES-256
	ciphertext, err := aes.Encrypt(version, sharedKey[:], message)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to AES encryption for ed25519: %w", err)
	}
	return ciphertext, &ephemeralEdPubKey, nil
}

func encryptV2(version string, peerPubKey *ed25519.PublicKey, message []byte) ([]byte, *ed25519.PublicKey, error) {
	// generate ephemeral key pair
	ephemeralEdPubKey, ephemeralEdPrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key pair for ed25519: %w", err)
	}

	// key exchange
	exchangedKey, err := exchangeKey(&ephemeralEdPrvKey, peerPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to X25519 key exchange: %w", err)
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
		return nil, nil, fmt.Errorf("failed to AES encryption for ed25519: %w", err)
	}

	// prepend salt to ciphertext
	ciphertext = append(salt, ciphertext...)

	return ciphertext, &ephemeralEdPubKey, nil
}

// Decrypt decrypts a message using X25519 key exchange and AES-256.
func Decrypt(version string, prvKey *ed25519.PrivateKey, peerPubKey *ed25519.PublicKey, ciphertext []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return decryptV1(version, prvKey, peerPubKey, ciphertext)
	case common.Version2:
		return decryptV2(version, prvKey, peerPubKey, ciphertext)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func decryptV1(version string, prvKey *ed25519.PrivateKey, peerPubKey *ed25519.PublicKey, ciphertext []byte) ([]byte, error) {
	// key exchange
	exchangedKey, err := exchangeKey(prvKey, peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to X25519 key exchange: %w", err)
	}

	// When using the exchanged key as an encryption key,
	// HKDF or similar should be used instead of SHA-2,
	// but SHA-2 is used for backward compatibility.
	sharedKey := sha256.Sum256(exchangedKey)

	// decrypt AES-256-CBC
	return aes.Decrypt(version, sharedKey[:], ciphertext)
}

func decryptV2(version string, prvKey *ed25519.PrivateKey, peerPubKey *ed25519.PublicKey, ciphertext []byte) ([]byte, error) {
	// key exchange
	exchangedKey, err := exchangeKey(prvKey, peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to X25519 key exchange: %w", err)
	}

	if len(ciphertext) < 32 {
		return nil, fmt.Errorf("ciphertext is too short for ed25519 decryption")
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

	// decrypt AES-256-GCM
	return aes.Decrypt(version, sharedKey[:], ciphertext)
}

func exchangeKey(prvKey *ed25519.PrivateKey, pubKey *ed25519.PublicKey) ([]byte, error) {
	// convert ed25519 public key to x25519 public key
	xPubKey, err := toX25519PublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ed25519 public key to X25519 public key: %w", err)
	}

	// convert ed25519 private key to x25519 private key
	xPrvKey, err := toX25519PrivateKey(prvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ed25519 private key to X25519 private key: %w", err)
	}

	// perform key exchange
	exchangedKey, err := xPrvKey.ECDH(xPubKey)
	if err != nil {
		return nil, err // don't wrap
	}

	return exchangedKey[:], nil
}

// Sign creates a signature for the given message using the provided private key.
func Sign(version string, prvKey *ed25519.PrivateKey, message []byte) ([]byte, error) {
	switch version {
	case common.Version1:
		return signV1(prvKey, message)
	case common.Version2:
		return signV2(prvKey, message)
	default:
		return nil, fmt.Errorf("unknown `caesar.json` version `%s`", version)
	}
}

func signV1(prvKey *ed25519.PrivateKey, message []byte) ([]byte, error) {
	// In the case of ed25519, hashing before signing/verifying is not required,
	// but it is done for backwards compatibility.
	hash := sha256.Sum256(message)

	sig := ed25519.Sign(*prvKey, hash[:])
	return sig, nil
}

func signV2(prvKey *ed25519.PrivateKey, message []byte) ([]byte, error) {
	sig := ed25519.Sign(*prvKey, message)
	return sig, nil
}

// Verify checks if the signature is valid for the given message and public key.
func Verify(version string, pubKey *ed25519.PublicKey, message, sig []byte) bool {
	switch version {
	case common.Version1:
		return verifyV1(pubKey, message, sig)
	case common.Version2:
		return verifyV2(pubKey, message, sig)
	default:
		return false // unknown version
	}
}

func verifyV1(pubKey *ed25519.PublicKey, message, sig []byte) bool {
	// In the case of ed25519, hashing before signing/verifying is not required,
	// but it is done for backwards compatibility.
	hash := sha256.Sum256(message)

	return ed25519.Verify(*pubKey, hash[:], sig)
}

func verifyV2(pubKey *ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(*pubKey, message, sig)
}
