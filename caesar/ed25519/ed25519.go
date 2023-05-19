package ed25519

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar/aes"
)

func Encrypt(otherPubKey *ed25519.PublicKey, message []byte) ([]byte, *ed25519.PublicKey, error) {

	// generate temporary key pair
	tempEdPubKey, tempEdPrvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate ephemeral key pair for ed25519.\n\t%w", err)
	}

	// convert ed25519 public key to x25519 public key
	xOtherPubKey, err := toX25519PublicKey(otherPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to convert X25519 to public key.\n\t%w", err)
	}

	// convert ed25519 prevate key to x25519 prevate key
	xPrvKey, err := toX2519PrivateKey(&tempEdPrvKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to convert X25519 to private key.\n\t%w", err)
	}

	// key exchange
	sharedKey, err := exchangeKey(xPrvKey, xOtherPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to X25519 key exchange.\n\t%w", err)
	}

	// encrypt AES-256-CBC
	ciphertext, err := aes.Encrypt(sharedKey, message)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to AES encryption for ed25519.\n\t%w", err)
	}
	return ciphertext, &tempEdPubKey, nil
}

func Decrypt(prvKey *ed25519.PrivateKey, otherPubKey *ed25519.PublicKey, ciphertext []byte) ([]byte, error) {

	// convert ed25519 public key to x25519 public key
	xOtherPubKey, err := toX25519PublicKey(otherPubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert X25519 to public key.\n\t%w", err)
	}

	// convert ed25519 prevate key to x25519 prevate key
	xPrvKey, err := toX2519PrivateKey(prvKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert X25519 to private key.\n\t%w", err)
	}

	// key exchange
	sharedKey, err := exchangeKey(xPrvKey, xOtherPubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to X25519 key exchange.\n\t%w", err)
	}

	// decrypt AES-256-CBC
	return aes.Decrypt(sharedKey, ciphertext)
}

func exchangeKey(xPrvKey *ecdh.PrivateKey, xPubKey *ecdh.PublicKey) ([]byte, error) {
	exchangedKey, err := xPrvKey.ECDH(xPubKey)
	if err != nil {
		return nil, err // don't wrap
	}
	sharedKey := sha256.Sum256(exchangedKey)
	return sharedKey[:], nil
}

func Sign(prvKey *ed25519.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	sig := ed25519.Sign(*prvKey, hash[:])
	return sig, nil
}

func Verify(pubKey *ed25519.PublicKey, message, sig []byte) bool {
	hash := sha256.Sum256(message)
	return ed25519.Verify(*pubKey, hash[:], sig)
}
