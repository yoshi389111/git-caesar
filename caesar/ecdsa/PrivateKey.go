package ecdsa

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/authkeylib"
	"golang.org/x/crypto/ssh"
)

type PrivateKey struct {
	prvKey ecdsa.PrivateKey
}

func NewPrivateKey(prvKey ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		prvKey: prvKey,
	}
}

func (p PrivateKey) ExtractShareKey(envelope caesar.Envelope) ([]byte, error) {
	envelopeEc, ok := envelope.(Envelope)
	if !ok {
		return nil, fmt.Errorf("envelope is not of type ecdsa.Envelope")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelopeEc.ShareKey)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode `key` in envelope for ecdsa: %w", err)
	}
	sshPubKey, err := authkeylib.ParseString(envelopeEc.TempAuthKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse `pubkey` in envelope for ecdsa: %w", err)
	}
	cryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed pubkey is not ssh.CryptoPublicKey")
	}
	pubKey, ok := cryptoPubKey.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto public key is not *ecdsa.PublicKey")
	}
	return Decrypt(&p.prvKey, pubKey, ciphertext)
}

func (p PrivateKey) Sign(message []byte) ([]byte, error) {
	return Sign(&p.prvKey, message)
}

func (p PrivateKey) GetAuthKey() (string, error) {
	sshPubKey, err := ssh.NewPublicKey(p.prvKey.Public())
	if err != nil {
		return "", fmt.Errorf("failed to generate ssh.PublicKey for ecdsa: %w", err)
	}
	return authkeylib.ToString(sshPubKey), nil
}
