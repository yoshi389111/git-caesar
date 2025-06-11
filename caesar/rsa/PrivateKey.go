package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/authkeylib"
	"golang.org/x/crypto/ssh"
)

type PrivateKey struct {
	prvKey rsa.PrivateKey
}

func NewPrivateKey(prvKey rsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		prvKey: prvKey,
	}
}

func (p PrivateKey) ExtractShareKey(envelope caesar.Envelope) ([]byte, error) {
	envelopeRsa, ok := envelope.(Envelope)
	if !ok {
		return nil, fmt.Errorf("envelope is not of type rsa.Envelope")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelopeRsa.ShareKey)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode `key` in envelope for rsa: %w", err)
	}
	return Decrypt(&p.prvKey, ciphertext)
}

func (p PrivateKey) Sign(message []byte) ([]byte, error) {
	return Sign(&p.prvKey, message)
}

func (p PrivateKey) GetAuthKey() (string, error) {
	sshPubKey, err := ssh.NewPublicKey(&p.prvKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate ssh.PublicKey for rsa: %w", err)
	}
	return authkeylib.ToString(sshPubKey), nil
}
