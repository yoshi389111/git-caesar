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
	envelopeRsa := envelope.(Envelope)
	ciphertext, err := base64.StdEncoding.DecodeString(envelopeRsa.ShareKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to base64 decode `key` in envelope for rsa.\n\t%w", err)
	}
	return Decrypt(&p.prvKey, ciphertext)
}

func (p PrivateKey) Sign(message []byte) ([]byte, error) {
	return Sign(&p.prvKey, message)
}

func (p PrivateKey) GetAuthKey() (string, error) {
	sshPubKey, err := ssh.NewPublicKey(&p.prvKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("Failed to generate ssh.PublicKey for rsa.\n\t%w", err)
	}
	return authkeylib.ToString(sshPubKey), nil
}
