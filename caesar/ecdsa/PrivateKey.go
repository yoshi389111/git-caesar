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
	envelopeEc := envelope.(Envelope)
	ciphertext, err := base64.StdEncoding.DecodeString(envelopeEc.ShareKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to base64 decode `key` in envelope for ecdsa.\n\t%w", err)
	}
	sshPubKey, err := authkeylib.ParseString(envelopeEc.TempAuthKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse `pubkey` in envelope for ecdsa.\n\t%w", err)
	}
	pubKey := sshPubKey.(ssh.CryptoPublicKey).CryptoPublicKey().(*ecdsa.PublicKey)
	return Decrypt(&p.prvKey, pubKey, ciphertext)
}

func (p PrivateKey) Sign(message []byte) ([]byte, error) {
	return Sign(&p.prvKey, message)
}

func (p PrivateKey) GetAuthKey() (string, error) {
	sshPubKey, err := ssh.NewPublicKey(p.prvKey.Public())
	if err != nil {
		return "", fmt.Errorf("Failed to generate ssh.PublicKey for ecdsa.\n\t%w", err)
	}
	return authkeylib.ToString(sshPubKey), nil
}
