package ecdsa

import (
	"crypto/ecdsa"
	"encoding/base64"

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
		return nil, err
	}
	sshPubKey, err := authkeylib.ParseString(envelopeEc.TempAuthKey)
	if err != nil {
		return nil, err
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
		return "", err
	}
	return authkeylib.ToString(sshPubKey), nil
}
