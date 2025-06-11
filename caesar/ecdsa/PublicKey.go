package ecdsa

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/authkeylib"
	"golang.org/x/crypto/ssh"
)

type PublicKey struct {
	pubKey    ecdsa.PublicKey
	sshPubKey ssh.PublicKey
}

func NewPublicKey(pubKey ecdsa.PublicKey, sshPubKey ssh.PublicKey) *PublicKey {
	return &PublicKey{
		pubKey:    pubKey,
		sshPubKey: sshPubKey,
	}
}

func (p PublicKey) NewEnvelope(shareKey []byte) (caesar.Envelope, error) {
	ciphertext, tempPubKey, err := Encrypt(&p.pubKey, shareKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt for ecdsa: %w", err)
	}
	senderSSHPubKey, err := ssh.NewPublicKey(tempPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sender's ssh.PublicKey for ecdsa: %w", err)
	}
	envelope := Envelope{
		Type:          "ecdsa",
		ShareKey:      base64.StdEncoding.EncodeToString(ciphertext),
		RecverAuthKey: authkeylib.ToString(p.sshPubKey),
		TempAuthKey:   authkeylib.ToString(senderSSHPubKey),
	}

	return envelope, nil
}

func (p PublicKey) Verify(message, sig []byte) bool {
	return Verify(&p.pubKey, message, sig)
}

func (p PublicKey) GetAuthKey() string {
	return authkeylib.ToString(p.sshPubKey)
}
