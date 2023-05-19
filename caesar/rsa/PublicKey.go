package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/authkeylib"
	"golang.org/x/crypto/ssh"
)

type PublicKey struct {
	pubKey    rsa.PublicKey
	sshPubKey ssh.PublicKey
}

func NewPublicKey(pubKey rsa.PublicKey, sshPubKey ssh.PublicKey) *PublicKey {
	return &PublicKey{
		pubKey:    pubKey,
		sshPubKey: sshPubKey,
	}
}

func (p PublicKey) NewEnvelope(shareKey []byte) (caesar.Envelope, error) {
	ciphertext, err := Encrypt(&p.pubKey, shareKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to encryption for rsa.\n\t%w", err)
	}
	envelope := Envelope{
		Type:          "rsa",
		ShareKey:      base64.StdEncoding.EncodeToString(ciphertext),
		RecverAuthKey: authkeylib.ToString(p.sshPubKey),
	}

	return envelope, nil
}

func (p PublicKey) Verify(message, sig []byte) bool {
	return Verify(&p.pubKey, message, sig)
}

func (p PublicKey) GetAuthKey() string {
	return authkeylib.ToString(p.sshPubKey)
}
