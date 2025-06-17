package ed25519

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/authkeylib"
	"golang.org/x/crypto/ssh"
)

type PublicKey struct {
	pubKey    ed25519.PublicKey
	sshPubKey ssh.PublicKey
}

func NewPublicKey(pubKey ed25519.PublicKey, sshPubKey ssh.PublicKey) *PublicKey {
	return &PublicKey{
		pubKey:    pubKey,
		sshPubKey: sshPubKey,
	}
}

func (p PublicKey) NewEnvelope(version string, shareKey []byte) (caesar.Envelope, error) {
	ciphertext, ephemeralPubKey, err := Encrypt(version, &p.pubKey, shareKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt for ed25519: %w", err)
	}
	senderSSHPubKey, err := ssh.NewPublicKey(*ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sender's ssh.PublicKey for ed25519: %w", err)
	}
	envelope := Envelope{
		Type:          "ed25519",
		ShareKey:      base64.StdEncoding.EncodeToString(ciphertext),
		RecverAuthKey: authkeylib.ToString(p.sshPubKey),
		TempAuthKey:   authkeylib.ToString(senderSSHPubKey),
	}

	return envelope, nil
}

func (p PublicKey) Verify(version string, message, sig []byte) bool {
	return Verify(version, &p.pubKey, message, sig)
}

func (p PublicKey) GetAuthKey() string {
	return authkeylib.ToString(p.sshPubKey)
}
