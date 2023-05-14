package ed25519

import (
	"crypto/ed25519"
	"encoding/base64"

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

func (p PublicKey) NewEnvelope(shareKey []byte) (caesar.Envelope, error) {
	ciphertext, tempPubKey, err := Encrypt(&p.pubKey, shareKey)
	if err != nil {
		return nil, err
	}
	senderSshPubKey, err := ssh.NewPublicKey(*tempPubKey)
	if err != nil {
		return nil, err
	}
	envelope := Envelope{
		Type:          "ed25519",
		ShareKey:      base64.StdEncoding.EncodeToString(ciphertext),
		RecverAuthKey: authkeylib.ToString(p.sshPubKey),
		TempAuthKey:   authkeylib.ToString(senderSshPubKey),
	}

	return envelope, nil
}

func (p PublicKey) Verify(message, sig []byte) bool {
	return Verify(&p.pubKey, message, sig)
}

func (p PublicKey) GetAuthKey() string {
	return authkeylib.ToString(p.sshPubKey)
}
