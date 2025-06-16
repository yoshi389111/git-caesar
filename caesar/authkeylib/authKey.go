package authkeylib

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ParseAuthKeys parses multiple SSH public keys from a byte slice (rawContent) in authorized_keys format.
func ParseAuthKeys(rawContent []byte) ([]ssh.PublicKey, error) {
	var sshPubKeys []ssh.PublicKey
	for len(rawContent) > 0 {
		sshPubKey, _, _, rest, err := ssh.ParseAuthorizedKey(rawContent)
		if err != nil {
			return nil, fmt.Errorf("failed to parse authentication key: key=`%s`: %w", string(rawContent), err)
		}
		sshPubKeys = append(sshPubKeys, sshPubKey)
		rawContent = rest
	}
	return sshPubKeys, nil
}

// ParseString parses a single SSH public key from a string in authorized_keys format.
func ParseString(authKey string) (ssh.PublicKey, error) {
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication key string: key=`%s`: %w", authKey, err)
	}
	return sshPubKey, nil
}

// ToString converts an ssh.PublicKey to the authorized_keys string format.
func ToString(sshPubKey ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(sshPubKey))
}
