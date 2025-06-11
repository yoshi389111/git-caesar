package authkeylib

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

func ParseAuthKeys(bytes []byte) ([]ssh.PublicKey, error) {
	var sshPubKeys []ssh.PublicKey
	for len(bytes) > 0 {
		sshPubKey, _, _, rest, err := ssh.ParseAuthorizedKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse authentication key: key=`%s`: %w", string(bytes), err)
		}
		sshPubKeys = append(sshPubKeys, sshPubKey)
		bytes = rest
	}
	return sshPubKeys, nil
}

func ParseString(authKey string) (ssh.PublicKey, error) {
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication key string: key=`%s`: %w", authKey, err)
	}
	return sshPubKey, nil
}

func ToString(sshPubKey ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(sshPubKey))
}
