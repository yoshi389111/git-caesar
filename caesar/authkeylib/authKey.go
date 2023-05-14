package authkeylib

import "golang.org/x/crypto/ssh"

func ParseAuthKeys(bytes []byte) ([]ssh.PublicKey, error) {
	var sshPubKeys []ssh.PublicKey
	for len(bytes) > 0 {
		sshPubKey, _, _, rest, err := ssh.ParseAuthorizedKey(bytes)
		if err != nil {
			return nil, err
		}
		sshPubKeys = append(sshPubKeys, sshPubKey)
		bytes = rest
	}
	return sshPubKeys, nil
}

func ParseString(authKey string) (ssh.PublicKey, error) {
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authKey))
	if err != nil {
		return nil, err
	}
	return sshPubKey, nil
}

func ToString(sshPubKey ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(sshPubKey))
}
