package pubkeylib

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/authkeylib"
	ec "github.com/yoshi389111/git-caesar/caesar/ecdsa"
	ed "github.com/yoshi389111/git-caesar/caesar/ed25519"
	rs "github.com/yoshi389111/git-caesar/caesar/rsa"
	"github.com/yoshi389111/git-caesar/iolib"
	"golang.org/x/crypto/ssh"
)

func ToCaesarPubKey(sshPubKey ssh.PublicKey) caesar.PublicKey {
	sshCryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil
	}
	cryptoPubKey := sshCryptoPubKey.CryptoPublicKey()
	if rsaPubKey, ok := cryptoPubKey.(*rsa.PublicKey); ok {
		if 1024 <= rsaPubKey.N.BitLen() {
			return rs.NewPublicKey(*rsaPubKey, sshPubKey)
		}
	} else if ecdsaPubKey, ok := cryptoPubKey.(*ecdsa.PublicKey); ok {
		return ec.NewPublicKey(*ecdsaPubKey, sshPubKey)
	} else if ed25519PubKey, ok := cryptoPubKey.(ed25519.PublicKey); ok {
		return ed.NewPublicKey(ed25519PubKey, sshPubKey)
	}
	return nil
}

func ParseAuthKey(authKey string) (caesar.PublicKey, error) {
	sshPubKey, err := authkeylib.ParseString(authKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse authentication key. authKey=`%s`\n\t%w", authKey, err)
	}
	return ToCaesarPubKey(sshPubKey), nil
}

func GetPubKeys(target string) ([]caesar.PublicKey, error) {
	if target == "" {
		// Returns `nil` as it is not required during decryption.
		return nil, nil
	}

	bytes, err := readTarget(target)
	if err != nil {
		return nil, fmt.Errorf("Failed to get public key. target=`%s`\n\t%w", target, err)
	}

	sshPubKeys, err := authkeylib.ParseAuthKeys(bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key. target=`%s`\n\t%w", target, err)
	}

	pubKeyList := make([]caesar.PublicKey, 0)
	for _, sshPubKey := range sshPubKeys {
		sshCryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey)
		if !ok {
			continue
		}
		cryptoPubKey := sshCryptoPubKey.CryptoPublicKey()
		if rsaPubKey, ok := cryptoPubKey.(rsa.PublicKey); ok {
			if 1024 <= rsaPubKey.N.BitLen() {
				pubKeyList = append(pubKeyList, rs.NewPublicKey(rsaPubKey, sshPubKey))
			}
		} else if ecdsaPubKey, ok := cryptoPubKey.(ecdsa.PublicKey); ok {
			pubKeyList = append(pubKeyList, ec.NewPublicKey(ecdsaPubKey, sshPubKey))
		} else if ed25519PubKey, ok := cryptoPubKey.(ed25519.PublicKey); ok {
			pubKeyList = append(pubKeyList, ed.NewPublicKey(ed25519PubKey, sshPubKey))
		}
	}
	return pubKeyList, nil
}

func readTarget(target string) ([]byte, error) {
	if strings.HasPrefix(target, "http:") || strings.HasPrefix(target, "https:") {
		// uri
		return iolib.FetchContent(target)
	} else if IsGithubAccount(target) {
		// account name of GitHub
		uri := fmt.Sprintf("https://github.com/%s.keys", target)
		return iolib.FetchContent(uri)
	} else {
		// file path
		return iolib.ReadFile(target)
	}
}
