package authkeylib

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func Test_ParseAuthKeys(t *testing.T) {

	rawContent := []byte(`
ssh-dss AAAAB3NzaC1kc3MAAACBALa2YNHK42LdnX8lMUQ+qlkMKN9unTDblQgu3QByjSzQw+f/sTBXgPxSVOEAtFF8WqgSSb49HOYSoYOwxGDY28fuSWHlw19oTRHKKVABi34gpNJB6b4Cppe6TuCTjeVfQSsgvBWW9m9FmqCrE2D81RxuoJp1or87ozuMHwzegduXAAAAFQCBq/6TN3XIxavG6t28mrkMVgFX7QAAAIBNhaJD3HRpdmLlsFokrozyuq8g51smcBR/vfRMcKuFo/2GGgDdKhUWYAS6ptAljJQ9qSkKCFe1O4u7njkqUDEEeYMvnyhYmu/ZaypHu+Vf/YZXnU6nwukewh7K8g0JvEyFFG3A/KLGpo+dOYsU2NBx8CVPVWgKX9SLbeWlx1RwNwAAAIBgzfGsgTzvMjg7i4xG7J/kMAvhN3JmbqNEbHaD57yAkTBlQYr+U0QFafG+68huDb7vsBmjxG7nvSt88G8vBTL1f3t+NFkGiBrX9kBuMl7NP/eWoILa82wWxnXVhZuB8C9ePS36Ye9S8Hygmp0APxEYEloY0BC0dqsfGZHGH7x0TQ== 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAXmYUaX/IUA74x2CSH6jBBja+JZ7CZHsr3O7yw7fG3F 
`)

	sshPubKeys, err := ParseAuthKeys(rawContent)
	if err != nil {
		t.Fatal(err)
	}

	if len(sshPubKeys) != 2 {
		t.Fatalf("len = %d", len(sshPubKeys))
	}

	if sshPubKeys[0].Type() != "ssh-dss" {
		t.Errorf("sshPubKeys[0].Type() = %s", sshPubKeys[0].Type())
	}
	if sshPubKeys[1].Type() != "ssh-ed25519" {
		t.Errorf("sshPubKeys[1].Type() = %s", sshPubKeys[1].Type())
	}
}

func Test_ParseString(t *testing.T) {

	authKeyString := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAXmYUaX/IUA74x2CSH6jBBja+JZ7CZHsr3O7yw7fG3F 
	`

	sshPubKey, err := ParseString(authKeyString)
	if err != nil {
		t.Fatal(err)
	}

	if sshPubKey.Type() != "ssh-ed25519" {
		t.Fatalf("sshPubKey.Type() = %s", sshPubKey.Type())
	}
}

func Test_ToString(t *testing.T) {

	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPubKey, err := ssh.NewPublicKey(ed25519PubKey)
	if err != nil {
		t.Fatal(err)
	}

	authKey := ToString(sshPubKey)
	if !strings.HasPrefix(authKey, "ssh-ed25519 ") {
		t.Fatal(authKey)
	}
}
