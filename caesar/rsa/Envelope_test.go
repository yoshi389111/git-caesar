package rsa

import "testing"

func Test_Unmarshal(t *testing.T) {
	m := map[string]any{
		"type":   "ecdsa",
		"key":    "key_value",
		"dest":   "dest_value",
		"pubkey": "pubkey_vaoue",
	}

	e, err := Unmarshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != "ecdsa" {
		t.Error(e.Type)
	}
	if e.ShareKey != "key_value" {
		t.Error(e.ShareKey)
	}
	if e.RecverAuthKey != "dest_value" {
		t.Error(e.RecverAuthKey)
	}
	if e.GetDest() != "dest_value" {
		t.Error(e.RecverAuthKey)
	}
}
