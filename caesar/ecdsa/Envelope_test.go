package ecdsa

import "testing"

func Test_Unmarshal(t *testing.T) {
	m := map[string]interface{}{
		"type":   "ecdsa",
		"key":    "key_value",
		"dest":   "dest_value",
		"pubkey": "pubkey_vaoue",
	}

	e := Unmarshal(m)
	if e.Type != "ecdsa" {
		t.Error(e.Type)
	}
	if e.ShareKey != "key_value" {
		t.Error(e.ShareKey)
	}
	if e.RecverAuthKey != "dest_value" {
		t.Error(e.RecverAuthKey)
	}
	if e.TempAuthKey != "pubkey_vaoue" {
		t.Error(e.TempAuthKey)
	}
	if e.GetDest() != "dest_value" {
		t.Error(e.RecverAuthKey)
	}
}
