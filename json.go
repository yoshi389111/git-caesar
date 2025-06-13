package main

import (
	"encoding/json"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar/ecdsa"
	"github.com/yoshi389111/git-caesar/caesar/ed25519"
	"github.com/yoshi389111/git-caesar/caesar/rsa"
)

const (
	CAESAR_JSON   = "caesar.json"
	CAESAR_CIPHER = "caesar.cipher"
)

type CaesarJson struct {
	Version   string `json:"version"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
	Envelopes []any  `json:"envelopes"`
}

func parseCaesarJson(rawContent []byte) (*CaesarJson, error) {
	var caesarJson CaesarJson
	err := json.Unmarshal(rawContent, &caesarJson)
	if err != nil {
		return nil, fmt.Errorf("failed to parse `caesar.json`: %w", err)
	}
	// replace `any` with `Envelope`
	for i, envelope := range caesarJson.Envelopes {
		envelopeMap, ok := envelope.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid envelope format in caesar.json")
		}
		t, ok := envelopeMap["type"].(string)
		if !ok {
			return nil, fmt.Errorf("envelope type is missing or not a string")
		}
		switch t {
		case "rsa":
			caesarJson.Envelopes[i] = rsa.Unmarshal(envelopeMap)
		case "ecdsa":
			caesarJson.Envelopes[i] = ecdsa.Unmarshal(envelopeMap)
		case "ed25519":
			caesarJson.Envelopes[i] = ed25519.Unmarshal(envelopeMap)
		default:
			return nil, fmt.Errorf("unknown envelope type `%s`", t)
		}
	}
	return &caesarJson, nil
}
