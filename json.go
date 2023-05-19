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
	Version   string        `json:"version"`
	Signature string        `json:"signature"`
	Signer    string        `json:"signer"`
	Envelopes []interface{} `json:"envelopes"`
}

func parseCaesarJson(bytes []byte) (*CaesarJson, error) {
	var caesarJson CaesarJson
	err := json.Unmarshal(bytes, &caesarJson)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse `caesar.json`.\n\t%w", err)
	}
	// replace `interface{}` with `Envelope`
	for i, envelope := range caesarJson.Envelopes {
		envelopeMap := envelope.(map[string]interface{})
		switch t := envelopeMap["type"].(string); t {
		case "rsa":
			caesarJson.Envelopes[i] = rsa.Unmarshal(envelopeMap)

		case "ecdsa":
			caesarJson.Envelopes[i] = ecdsa.Unmarshal(envelopeMap)

		case "ed25519":
			caesarJson.Envelopes[i] = ed25519.Unmarshal(envelopeMap)

		default:
			return nil, fmt.Errorf("Unknown envelope type `%s`", t)
		}
	}

	return &caesarJson, nil
}
