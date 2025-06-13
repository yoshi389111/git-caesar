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
		typeName, ok := envelopeMap["type"].(string)
		if !ok {
			return nil, fmt.Errorf("envelope type is missing or not a string")
		}
		switch typeName {
		case "rsa":
			env, err := rsa.Unmarshal(envelopeMap)
			if err != nil {
				return nil, err
			}
			caesarJson.Envelopes[i] = env
		case "ecdsa":
			env, err := ecdsa.Unmarshal(envelopeMap)
			if err != nil {
				return nil, err
			}
			caesarJson.Envelopes[i] = env
		case "ed25519":
			env, err := ed25519.Unmarshal(envelopeMap)
			if err != nil {
				return nil, err
			}
			caesarJson.Envelopes[i] = env
		default:
			return nil, fmt.Errorf("unknown envelope type `%s`", typeName)
		}
	}
	return &caesarJson, nil
}
