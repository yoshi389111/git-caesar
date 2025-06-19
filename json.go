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
		return nil, err
	}

	// format version validation
	if !IsValidCaesarJsonVersion(caesarJson.Version) {
		return nil, fmt.Errorf("unknown version `%s`", caesarJson.Version)
	}

	// replace `any` with `Envelope`
	for i, envelope := range caesarJson.Envelopes {
		envelopeMap, ok := envelope.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid format in envelope #%d", i)
		}
		typeName, ok := envelopeMap["type"].(string)
		if !ok {
			return nil, fmt.Errorf("`type` is missing in envelope #%d", i)
		}
		switch typeName {
		case "rsa":
			env, err := rsa.Unmarshal(envelopeMap)
			if err != nil {
				return nil, fmt.Errorf("invalid format in envelope #%d: %w", i, err)
			}
			caesarJson.Envelopes[i] = env
		case "ecdsa":
			env, err := ecdsa.Unmarshal(envelopeMap)
			if err != nil {
				return nil, fmt.Errorf("invalid format in envelope #%d: %w", i, err)
			}
			caesarJson.Envelopes[i] = env
		case "ed25519":
			env, err := ed25519.Unmarshal(envelopeMap)
			if err != nil {
				return nil, fmt.Errorf("invalid format in envelope #%d: %w", i, err)
			}
			caesarJson.Envelopes[i] = env
		default:
			return nil, fmt.Errorf("unknown type `%s` in envelope #%d", typeName, i)
		}
	}
	return &caesarJson, nil
}
