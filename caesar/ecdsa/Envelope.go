package ecdsa

import "fmt"

type Envelope struct {
	Type          string `json:"type"`
	ShareKey      string `json:"key"`
	RecverAuthKey string `json:"dest"`
	TempAuthKey   string `json:"pubkey"`
}

func (a Envelope) GetDest() string {
	return a.RecverAuthKey
}

func Unmarshal(envelopeMap map[string]any) (Envelope, error) {
	var envelope Envelope
	var ok bool

	if envelope.Type, ok = envelopeMap["type"].(string); !ok {
		return envelope, fmt.Errorf("type assertion failed for 'type'")
	}
	if envelope.ShareKey, ok = envelopeMap["key"].(string); !ok {
		return envelope, fmt.Errorf("type assertion failed for 'key'")
	}
	if envelope.RecverAuthKey, ok = envelopeMap["dest"].(string); !ok {
		return envelope, fmt.Errorf("type assertion failed for 'dest'")
	}
	if envelope.TempAuthKey, ok = envelopeMap["pubkey"].(string); !ok {
		return envelope, fmt.Errorf("type assertion failed for 'pubkey'")
	}
	return envelope, nil
}
