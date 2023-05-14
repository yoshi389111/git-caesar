package ed25519

type Envelope struct {
	Type          string `json:"type"`
	ShareKey      string `json:"key"`
	RecverAuthKey string `json:"dest"`
	TempAuthKey   string `json:"pubkey"`
}

func (a Envelope) GetDest() string {
	return a.RecverAuthKey
}

func Unmarshal(envelopeMap map[string]interface{}) Envelope {
	envelope := Envelope{
		Type:          envelopeMap["type"].(string),
		ShareKey:      envelopeMap["key"].(string),
		RecverAuthKey: envelopeMap["dest"].(string),
		TempAuthKey:   envelopeMap["pubkey"].(string),
	}
	return envelope
}
