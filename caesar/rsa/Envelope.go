package rsa

type Envelope struct {
	Type          string `json:"type"`
	ShareKey      string `json:"key"`
	RecverAuthKey string `json:"dest"`
}

func (a Envelope) GetDest() string {
	return a.RecverAuthKey
}

func Unmarshal(envelopeMap map[string]any) Envelope {
	envelope := Envelope{
		Type:          envelopeMap["type"].(string),
		ShareKey:      envelopeMap["key"].(string),
		RecverAuthKey: envelopeMap["dest"].(string),
	}
	return envelope
}
