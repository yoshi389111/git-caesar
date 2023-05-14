package caesar

type PrivateKey interface {
	ExtractShareKey(envelope Envelope) ([]byte, error)

	Sign(message []byte) ([]byte, error)

	GetAuthKey() (string, error)
}
