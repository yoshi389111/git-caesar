package caesar

type PublicKey interface {
	NewEnvelope(shareKey []byte) (Envelope, error)

	Verify(message, sig []byte) bool

	GetAuthKey() string
}
