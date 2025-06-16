package caesar

type PublicKey interface {
	NewEnvelope(version string, shareKey []byte) (Envelope, error)

	Verify(version string, message, sig []byte) bool

	GetAuthKey() string
}
