package caesar

type PrivateKey interface {
	ExtractShareKey(version string, envelope Envelope) ([]byte, error)

	Sign(version string, message []byte) ([]byte, error)

	GetAuthKey() (string, error)
}
