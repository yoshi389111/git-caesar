package caesar

type Envelope interface {
	// get the recipient's authkey
	GetDest() string
}
