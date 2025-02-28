package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func Test_toX25519PublicKey_fix_issue4(t *testing.T) {
	pubGolden, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	for index, test := range []*ed25519.PublicKey{
		// control (generated key)
		&pubGolden,
		// x25519: 0xFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00
		// u = 2^252-2 corresponds to y = (u-1)/(u+1) = (2^251-1)/(2^251) = 1-2^(-251)
		{
			0x09, 0x5d, 0x74, 0xd1, 0x45, 0x17, 0x5d, 0x74,
			0xd1, 0x45, 0x17, 0x5d, 0x74, 0xd1, 0x45, 0x17,
			0x5d, 0x74, 0xd1, 0x45, 0x17, 0x5d, 0x74, 0xd1,
			0x45, 0x17, 0x5d, 0x74, 0xd1, 0x45, 0x17, 0x5d,
		},
		// x25519: 0x0300000000000000000000000000000000000000000000000000000000000000
		// u = 3 corresponds to y = (u-1)/(u+1) = 1/2 = (p+1)/2
		{
			0xf7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
		},
	} {
		// Require no error
		_, err := toX25519PublicKey(test)
		if err != nil {
			t.Fatalf("#%d failed: a valid pub key with trailing zeros should not cause an error. %v",
				index+1, err)
		}
	}
}

func Test_toX25519PublicKey_errors_with_invalid_length_keys(t *testing.T) {
	t.Run("invalid length", func(t *testing.T) {
		lengths := []int{0, 1, 31, 33, 64}
		for _, length := range lengths {
			badKey := ed25519.PublicKey(bytes.Repeat([]byte{0xFF}, length))

			// Require error
			_, err := toX25519PublicKey(&badKey)
			if err == nil {
				t.Fatalf("key length not equal to 32 should cause an error")
			}
		}
	})
}
