package ed25519

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"math/big"

	"errors"
)

func toX25519PrivateKey(edPrvKey *ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	key := sha512.Sum512(edPrvKey.Seed())
	// ref. crypto/ecdh/x25519.go#L90_92
	// key[0] &= 248
	// key[31] &= 127
	// key[31] |= 64
	return ecdh.X25519().NewPrivateKey(key[:32])
}

// p = 2^255 - 19
var p, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
var one = big.NewInt(1)

func toX25519PublicKey(edPubKey *ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(*edPubKey) != ed25519.PublicKeySize {
		return nil, errors.New("ed25519: bad public key length")
	}

	// convert to big-endian
	bigEndianY := toReverse(*edPubKey)

	// turn off the first bit
	bigEndianY[0] &= 0b0111_1111

	y := new(big.Int).SetBytes(bigEndianY)
	numer := new(big.Int).Add(one, y)             // (1 + y)
	denom := new(big.Int).Sub(one, y)             // (1 - y)
	denomInv := new(big.Int).ModInverse(denom, p) // 1 / (1 - y)
	if denomInv == nil {
		return nil, errors.New("ed25519: public key is not valid for x25519 conversion")
	}
	u := new(big.Int).Mul(numer, denomInv) // u = (1 + y) / (1 - y)
	u.Mod(u, p)                            // u = u mod p

	// convert to little-endian
	littleEndianU := make([]byte, 32)
	u.FillBytes(littleEndianU)
	littleEndianU = toReverse(littleEndianU)

	// create x25519 public key
	return ecdh.X25519().NewPublicKey(littleEndianU)
}

func toReverse(input []byte) []byte {
	length := len(input)
	output := make([]byte, length)
	for i, b := range input {
		output[length-i-1] = b
	}
	return output
}
