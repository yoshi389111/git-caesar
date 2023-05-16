package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/aes"
	"github.com/yoshi389111/git-caesar/caesar/pubkeylib"
	"github.com/yoshi389111/git-caesar/iolib"
)

func decrypt(peerPubKeys []caesar.PublicKey, prvKey caesar.PrivateKey, ciphertext []byte) ([]byte, error) {

	// extract ZIP file
	zipReader, err := zip.NewReader(bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err != nil {
		return nil, err
	}
	caesarJsonBytes, err := iolib.ExtractZipEntry(zipReader, CAESAR_JSON)
	if err != nil {
		return nil, err
	}
	caesarCipher, err := iolib.ExtractZipEntry(zipReader, CAESAR_CIPHER)
	if err != nil {
		return nil, err
	}

	// unmarshal `caesar.json`
	caesarJson, err := parseCaesarJson(caesarJsonBytes)
	if err != nil {
		return nil, err
	}

	// version validation
	if caesarJson.Version != "1" {
		return nil, fmt.Errorf("Unknown json version `%s`", caesarJson.Version)
	}

	// existence check of sender's public key
	if peerPubKeys != nil {
		verifySender := false
		for _, peerPubKey := range peerPubKeys {
			if peerPubKey.GetAuthKey() == caesarJson.Signer {
				verifySender = true
				break
			}
		}
		if !verifySender {
			return nil, errors.New("not find sender publicKey")
		}
	}

	// verify signature
	peerPubKey, err := pubkeylib.ParseAuthKey(caesarJson.Signer)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(caesarJson.Signature)
	if err != nil {
		return nil, err
	}
	if !peerPubKey.Verify(caesarCipher, sig) {
		return nil, errors.New("signature verification failed")
	}

	// find the envelope corresponding to self private key
	selfAuthKey, err := prvKey.GetAuthKey()
	if err != nil {
		return nil, err
	}
	var targetEnvelope caesar.Envelope
	for _, rawEnvelope := range caesarJson.Envelopes {
		envelope := rawEnvelope.(caesar.Envelope)
		if envelope.GetDest() == selfAuthKey {
			targetEnvelope = envelope
			break
		}
	}
	if targetEnvelope == nil {
		return nil, errors.New("not find corresponding a envelope")
	}

	// key exchange
	shareKey, err := prvKey.ExtractShareKey(targetEnvelope)
	if err != nil {
		return nil, err
	}

	// decrypt `caesar.cipher`
	plaintext, err := aes.Decrypt(shareKey, caesarCipher)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
