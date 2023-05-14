package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/aes"
	"github.com/yoshi389111/git-caesar/iolib"
)

func encrypt(oppoPubKeys []caesar.PublicKey, prvKey caesar.PrivateKey, plaintext []byte) ([]byte, error) {

	// generate shared key (for AES-256-CBC)
	shareKey := make([]byte, 32)
	_, err := rand.Read(shareKey)
	if err != nil {
		return nil, err
	}

	// encrypt shared key per public key
	var envelopes []interface{}
	for _, oppoPubKey := range oppoPubKeys {
		envelope, err := oppoPubKey.NewEnvelope(shareKey)
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, envelope)
	}

	// encrypt the plaintext (by AES-256-CBC)
	ciphertext, err := aes.Encrypt(shareKey, plaintext)
	if err != nil {
		return nil, err
	}

	// sign the ciphertext
	sig, err := prvKey.Sign(ciphertext)
	if err != nil {
		return nil, err
	}

	// create `caesar.json`
	selfAuthKey, err := prvKey.GetAuthKey()
	if err != nil {
		return nil, err
	}
	caesarJson := &CaesarJson{
		Version:   "1",
		Signature: base64.StdEncoding.EncodeToString(sig),
		Signer:    selfAuthKey,
		Envelopes: envelopes,
	}
	jsonBytes, err := json.Marshal(caesarJson)
	if err != nil {
		return nil, err
	}

	// create zip data
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)
	err = iolib.AppendZieEntry(zipWriter, CAESAR_JSON, jsonBytes)
	if err != nil {
		return nil, err
	}
	err = iolib.AppendZieEntry(zipWriter, CAESAR_CIPHER, ciphertext)
	if err != nil {
		return nil, err
	}
	err = zipWriter.Close()
	if err != nil {
		return nil, err
	}
	zipBytes := zipBuf.Bytes()

	return zipBytes, nil
}
