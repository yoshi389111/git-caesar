package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/yoshi389111/git-caesar/caesar"
	"github.com/yoshi389111/git-caesar/caesar/aes"
	"github.com/yoshi389111/git-caesar/iolib"
)

func encrypt(peerPubKeys []caesar.PublicKey, prvKey caesar.PrivateKey, plaintext []byte) ([]byte, error) {

	// generate shared key (for AES-256-CBC)
	shareKey := make([]byte, 32)
	_, err := rand.Read(shareKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to get random number (shared key).\n\t%w", err)
	}

	// encrypt shared key per public key
	var envelopes []interface{}
	for _, peerPubKey := range peerPubKeys {
		envelope, err := peerPubKey.NewEnvelope(shareKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to create envelope.\n\t%w", err)
		}
		envelopes = append(envelopes, envelope)
	}

	// encrypt the plaintext (by AES-256-CBC)
	ciphertext, err := aes.Encrypt(shareKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("AES encryption failed.\n\t%w", err)
	}

	// sign the ciphertext
	sig, err := prvKey.Sign(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign.\n\t%w", err)
	}

	// create `caesar.json`
	selfAuthKey, err := prvKey.GetAuthKey()
	if err != nil {
		return nil, fmt.Errorf("The authentication key could not be obtained from the private key during encryption.\n\t%w", err)
	}
	caesarJson := &CaesarJson{
		Version:   "1",
		Signature: base64.StdEncoding.EncodeToString(sig),
		Signer:    selfAuthKey,
		Envelopes: envelopes,
	}
	jsonBytes, err := json.Marshal(caesarJson)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal `caesar.json`.\n\t%w", err)
	}

	// create zip data
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)
	err = iolib.AppendZieEntry(zipWriter, CAESAR_JSON, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to add `caesar.json` entry to ZIP file.\n\t%w", err)
	}
	err = iolib.AppendZieEntry(zipWriter, CAESAR_CIPHER, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Failed to add `caesar.cipher` entry to ZIP file.\n\t%w", err)
	}
	err = zipWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to create ZIP file.\n\t%w", err)
	}
	zipBytes := zipBuf.Bytes()

	return zipBytes, nil
}
