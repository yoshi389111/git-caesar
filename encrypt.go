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
		return nil, fmt.Errorf("failed to get random number (shared key): %w", err)
	}

	// encrypt shared key per public key
	envelopes := make([]any, 0, len(peerPubKeys))
	for _, peerPubKey := range peerPubKeys {
		envelope, err := peerPubKey.NewEnvelope(shareKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create envelope: %w", err)
		}
		envelopes = append(envelopes, envelope)
	}

	// encrypt the plaintext (by AES-256-CBC)
	ciphertext, err := aes.Encrypt(shareKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("AES encryption failed: %w", err)
	}

	// sign the ciphertext
	sig, err := prvKey.Sign(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// create `caesar.json`
	selfAuthKey, err := prvKey.GetAuthKey()
	if err != nil {
		return nil, fmt.Errorf("the authentication key could not be obtained from the private key during encryption: %w", err)
	}
	caesarJson := &CaesarJson{
		Version:   "1",
		Signature: base64.StdEncoding.EncodeToString(sig),
		Signer:    selfAuthKey,
		Envelopes: envelopes,
	}
	jsonBytes, err := json.Marshal(caesarJson)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal `caesar.json`: %w", err)
	}

	// create zip data
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)
	if err := iolib.AppendZipEntry(zipWriter, CAESAR_JSON, jsonBytes); err != nil {
		return nil, fmt.Errorf("failed to add `caesar.json` entry to ZIP file: %w", err)
	}
	if err := iolib.AppendZipEntry(zipWriter, CAESAR_CIPHER, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to add `caesar.cipher` entry to ZIP file: %w", err)
	}
	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to create ZIP file: %w", err)
	}
	zipBytes := zipBuf.Bytes()

	return zipBytes, nil
}
