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
		return nil, fmt.Errorf("Failed to expand zip file.\r\t%w", err)
	}
	caesarJsonBytes, err := iolib.ExtractZipEntry(zipReader, CAESAR_JSON)
	if err != nil {
		return nil, fmt.Errorf("Failed to extract `caesar.json`.\r\t%w", err)
	}
	caesarCipher, err := iolib.ExtractZipEntry(zipReader, CAESAR_CIPHER)
	if err != nil {
		return nil, fmt.Errorf("Failed to extract `caesar.cipher`.\r\t%w", err)
	}

	// unmarshal `caesar.json`
	caesarJson, err := parseCaesarJson(caesarJsonBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal `caesar.json`.\n\t%w", err)
	}

	// version validation
	if caesarJson.Version != "1" {
		return nil, fmt.Errorf("Unknown `caesar.json` version `%s`", caesarJson.Version)
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
			return nil, errors.New("VERIFY_ERROR: not found sender publicKey.")
		}
	}

	// verify signature
	peerPubKey, err := pubkeylib.ParseAuthKey(caesarJson.Signer)
	if err != nil {
		return nil, fmt.Errorf("Invalid signer in `caesar.json`.\n\t%w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(caesarJson.Signature)
	if err != nil {
		return nil, fmt.Errorf("Invalid signature in `caesar.json`.\n\t%w", err)
	}
	if !peerPubKey.Verify(caesarCipher, sig) {
		return nil, errors.New("File is corrupted.")
	}

	// find the envelope corresponding to self private key
	selfAuthKey, err := prvKey.GetAuthKey()
	if err != nil {
		return nil, fmt.Errorf("The authentication key could not be obtained from the private key during decryption.\n\t%w", err)
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
		return nil, errors.New("Unable to decrypt with the specified private key.")
	}

	// key exchange
	shareKey, err := prvKey.ExtractShareKey(targetEnvelope)
	if err != nil {
		return nil, fmt.Errorf("Key exchange failed.\n\t%w", err)
	}

	// decrypt `caesar.cipher`
	plaintext, err := aes.Decrypt(shareKey, caesarCipher)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt `caesar.cipher` with AES.\n\t%w", err)
	}

	return plaintext, nil
}
