package privatebin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"

	"github.com/safing/go-privatebin/utils"
	"golang.org/x/crypto/pbkdf2"
)

const (
	specIterations  = 100000
	specKeySize     = 256
	specTagSize     = 128
	specAlgorithm   = "aes"
	specMode        = "gcm"
	specCompression = "none"
)

func Encrypt(master []byte, message []byte) (*PasteData, error) {
	// Generate a initialization vector.
	iv, err := utils.GenRandomBytes(12)
	if err != nil {
		return nil, err
	}

	// Generate salt.
	salt, err := utils.GenRandomBytes(8)
	if err != nil {
		return nil, err
	}

	// Create the Paste Data and generate a key.
	paste := &PasteData{
		PasteSpec: &PasteSpec{
			IV:          utils.Base64(iv),
			Salt:        utils.Base64(salt),
			Iterations:  specIterations,
			KeySize:     specKeySize,
			TagSize:     specTagSize,
			Algorithm:   specAlgorithm,
			Mode:        specMode,
			Compression: specCompression,
		},
	}
	key := pbkdf2.Key(master, salt, paste.Iterations, 32, sha256.New)

	// Get the "adata" for the paste.
	adata, err := json.Marshal(paste.GetAData())
	if err != nil {
		return nil, err
	}

	// Create a new Cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Sign the message.
	data := gcm.Seal(nil, iv, message, adata)

	// Update and return the paste data.
	paste.Data = data

	return paste, nil
}
