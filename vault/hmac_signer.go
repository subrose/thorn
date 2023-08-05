package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

type HMACSigner struct {
	key []byte
}

func NewHMACSigner(key []byte) (*HMACSigner, error) {
	if len(key) == 0 {
		return nil, errors.New("key cannot be empty")
	}
	return &HMACSigner{key: key}, nil
}

// Sign signs the provided message using HMAC and returns the signature as a hexadecimal string.
func (h *HMACSigner) Sign(message string) (string, error) {
	if message == "" {
		return "", errors.New("message cannot be empty")
	}

	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	return hex.EncodeToString(signature), nil
}

// Verify checks if the provided signature is a valid signature of the provided message.
func (h *HMACSigner) Verify(message, signature string) (bool, error) {
	expectedSignature, err := h.Sign(message)
	if err != nil {
		return false, err
	}
	// Always use Equal to compare MACs in order to avoid timing side-channels
	return hmac.Equal([]byte(expectedSignature), []byte(signature)), nil
}
