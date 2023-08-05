package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func GenerateSecret() (string, error) {
	// Define the desired token length in bytes
	tokenLength := 16
	// Create a byte slice to hold the random bytes
	tokenBytes := make([]byte, tokenLength)

	// Read random bytes from the secure random number generator
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	// Encode the random bytes as a base64 string to make it human-readable
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	return token, nil
}

func Hash(msg string) string {
	hash := sha256.Sum256([]byte(msg))
	return hex.EncodeToString(hash[:])
}
