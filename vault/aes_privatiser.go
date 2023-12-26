package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

type AESPrivatiser struct {
	secret string
}

func NewAESPrivatiser(secret string) (*AESPrivatiser, error) {
	if len(secret) != 16 && len(secret) != 24 && len(secret) != 32 {
		return nil, errors.New("invalid secret length; must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256 respectively")
	}
	return &AESPrivatiser{secret}, nil
}

func (p *AESPrivatiser) Encrypt(text string) (string, error) {
	block, err := aes.NewCipher([]byte(p.secret))
	if err != nil {
		return "", err
	}

	// Using a fixed IV for deterministic encryption
	iv := make([]byte, aes.BlockSize) // Fixed IV (e.g., all zeros)

	cfb := cipher.NewCFBEncrypter(block, iv)
	cipherText := make([]byte, len(text))
	cfb.XORKeyStream(cipherText, []byte(text))

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (p *AESPrivatiser) Decrypt(encodedText string) (string, error) {
	block, err := aes.NewCipher([]byte(p.secret))
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encodedText)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize) // Same fixed IV as used in encryption

	cfb := cipher.NewCFBDecrypter(block, iv)
	plainText := make([]byte, len(data))
	cfb.XORKeyStream(plainText, data)

	return string(plainText), nil
}
