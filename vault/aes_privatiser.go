package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

type AESPrivatiser struct {
	secret []byte
	block  cipher.Block // Store the cipher block
}

func NewAESPrivatiser(secret string) (*AESPrivatiser, error) {
	if len(secret) != 16 && len(secret) != 24 && len(secret) != 32 {
		// TODO: Enforce AES-256
		return nil, errors.New("invalid secret length; must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256 respectively")
	}
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}
	return &AESPrivatiser{[]byte(secret), block}, nil
}

func (p *AESPrivatiser) Encrypt(text string) (string, error) {
	iv := make([]byte, aes.BlockSize)
	cfb := cipher.NewCFBEncrypter(p.block, iv)
	cipherText := make([]byte, len(text))
	cfb.XORKeyStream(cipherText, []byte(text))

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (p *AESPrivatiser) Decrypt(encodedText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encodedText)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)

	cfb := cipher.NewCFBDecrypter(p.block, iv)
	plainText := make([]byte, len(data))
	cfb.XORKeyStream(plainText, data)

	return string(plainText), nil
}
