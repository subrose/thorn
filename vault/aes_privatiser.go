package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type AESPrivatiser struct {
	bytes  []byte
	secret string
}

func NewAESPrivatiser(bytes []byte, secret string) AESPrivatiser {
	return AESPrivatiser{bytes, secret}
}

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// Encrypt method is to encrypt or hide any classified text
func (p AESPrivatiser) Encrypt(text string) (string, error) {
	block, err := aes.NewCipher([]byte(p.secret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, p.bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

func (p AESPrivatiser) Decrypt(text string) (string, error) {
	block, err := aes.NewCipher([]byte(p.secret))
	if err != nil {
		return "", err
	}
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, p.bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}
