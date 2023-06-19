package vault

import "testing"

func TestEncrypt(t *testing.T) {
	t.Run("Can encrypt and decrypt", func(t *testing.T) {
		bytes := []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
		secret := "abc&1*~#^2^#s0^=)^^7%b34"
		val := "hello world!"
		p := NewAESPrivatiser(bytes, secret)
		encrypted, err := p.Encrypt(val)
		if err != nil {
			t.Errorf("Error encrypting: %v", err)
		}
		if encrypted == "" {
			t.Error("Encrypted string is empty")
		}

		decrypted, err := p.Decrypt(encrypted)
		if err != nil {
			t.Errorf("Error decrypting: %v", err)
		}

		if decrypted != val {
			t.Errorf("Mismatch between value %s and decrypted: %s", val, decrypted)
		}
	})
}
