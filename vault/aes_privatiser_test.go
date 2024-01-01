package vault

import "testing"

func TestEncrypt(t *testing.T) {
	t.Run("Can encrypt and decrypt", func(t *testing.T) {
		secret := "abc&1*~#^2^#s0^=)^^7%b34"
		val := "hello world!"
		p, err := NewAESPrivatiser(secret)
		if err != nil {
			t.Errorf("Error creating privatiser: %v", err)
		}
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
