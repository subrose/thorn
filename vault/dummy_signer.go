package vault

type DummySigner struct {
}

func NewDummySigner() (DummySigner, error) {
	return DummySigner{}, nil
}

// Sign signs the provided message using HMAC and returns the signature as a hexadecimal string.
func (h DummySigner) Sign(message string) (string, error) {
	return "dummy", nil
}

// Verify checks if the provided signature is a valid signature of the provided message.
func (h DummySigner) Verify(message, signature string) (bool, error) {
	return true, nil
}
