package vault

import (
	"testing"

	"github.com/go-playground/assert/v2"
)

func TestStringPType(t *testing.T) {
	value := "test"

	str, _ := GetPType(StringType, value)

	plain, _ := str.Get("plain")
	masked, _ := str.Get("masked")

	assert.Equal(t, plain, value)
	assert.Equal(t, masked, "*")

}

func TestNamePType(t *testing.T) {
	value := "Asd Das"

	name, _ := GetPType(NameType, value)

	plain, _ := name.Get("plain")
	masked, _ := name.Get("masked")

	assert.Equal(t, plain, value)
	assert.Equal(t, masked, "A** D**")
}

func TestPhonePType(t *testing.T) {
	value := "+44 0711 222 3333"

	pn, err := GetPType(PhoneNumberType, value)
	assert.Equal(t, err, nil)

	plain, _ := pn.Get("plain")
	masked, _ := pn.Get("masked")

	assert.Equal(t, plain, "+447112223333")
	assert.Equal(t, masked, "+44711*******")
}

func TestInvalidPhonePType(t *testing.T) {
	value := "0t711"

	_, err := GetPType(PhoneNumberType, value)
	assert.NotEqual(t, err, nil)

}

func TestEmailPType(t *testing.T) {
	value := "test@something.com"

	em, err := GetPType(EmailType, value)
	assert.Equal(t, err, nil)

	plain, _ := em.Get("plain")
	masked, _ := em.Get("masked")

	assert.Equal(t, plain, value)
	assert.Equal(t, masked, "****@something.com")
}

func TestInvalidEmailPType(t *testing.T) {
	value := "testsomething.com"

	_, err := GetPType(EmailType, value)
	assert.NotEqual(t, err, nil)
}
