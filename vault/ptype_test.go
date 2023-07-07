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
	redacted, _ := str.Get("redacted")

	assert.Equal(t, plain, value)
	assert.Equal(t, masked, "****")
	assert.Equal(t, redacted, REDACTED_VALUE)

}

func TestNamePType(t *testing.T) {
	value := "Asd Das"

	name, _ := GetPType(NameType, value)

	plain, _ := name.Get("plain")
	masked, _ := name.Get("masked")
	redacted, _ := name.Get("redacted")

	assert.Equal(t, plain, value)
	assert.Equal(t, masked, "*** ***")
	assert.Equal(t, redacted, REDACTED_VALUE)
}

func TestPhonePType(t *testing.T) {
	value := "+44 0711 222 3333"

	pn, err := GetPType(PhoneNumberType, value)
	assert.Equal(t, err, nil)

	plain, _ := pn.Get("plain")
	masked, _ := pn.Get("masked")
	redacted, _ := pn.Get("redacted")

	assert.Equal(t, plain, "+447112223333")
	assert.Equal(t, masked, "+4411111111111")
	assert.Equal(t, redacted, REDACTED_VALUE)
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
	redacted, _ := em.Get("redacted")

	assert.Equal(t, plain, value)
	assert.Equal(t, masked, "****@something.com")
	assert.Equal(t, redacted, REDACTED_VALUE)
}

func TestInvalidEmailPType(t *testing.T) {
	value := "testsomething.com"

	_, err := GetPType(EmailType, value)
	assert.NotEqual(t, err, nil)
}
