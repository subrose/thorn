package vault

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/nyaruka/phonenumbers"
	"github.com/retgits/creditcard"
)

var ErrNotSupported = errors.New("notsupported")
var ErrValidation = errors.New("invalid")

type PTypeName string

const (
	PhoneNumberType PTypeName = "phone_number"
	NameType        PTypeName = "name"
	StringType      PTypeName = "string"
	EmailType       PTypeName = "email"
	CreditCardType  PTypeName = "credit_card"
	RegexType       PTypeName = "regex"
)

type PType interface {
	Get(format string) (string, error)
	// New(val string) (PType, error)
}

type String struct {
	val string
}

func (s String) Get(format string) (string, error) {
	switch format {
	case "plain":
		return s.val, nil
	case "masked":
		return s.GetMasked(), nil
	default:
		return "", ErrNotSupported
	}
}

func (s String) GetMasked() string {
	return allStars(s.val)
}

func (s String) Validate() bool {
	return true
}

type Name struct {
	val string
}

func (n Name) Get(format string) (string, error) {
	switch format {
	case "plain":
		return n.val, nil
	case "masked":
		return n.GetMasked(), nil
	default:
		return "", ErrNotSupported
	}
}

func (n Name) GetMasked() string {
	names := strings.Split(n.val, " ")
	maskedNames := []string{}

	for _, name := range names {
		maskedNames = append(maskedNames, allStars(name))
	}
	return strings.Join(maskedNames, " ")

}

func (n Name) Validate() bool {
	// Turns out it's not that easy to validate a name...
	// See https://stackoverflow.com/questions/2385701/regular-expression-for-first-and-last-name
	return true
}

type PhoneNumber struct {
	val *phonenumbers.PhoneNumber
}

func (pn PhoneNumber) Get(format string) (string, error) {
	switch format {
	case "plain":
		return phonenumbers.Format(pn.val, phonenumbers.E164), nil
	case "masked":
		return pn.GetMasked(), nil
	default:
		return "", ErrNotSupported
	}
}

func (pn PhoneNumber) GetMasked() string {
	rawNumber := phonenumbers.Format(pn.val, phonenumbers.E164)
	cCode := *pn.val.CountryCode

	// TODO: mask better
	maskedNumber := fmt.Sprintf(
		"+%d%s",
		cCode,
		strings.Repeat("1", len(rawNumber)-2),
	)

	return maskedNumber
}

func (pn PhoneNumber) Validate() bool {
	return true
}

type Email struct {
	address mail.Address
}

func (em Email) Get(format string) (string, error) {
	switch format {
	case "plain":
		return em.GetPlain(), nil
	case "masked":
		return em.GetMasked(), nil
	default:
		return "", ErrNotSupported
	}
}

func (em Email) GetPlain() string {
	raw := em.address.String()

	return raw[1 : len(raw)-1]

}

func (em Email) GetMasked() string {
	components := strings.Split(em.GetPlain(), "@")
	username, domain := components[0], components[1]

	return strings.Join([]string{allStars(username), domain}, "@")
}

func (em Email) Validate() bool {
	return true
}

type CreditCard struct {
	cardNumber creditcard.Card
}

func (c CreditCard) Get(format string) (string, error) {
	// This needs to be exported as an object since it contains other things.
	switch format {
	case "plain":
		return c.cardNumber.Number, nil
	case "masked":
		return c.GetMasked(), nil
	default:
		return "", nil
	}
}

func (c CreditCard) GetMasked() string {
	return "****"
}

func (c CreditCard) Validate() bool {
	return true
}

func allStars(s string) string {
	return strings.Repeat("*", len(s))
}

func GetPType(pType PTypeName, value string) (PType, error) {
	switch pType {
	case StringType:
		newString := String{value}
		if !newString.Validate() {
			return nil, ErrValidation
		}
		return newString, nil
	case PhoneNumberType:
		parsedPhoneNumber, err := phonenumbers.Parse(value, "UK")
		if err != nil {
			return nil, err
		}
		return PhoneNumber{parsedPhoneNumber}, nil
	case NameType:
		newName := Name{value}
		if !newName.Validate() {
			return nil, ErrValidation
		}
		return newName, nil
	case EmailType:
		emailAddress, err := mail.ParseAddress(value)
		if err != nil {
			return nil, err
		}
		return Email{*emailAddress}, nil
	case CreditCardType:
		// TODO: Build from json?
		return nil, ErrNotSupported
	default:
		// Defaulting to string
		return String{value}, nil
	}
}
