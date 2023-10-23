package vault

import (
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/nyaruka/phonenumbers"
)

type PTypeName string

const (
	PhoneNumberType      PTypeName = "phone_number"
	NameType             PTypeName = "name"
	StringType           PTypeName = "string"
	EmailType            PTypeName = "email"
	CreditCardNumberType PTypeName = "cc_number"
	RegexType            PTypeName = "regex"
	IntegerType          PTypeName = "integer"
	DateType             PTypeName = "date"
)

const (
	MASKED_FORMAT = "masked"
	PLAIN_FORMAT  = "plain"
)

type PType interface {
	Get(format string) (string, error)
	GetPlain() string
	GetMasked() string
	Validate() error
}

type String struct {
	val string
}

func (s String) Get(format string) (string, error) {
	return getFormat(s, format)
}

func (s String) GetPlain() string {
	return s.val
}

func (s String) GetMasked() string {
	return "*"
}

func (s String) Validate() error {
	return nil
}

type Name struct {
	val string
}

func (n Name) Get(format string) (string, error) {
	return getFormat(n, format)
}

func (n Name) GetPlain() string {
	return n.val
}

func (n Name) GetMasked() string {
	names := strings.Split(n.val, " ")
	maskedNames := []string{}

	for _, name := range names {
		maskedNames = append(maskedNames, string(name[0])+allStars(name[1:]))
	}
	return strings.Join(maskedNames, " ")
}

func (n Name) Validate() error {
	return nil
}

type PhoneNumber struct {
	val *phonenumbers.PhoneNumber
}

func (pn PhoneNumber) Get(format string) (string, error) {
	return getFormat(pn, format)
}

func (pn PhoneNumber) GetPlain() string {
	return phonenumbers.Format(pn.val, phonenumbers.E164)
}

func (pn PhoneNumber) GetMasked() string {
	rawNumber := phonenumbers.Format(pn.val, phonenumbers.E164)
	cCodeStr := strconv.Itoa(int(*pn.val.CountryCode))
	withoutCountryCode := rawNumber[len(cCodeStr)+1:]
	var masked string
	if len(withoutCountryCode) > 3 {
		masked = withoutCountryCode[:3] + strings.Repeat("*", len(withoutCountryCode)-3)
	} else {
		masked = strings.Repeat("*", len(withoutCountryCode))
	}
	return fmt.Sprintf("+%s%s", cCodeStr, masked)
}

func (pn PhoneNumber) Validate() error {
	return nil
}

type Email struct {
	address mail.Address
}

func (em Email) Get(format string) (string, error) {
	return getFormat(em, format)
}

func (em Email) GetPlain() string {
	return em.address.Address
}

func (em Email) GetMasked() string {
	components := strings.Split(em.address.Address, "@")
	username, domain := components[0], components[1]
	return strings.Join([]string{allStars(username), domain}, "@")
}

func (em Email) Validate() error {
	return nil
}

type CreditCardNumber struct {
	cardNumber string
}

func (c CreditCardNumber) Get(format string) (string, error) {
	return getFormat(c, format)
}

func (c CreditCardNumber) GetPlain() string {
	return c.cardNumber
}

func (c CreditCardNumber) GetMasked() string {
	return strings.Repeat("*", len(c.cardNumber)-4) + c.cardNumber[len(c.cardNumber)-4:]
}

func (c CreditCardNumber) Validate() error {
	var sum int
	var alternate bool
	numberLen := len(c.cardNumber)
	if numberLen < 13 || numberLen > 19 {
		return &ValueError{Msg: "Invalid card number, must be between 13 and 19 digits"}
	}
	for i := numberLen - 1; i > -1; i-- {
		mod, err := strconv.Atoi(string(c.cardNumber[i]))
		if err != nil {
			return &ValueError{Msg: "Invalid card number, failed to parse"}
		}
		if alternate {
			mod *= 2
			if mod > 9 {
				mod = (mod % 10) + 1
			}
		}
		alternate = !alternate
		sum += mod
	}
	if sum%10 != 0 {
		return &ValueError{Msg: "Invalid card number, failed sum check"}
	}
	return nil
}

type Integer struct {
	val int
}

func (i Integer) Get(format string) (string, error) {
	return getFormat(i, format)
}

func (i Integer) GetPlain() string {
	return strconv.Itoa(i.val)
}

func (i Integer) GetMasked() string {
	return "*"
}

func (i Integer) Validate() error {
	return nil
}

type Date struct {
	val time.Time
}

func (d Date) Get(format string) (string, error) {
	return getFormat(d, format)
}

func (d Date) GetPlain() string {
	return d.val.Format("2006-01-02")
}

func (d Date) GetMasked() string {
	return "****-**-**"
}

func (d Date) Validate() error {
	return nil
}

func allStars(s string) string {
	return strings.Repeat("*", len(s))
}

func getFormat(p PType, format string) (string, error) {
	switch format {
	case PLAIN_FORMAT:
		return p.GetPlain(), nil
	case MASKED_FORMAT:
		return p.GetMasked(), nil
	default:
		return "", ErrNotSupported
	}
}

func GetPType(pType PTypeName, value string) (PType, error) {
	switch pType {
	case StringType:
		newString := String{value}
		if err := newString.Validate(); err != nil {
			return nil, err
		}
		return newString, nil
	case PhoneNumberType:
		parsedPhoneNumber, err := phonenumbers.Parse(value, "")
		if err != nil {
			return nil, err
		}
		phoneNumber := PhoneNumber{parsedPhoneNumber}
		if err := phoneNumber.Validate(); err != nil {
			return nil, err
		}
		return phoneNumber, nil
	case NameType:
		newName := Name{value}
		if err := newName.Validate(); err != nil {
			return nil, err
		}
		return newName, nil
	case EmailType:
		emailAddress, err := mail.ParseAddress(value)
		if err != nil {
			return nil, err
		}
		email := Email{*emailAddress}
		if err := email.Validate(); err != nil {
			return nil, err
		}
		return email, nil
	case CreditCardNumberType:
		newCCNumber := CreditCardNumber{value}
		if err := newCCNumber.Validate(); err != nil {
			return nil, err
		}
		return newCCNumber, nil
	case IntegerType:
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return nil, err
		}
		newInteger := Integer{intValue}
		if err := newInteger.Validate(); err != nil {
			return nil, err
		}
		return newInteger, nil
	case DateType:
		dateValue, err := time.Parse("2006-01-02", value)
		if err != nil {
			return nil, err
		}
		newDate := Date{dateValue}
		if err := newDate.Validate(); err != nil {
			return nil, err
		}
		return newDate, nil
	default:
		newString := String{value}
		if err := newString.Validate(); err != nil {
			return nil, err
		}
		return newString, nil
	}
}
