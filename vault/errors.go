package vault

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var (
	ErrIndexError   = errors.New("index")
	ErrNotSupported = errors.New("notsupported")
)

type ForbiddenError struct{ request Request }

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("forbidden: principal %s doing %s on %s", e.request.Actor.Username, e.request.Action, e.request.Resource)
}

type NotFoundError struct {
	resourceName  string
	resourceValue string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%s: %s does not exist", e.resourceName, e.resourceName)
}

type ConflictError struct{ resourceName string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict: %s", e.resourceName)
}

type ValueError struct{ Msg string }

func (e *ValueError) Error() string {
	return e.Msg
}

type ErrorResponse struct {
	Message string         `json:"message"`
	Errors  []*interface{} `json:"errors"`
}

func ValidateResourceName(fl validator.FieldLevel) bool {
	reg := "^[a-zA-Z0-9._]{1,249}$"
	match, _ := regexp.MatchString(reg, fl.Field().String())

	// Check for prohibited values: single period, double underscore, and hyphen
	if fl.Field().String() == "." || fl.Field().String() == "__" || fl.Field().String() == "-" {
		return false
	}

	return match
}

type ValidationError struct {
	FailedField string `json:"failed_field"`
	Tag         string `json:"tag"`
	Value       string `json:"value"`
}

type ValidationErrors struct {
	Errors []*ValidationError `json:"errors"`
}

func (e ValidationErrors) Error() string {
	errors := make([]string, len(e.Errors))
	for i, err := range e.Errors {
		errors[i] = fmt.Sprintf("%s: %s", err.FailedField, err.Tag)
	}
	return strings.Join(errors, ", ")
}

func NewValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	err := v.RegisterValidation("vaultResourceNames", ValidateResourceName)
	if err != nil {
		panic(err)
	}
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	return v
}
