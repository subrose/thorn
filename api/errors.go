package main

import (
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

type AuthError struct{ Msg string }

func (e *AuthError) Error() string {
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

func newValidator() *validator.Validate {
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
