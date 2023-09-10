package main

import (
	"strings"

	"regexp"

	"github.com/go-playground/validator/v10"
)

type AuthError struct{ Msg string }

func (e *AuthError) Error() string {
	return e.Msg
}

type ErrorResponse struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Errors  []*interface{} `json:"errors"`
}

func ValidateResourceName(fl validator.FieldLevel) bool {
	// Validation for vault internal resource names
	reg := "^[a-zA-Z0-9._-]{1,249}$"
	match, _ := regexp.MatchString(reg, fl.Field().String())

	// Check for prohibited values: single period and double underscore
	if fl.Field().String() == "." || fl.Field().String() == "__" {
		return false
	}

	return match
}

type ValidationError struct {
	FailedField string `json:"failed_field"`
	Tag         string `json:"tag"`
	Value       string `json:"value"`
}

// Validate validates the input struct
func Validate(payload interface{}) []*ValidationError {
	var errors []*ValidationError
	var validate = validator.New()
	_ = validate.RegisterValidation("vaultResourceNames", ValidateResourceName)

	err := validate.Struct(payload)
	if err != nil {
		// Check if the error is a validator.ValidationErrors type
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return errors
		}
		for _, err := range err.(validator.ValidationErrors) {
			var element ValidationError
			element.FailedField = strings.ToLower(err.StructField())
			element.Tag = err.Tag()
			element.Value = err.Param()
			errors = append(errors, &element)
		}
	}
	return errors
}
