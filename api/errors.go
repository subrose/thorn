package main

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

type ErrorResponse struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Errors  []*interface{} `json:"errors"`
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

	err := validate.Struct(payload)

	if err != nil {
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
