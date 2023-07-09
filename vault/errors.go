package vault

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	// ErrForbidden  = errors.New("forbidden")
	ErrIndexError = errors.New("index")
)

type ErrForbidden struct{ action Action }

func (f ErrForbidden) Error() string {
	return fmt.Sprintf("forbidden: principal %s doing %s on %s", f.action.Principal.Name, f.action.Action, f.action.Resource)
}

type ValueError struct {
	Err error
	Msg string
}

func (ve *ValueError) Error() string {
	return fmt.Sprintf("value error: %s", ve.Err)
}

func (ve *ValueError) Unwrap() error {
	return ve.Err
}

func newValueError(err error) *ValueError {
	return &ValueError{
		Err: err,
	}
}

type ValidationError struct {
	FailedField string `json:"failed_field"`
	Tag         string `json:"tag"`
	Value       string `json:"value"`
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("Validation failed on field '%s': condition '%s' for value '%s'",
		ve.FailedField, ve.Tag, ve.Value)
}

type ValidationErrors struct {
	Errs []ValidationError
	Msg  string
}

func newValidationErrors(errs []ValidationError) *ValidationErrors {
	return &ValidationErrors{
		Errs: errs,
		Msg:  "validation errors",
	}
}

func (ve *ValidationErrors) Error() string {
	msg := ve.Msg
	for _, err := range ve.Errs {
		msg += "\n" + err.Error()
	}
	return msg
}
