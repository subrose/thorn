package vault

import (
	"errors"
	"fmt"
)

var (
	ErrIndexError = errors.New("index")
)

type ForbiddenError struct{ request Request }

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("forbidden: principal %s doing %s on %s", e.request.Principal.Username, e.request.Action, e.request.Resource)
}

type NotFoundError struct{ resourceName string }

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("not found: %s", e.resourceName)
}

type ConflictError struct{ resourceName string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict: %s", e.resourceName)
}

type InvalidTokenError struct {
	Message string
}

func (e *InvalidTokenError) Error() string {
	return e.Message
}

type ExpiredTokenError struct {
	Message string
}

func (e *ExpiredTokenError) Error() string {
	return e.Message
}

type NonExistentTokenError struct {
	Message string
}

func (e *NonExistentTokenError) Error() string {
	return e.Message
}

type NotYetValidTokenError struct {
	Message string
}

func (e *NotYetValidTokenError) Error() string {
	return e.Message
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
