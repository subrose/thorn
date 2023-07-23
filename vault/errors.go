package vault

import (
	"errors"
	"fmt"
)

var (
	ErrIndexError = errors.New("index")
)

type ForbiddenError struct{ action Action }

func (e *ForbiddenError) Error() string {
	return fmt.Sprintf("forbidden: principal %s doing %s on %s", e.action.Principal.Username, e.action.Action, e.action.Resource)
}

type NotFoundError struct{ resourceName string }

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("not found: %s", e.resourceName)
}

type ConflictError struct{ resourceName string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict: %s", e.resourceName)
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
