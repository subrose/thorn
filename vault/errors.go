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
