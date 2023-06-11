package vault

import (
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")
var ErrForbidden = errors.New("forbidden")
var ErrIndexError = errors.New("index")

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
