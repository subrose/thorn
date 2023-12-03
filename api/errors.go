package main

type AuthError struct{ Msg string }

func (e *AuthError) Error() string {
	return e.Msg
}

type ErrorResponse struct {
	Message string         `json:"message"`
	Errors  []*interface{} `json:"errors"`
}
