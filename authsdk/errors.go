package authsdk

import "errors"

var (
	ErrMissingToken = errors.New("authsdk: missing bearer token")
	ErrTokenRevoked = errors.New("authsdk: token has been revoked")
)
