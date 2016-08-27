// Package jwt is a barebones JWT implementation that supports just the bare necessities.
package jwt

import (
	"fmt"

	"github.com/pkg/errors"
)

var (
	// ErrInvalidSignature is returned when the signature used to sign a token isn't valid.
	ErrInvalidSignature = errors.New("Invalid signature doesn't match")
)

// ErrEncodeFailure is returned when the Encode function fails to properly encode a claim set.
type ErrEncodeFailure struct {
	Embedded    error
	Description string
}

func (e ErrEncodeFailure) Error() string {
	return fmt.Sprintf("Failed to encode claims: %s: %s", e.Description, e.Embedded.Error())
}

// ErrDecodeFailure is returned when the Decode function fails to properly decode a jwt.
type ErrDecodeFailure struct {
	Embedded    error
	Description string
}

func (e ErrDecodeFailure) Error() string {
	return fmt.Sprintf("Failed to encode claims: %s: %s", e.Description, e.Embedded.Error())
}

// Header containins important information for encrypting / decryting
type Header struct {
	Typ string // Token Type
	Alg string // Message Authentication Code Algorithm - The issuer can freely set an algorithm to verify the signature on the token. However, some asymmetrical algorithms pose security concerns
	Cty string // Content Type - This claim should always be JWT
}
