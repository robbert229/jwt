// Package jwt is a barebones JWT implementation that supports just the bare necessities.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
)

var (
	// ErrExpired is returned when a token has expired.
	ErrExpired = errors.New("Token has expired")
	// ErrNotValidYet is returned when a token is not valid yet.
	ErrNotValidYet = errors.New("Token not valid yet")
	// ErrInvalidSignature is returned when the signature used to sign a token isn't valid.
	ErrInvalidSignature = errors.New("Invalid signature doesn't match")
)

// ErrEncodeFailure is returned when the Encode funtion fails to properly encode a claim set.
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

// NewClaim returns a new map representing the claims with the default values. The schema is detailed below.
//		claim["iis"] Issuer - string - identifies principal that issued the JWT;
//		claim["sub"] Subject - string - identifies the subject of the JWT;
//		claim["aud"] Audience - string - The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present, then the JWT MUST be rejected.
//		claim["exp"] Expiration time - time - The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
//		claim["nbf"] Not before - time - Similarly, the not-before time claim identifies the time on which the JWT will start to be accepted for processing.
//		claim["iat"] Issued at - time - The "iat" (issued at) claim identifies the time at which the JWT was issued.
//		claim["jti"] JWT ID - string - case sensitive unique identifier of the token even among different issuers.
func NewClaim() map[string]interface{} {
	claim := make(map[string]interface{})

	claim["iat"] = time.Now().Unix()

	return claim
}

// Sign signs the token with the given hash, and key
func Sign(algorithm Algorithm, unsignedToken string) (string, error) {
	_, err := algorithm.Write([]byte(unsignedToken))
	if err != nil {
		return "", errors.Wrap(err, "Unable to write to HMAC-SHA256")
	}

	encodedToken := base64.StdEncoding.EncodeToString(algorithm.Sum(nil))
	algorithm.Reset()

	return encodedToken, nil
}

// Encode returns an encoded JWT token from a header, payload, and secret
func Encode(algorithm Algorithm, payload map[string]interface{}) (string, error) {
	header := algorithm.NewHeader()

	jsonTokenHeader, err := json.Marshal(header)
	if err != nil {
		return "", ErrEncodeFailure{err, "unable to marshal header"}
	}

	b64TokenHeader := base64.StdEncoding.EncodeToString(jsonTokenHeader)

	jsonTokenPayload, err := json.Marshal(payload)
	if err != nil {
		return "", ErrEncodeFailure{err, "unable to marshal payload"}
	}

	b64TokenPayload := base64.StdEncoding.EncodeToString(jsonTokenPayload)

	unsignedSignature := b64TokenHeader + "." + b64TokenPayload

	signature, err := Sign(algorithm, unsignedSignature)
	if err != nil {
		return "", ErrEncodeFailure{err, "unable to sign token"}
	}
	b64Signature := base64.StdEncoding.EncodeToString([]byte(signature))

	token := b64TokenHeader + "." + b64TokenPayload + "." + b64Signature

	return token, nil
}

// Decode returns a map representing the token's claims. DOESNT validate the claims though.
func Decode(algorithm Algorithm, encoded string) (map[string]interface{}, error) {
	encryptedComponents := strings.Split(encoded, ".")

	b64Header := encryptedComponents[0]
	b64Payload := encryptedComponents[1]
	b64Signature := encryptedComponents[2]

	unsignedAttempt := b64Header + "." + b64Payload
	signedAttempt, err := Sign(algorithm, unsignedAttempt)

	if err != nil {
		return nil, ErrDecodeFailure{err, "unable to sign token for validation"}
	}

	b64SignedAttempt := base64.StdEncoding.EncodeToString([]byte(signedAttempt))

	if strings.Compare(b64Signature, b64SignedAttempt) != 0 {
		return nil, ErrInvalidSignature
	}

	var claims map[string]interface{}
	payload, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return nil, ErrDecodeFailure{err, "unable to decode base64 payload"}
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrDecodeFailure{err, "unable to unmarshal payload json"}
	}

	return claims, nil
}

// Verify verifies if a token is valid,
func IsValid(algorithm Algorithm, encoded string) error {
	claims, err := Decode(algorithm, encoded)
	if err != nil {
		return err
	}

	if f, ok := claims["exp"].(float64); ok {
		exp := time.Unix(int64(f), 0)
		if exp.Before(time.Now()) {
			return ErrExpired
		}
	}

	if f, ok := claims["nbf"].(float64); ok {
		nbf := time.Unix(int64(f), 0)
		if nbf.After(time.Now()) {
			return ErrNotValidYet
		}
	}

	return err
}
