package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
	"time"

	"github.com/pkg/errors"
)

var (
	// ErrTokenExpired is returned by algorithm.Validate when the token has expired.
	ErrTokenExpired = errors.New("token has expired")
	// ErrTokenNotYetValid is returned by algorithm.Validate what the token is not yet valid. (nbf tag is in the future)
	ErrTokenNotYetValid = errors.New("token is not yet valid")
)

//Algorithm is used to sign and validate a token.
type Algorithm struct {
	signingHash hash.Hash
	algorithm   string
}

// NewHeader returns a new Header object.
func (a *Algorithm) NewHeader() *Header {
	return &Header{
		Typ: "JWT",
		Alg: a.algorithm,
	}
}

func (a *Algorithm) sum(data []byte) []byte {
	return a.signingHash.Sum(data)
}

func (a *Algorithm) reset() {
	a.signingHash.Reset()
}

func (a *Algorithm) write(data []byte) (int, error) {
	return a.signingHash.Write(data)
}

// Sign signs the token with the given hash, and key
func (a *Algorithm) Sign(unsignedToken string) (string, error) {
	_, err := a.write([]byte(unsignedToken))
	if err != nil {
		return "", errors.Wrap(err, "Unable to write to HMAC-SHA256")
	}

	encodedToken := base64.StdEncoding.EncodeToString(a.sum(nil))
	a.reset()

	return encodedToken, nil
}

// Encode returns an encoded JWT token from a header, payload, and secret
func (a *Algorithm) Encode(payload *Claims) (string, error) {
	header := a.NewHeader()

	jsonTokenHeader, err := json.Marshal(header)
	if err != nil {
		return "", ErrEncodeFailure{err, "unable to marshal header"}
	}

	b64TokenHeader := base64.StdEncoding.EncodeToString(jsonTokenHeader)

	jsonTokenPayload, err := json.Marshal(payload.claimsMap)
	if err != nil {
		return "", ErrEncodeFailure{err, "unable to marshal payload"}
	}

	b64TokenPayload := base64.StdEncoding.EncodeToString(jsonTokenPayload)

	unsignedSignature := b64TokenHeader + "." + b64TokenPayload

	signature, err := a.Sign(unsignedSignature)
	if err != nil {
		return "", ErrEncodeFailure{err, "unable to sign token"}
	}
	b64Signature := base64.StdEncoding.EncodeToString([]byte(signature))

	token := b64TokenHeader + "." + b64TokenPayload + "." + b64Signature

	return token, nil
}

// Decode returns a map representing the token's claims. DOESNT validate the claims though.
func (a *Algorithm) Decode(encoded string) (*Claims, error) {
	encryptedComponents := strings.Split(encoded, ".")

	b64Payload := encryptedComponents[1]

	var claims map[string]string
	payload, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return nil, ErrDecodeFailure{err, "unable to decode base64 payload"}
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrDecodeFailure{err, "unable to unmarshal payload json"}
	}

	return &Claims{
		claimsMap: claims,
	}, nil
}

// Validate verifies a tokens validity. It returns nil if it is valid, and an error if invalid.
func (a *Algorithm) Validate(encoded string) error {
	claims, err := a.Decode(encoded)
	if err != nil {
		return err
	}

	encryptedComponents := strings.Split(encoded, ".")

	b64Header := encryptedComponents[0]
	b64Payload := encryptedComponents[1]
	b64Signature := encryptedComponents[2]

	unsignedAttempt := b64Header + "." + b64Payload
	signedAttempt, err := a.Sign(unsignedAttempt)
	if err != nil {
		return ErrDecodeFailure{err, "unable to sign token for validation"}
	}

	b64SignedAttempt := base64.StdEncoding.EncodeToString([]byte(signedAttempt))

	if strings.Compare(b64Signature, b64SignedAttempt) != 0 {
		return ErrInvalidSignature
	}

	exp, err := claims.GetTime("exp")
	if err != nil {
		return err
	}

	if exp.Before(time.Now()) {
		return ErrTokenExpired
	}

	nbf, err := claims.GetTime("nbf")
	if err != nil {
		return err
	}

	if nbf.After(time.Now()) {
		return ErrTokenNotYetValid
	}

	return nil
}

//HmacSha256 returns the SingingMethod for HMAC with SHA256
func HmacSha256(key string) Algorithm {
	return Algorithm{
		algorithm:   "HS256",
		signingHash: hmac.New(sha256.New, []byte(key)),
	}
}

//HmacSha512 returns the SigningMethod for HMAC with SHA512
func HmacSha512(key string) Algorithm {
	return Algorithm{
		algorithm:   "HS512",
		signingHash: hmac.New(sha512.New, []byte(key)),
	}
}

//HmacSha384 returns the SigningMethod for HMAC with SHA384
func HmacSha384(key string) Algorithm {
	return Algorithm{
		algorithm:   "HS384",
		signingHash: hmac.New(crypto.SHA384.New, []byte(key)),
	}
}
