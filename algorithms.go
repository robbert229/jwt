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
func (a *Algorithm) Sign(unsignedToken string) ([]byte, error) {
	_, err := a.write([]byte(unsignedToken))
	if err != nil {
		return nil, errors.Wrap(err, "Unable to write to HMAC-SHA256")
	}

	encodedToken := a.sum(nil)
	a.reset()

	return encodedToken, nil
}

// Encode returns an encoded JWT token from a header, payload, and secret
func (a *Algorithm) Encode(payload *Claims) (string, error) {
	header := a.NewHeader()

	jsonTokenHeader, err := json.Marshal(header)
	if err != nil {
		return "", errors.Wrap(err, "unable to marshal header")
	}

	b64TokenHeader := base64.RawURLEncoding.EncodeToString(jsonTokenHeader)

	jsonTokenPayload, err := json.Marshal(payload.claimsMap)
	if err != nil {
		return "", errors.Wrap(err, "unable to marshal payload")
	}

	b64TokenPayload := base64.RawURLEncoding.EncodeToString(jsonTokenPayload)

	unsignedSignature := b64TokenHeader + "." + b64TokenPayload

	signature, err := a.Sign(unsignedSignature)
	if err != nil {
		return "", errors.Wrap(err, "unable to sign token")
	}
	b64Signature := base64.RawURLEncoding.EncodeToString([]byte(signature))

	token := b64TokenHeader + "." + b64TokenPayload + "." + b64Signature

	return token, nil
}

// Decode returns a map representing the token's claims. DOESN'T validate the claims though.
func (a *Algorithm) Decode(encoded string) (*Claims, error) {
	encryptedComponents := strings.Split(encoded, ".")
	if len(encryptedComponents) != 3 {
		return nil, errors.New("malformed token")
	}

	b64Payload := encryptedComponents[1]

	var claims map[string]interface{}
	payload, err := base64.RawURLEncoding.DecodeString(b64Payload)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode base64 payload")
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal payload json")
	}

	return &Claims{
		claimsMap: claims,
	}, nil
}

// Validate verifies a tokens validity. It returns nil if it is valid, and an error if invalid.
func (a *Algorithm) Validate(encoded string) error {
	_, err := a.DecodeAndValidate(encoded)
	return err
}

// DecodeAndValidate returns a map representing the token's claims, and it's valid.
func (a *Algorithm) DecodeAndValidate(encoded string) (claims *Claims, err error) {
	claims, err = a.Decode(encoded)
	if err != nil {
		return
	}

	if err = a.validateSignature(encoded); err != nil {
		err = errors.Wrap(err, "failed to validate signature")
		return
	}

	if err = a.validateExp(claims); err != nil {
		err = errors.Wrap(err, "failed to validate exp")
		return
	}

	if err = a.validateNbf(claims); err != nil {
		err = errors.Wrap(err, "failed to validate nbf")
	}

	return
}

func (a *Algorithm) validateSignature(encoded string) error {
	encryptedComponents := strings.Split(encoded, ".")

	b64Header := encryptedComponents[0]
	b64Payload := encryptedComponents[1]
	b64Signature := encryptedComponents[2]

	unsignedAttempt := b64Header + "." + b64Payload
	signedAttempt, err := a.Sign(unsignedAttempt)
	if err != nil {
		return errors.Wrap(err, "unable to sign token for validation")
	}

	b64SignedAttempt := base64.RawURLEncoding.EncodeToString([]byte(signedAttempt))

	if !hmac.Equal([]byte(b64Signature), []byte(b64SignedAttempt)) {
		return errors.New("invalid signature")
	}

	return nil
}

func (a *Algorithm) validateExp(claims *Claims) error {
	if claims.HasClaim("exp") {
		exp, err := claims.GetTime("exp")
		if err != nil {
			return err
		}

		if exp.Before(time.Now()) {
			return errors.New("token has expired")
		}
	}

	return nil
}

func (a *Algorithm) validateNbf(claims *Claims) error {
	if claims.HasClaim("nbf") {
		nbf, err := claims.GetTime("nbf")
		if err != nil {
			return err
		}

		if nbf.After(time.Now()) {
			return errors.New("token isn't valid yet")
		}
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
