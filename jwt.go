// Package jwt is a barebones JWT implementation that only supports HS256
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

//SigningMethod is the algorithm used to sign and validate a token.
type SigningMethod struct {
	signingHash hash.Hash
	algorithm string
}

// NewHeader returns a new Header object.
func (method *SigningMethod) NewHeader() *Header{
	return &Header{
		Typ: "JWT",
		Alg: method.algorithm,
	}
}

// Sum returns the sum of the hash
func (method *SigningMethod) Sum(data []byte) []byte {
	return method.signingHash.Sum(data)
}

// Reset resets the hash
func (method *SigningMethod) Reset(){
	method.signingHash.Reset()
}

// Write writes the specified bytes to the hash
func (method *SigningMethod) Write(data []byte) (int, error){
	return method.signingHash.Write(data)
}

// Header containins important information for encrypting / decryting
type Header struct {
	Typ string // Token Type
	Alg string // Message Authentication Code Algorithm - The issuer can freely set an algorithm to verify the signature on the token. However, some asymmetrical algorithms pose security concerns
	Cty string // Content Type - This claim should always be JWT
}


// Payload contains the claims of the token
type Payload struct {
	//Standard Fields
	Iis string    // Issuer - identifies principal that issued the JWT;
	Sub string    // Subject - identifies the subject of the JWT;
	Aud string    // Audience - The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present, then the JWT MUST be rejected.
	Exp time.Time // Expiration time - The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
	Nbf time.Time // Not before - Similarly, the not-before time claim identifies the time on which the JWT will start to be accepted for processing.
	Iat time.Time // Issued at - The "iat" (issued at) claim identifies the time at which the JWT was issued.
	Jti string    // JWT ID - case sensitive unique identifier of the token even among different issuers.
}


//HmacSha256 returns the SingingMethod for HMAC with SHA256
func HmacSha256(key string) SigningMethod {
	return SigningMethod{
		algorithm: "HS256",
		signingHash: hmac.New(sha256.New, []byte(key)),
	}
}

//HmacSha512 returns the SigningMethod for HMAC with SHA512
func HmacSha512(key string) SigningMethod {
	return SigningMethod{
		algorithm: "HS512",
		signingHash: hmac.New(sha512.New, []byte(key)),
	}
}

//Sign signs the token with the given hash, and key
func Sign(signingHash SigningMethod, unsignedToken string) (string, error){
	_, err := signingHash.Write([]byte(unsignedToken))
	if err != nil {
		return "", errors.New("Unable to write to HMAC-SHA256")
	}

	encodedToken := base64.StdEncoding.EncodeToString(signingHash.Sum(nil))
	signingHash.Reset()

	return encodedToken, nil
}

// Encode returns an encoded JWT token from a header, payload, and secret
func Encode(signingHash SigningMethod, header Header, payload Payload) (string, error) {
	jsonTokenHeader, err := json.Marshal(header)
	if err != nil {
		return "", errors.New("unable to marshal header")
	}

	b64TokenHeader := base64.StdEncoding.EncodeToString(jsonTokenHeader)

	jsonTokenPayload, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("unable to marshal payload")
	}

	b64TokenPayload := base64.StdEncoding.EncodeToString(jsonTokenPayload)

	unsignedSignature := b64TokenHeader + "." + b64TokenPayload

	signature, err := Sign(signingHash, unsignedSignature)
	if err != nil {
		return "", err
	}
	b64Signature := base64.StdEncoding.EncodeToString([]byte(signature))

	token := b64TokenHeader + "." + b64TokenPayload + "." + b64Signature

	return token, nil
}

// Verify verifies if a token is valid,
func Verify(signingHash SigningMethod, encoded string) error {
	encryptedComponents := strings.Split(encoded, ".")

	b64Header := encryptedComponents[0]
	b64Payload := encryptedComponents[1]
	b64Signature := encryptedComponents[2]

	unsignedAttempt := b64Header + "." + b64Payload
	signedAttempt, err := Sign(signingHash, unsignedAttempt)

	if err != nil {
		return err
	}

	b64SignedAttempt := base64.StdEncoding.EncodeToString([]byte(signedAttempt))

	if strings.Compare(b64Signature, b64SignedAttempt) != 0 {
		return errors.New("Invalid Signature Doesn't Match")
	}

	return nil
}
