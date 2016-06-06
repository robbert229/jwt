package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
    "crypto"
	"hash"
)

//Algorithm is used to sign and validate a token.
type Algorithm struct {
	signingHash hash.Hash
	algorithm   string
}

// NewHeader returns a new Header object.
func (method *Algorithm) NewHeader() *Header {
	return &Header{
		Typ: "JWT",
		Alg: method.algorithm,
	}
}

// Sum returns the sum of the hash
func (method *Algorithm) Sum(data []byte) []byte {
	return method.signingHash.Sum(data)
}

// Reset resets the hash
func (method *Algorithm) Reset() {
	method.signingHash.Reset()
}

// Write writes the specified bytes to the hash
func (method *Algorithm) Write(data []byte) (int, error) {
	return method.signingHash.Write(data)
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
        algorithm: "HS384",
        signingHash: hmac.New(crypto.SHA384.New, []byte(key)),
    }
}