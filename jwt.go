// Package jwt is a barebones JWT implementation that supports just the bare necessities.
package jwt

// Header contains important information for encrypting / decrypting
type Header struct {
	Typ string `json:"typ"` // Token Type
	Alg string `json:"alg"` // Message Authentication Code Algorithm - The issuer can freely set an algorithm to verify the signature on the token. However, some asymmetrical algorithms pose security concerns
	Cty string `json:"cty"` // Content Type - This claim should always be JWT
}
