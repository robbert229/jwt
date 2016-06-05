package jwt

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEncodeAndVerifyToken(t *testing.T) {
	secret := "secret"
	signingHash := HmacSha256(secret)
	
	payload := NewClaim()
	err := json.Unmarshal([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`), &payload)
	if err != nil {
		t.Fatal(err)
	}

	token, err := Encode(signingHash, payload)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(signingHash, token)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyToken(t *testing.T) {
	secret := "secret"
	signingHash := HmacSha256(secret)
	
	payload := NewClaim()
	err := json.Unmarshal([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`), &payload)
	if err != nil {
		t.Fatal(err)
	}

	token, err := Encode(signingHash, payload)
	if err != nil {
		t.Fatal(err)
	}

	tokenComponents := strings.Split(token, ".")

	invalidSignature := "cBab30RMHrHDcEfxjoYZgeFONFh7Hg"
	invalidToken := tokenComponents[0] + "." + tokenComponents[1] + "." + invalidSignature

	err = Verify(signingHash, invalidToken)
	if err == nil {
		t.Fatal(err)
	}
}
