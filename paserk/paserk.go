package paserk

import (
	"aidanwoods.dev/go-paseto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"strings"
)

// ParsePublic loads a k4.public-encoded v4 public key
func ParsePublic(s string) (key paseto.V4AsymmetricPublicKey, err error) {
	rest, ok := strings.CutPrefix(s, "k4.public.")
	if !ok {
		return key, errors.New("not a k4.public key")
	}

	rawKey, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return key, fmt.Errorf("failed to decode k4.public key: %w", err)
	}

	return paseto.NewV4AsymmetricPublicKeyFromBytes(rawKey)
}

func Encode(key interface{ ExportBytes() []byte }) string {
	encoded := base64.RawURLEncoding.EncodeToString(key.ExportBytes())
	switch v := key.(type) {
	case paseto.V4SymmetricKey:
		return "k4.local." + encoded
	case paseto.V4AsymmetricSecretKey:
		return "k4.secret." + encoded
	case paseto.V4AsymmetricPublicKey:
		return "k4.public." + encoded
	default:
		panic(fmt.Sprintf("cannot PASERKify type %T", v))
	}
}

func KeyID(key interface{ ExportBytes() []byte }) string {
	var header string
	switch v := key.(type) {
	case paseto.V4SymmetricKey:
		header = "k4.lid."
	case paseto.V4AsymmetricSecretKey:
		header = "k4.sid."
	case paseto.V4AsymmetricPublicKey:
		header = "k4.pid."
	default:
		panic(fmt.Sprintf("cannot PASERKify type %T", v))
	}
	hash, err := blake2b.New(33, nil)
	if err != nil {
		panic(err)
	}
	hash.Write([]byte(header))
	hash.Write([]byte(Encode(key)))
	return header + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// KeyIDFooter returns the key id wrapped in json, suitable for a paseto token's footer
func KeyIDFooter(key interface{ ExportBytes() []byte }) string {
	// KeyID never contains characters that need to be escaped
	return `{"kid":"` + KeyID(key) + `"}`
}

func ParseKeyIDFooter(s string) (string, error) {
	var footer struct {
		KeyID string `json:"kid"`
	}
	err := json.Unmarshal([]byte(s), &footer)
	if err != nil {
		return "", err
	}
	hasAcceptablePrefix := strings.HasPrefix(footer.KeyID, "k4.lid.") || strings.HasPrefix(footer.KeyID, "s4.sid.") || strings.HasPrefix(footer.KeyID, "k4.pid.")
	if !hasAcceptablePrefix {
		return "", fmt.Errorf("not a k4.lid/sid/pid token")
	}

	return footer.KeyID, nil
}
