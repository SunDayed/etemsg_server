// Package utils provides shared helpers: validation, ID generation, timestamps.
package utils

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

const (
	MinUserIDLen = 3
	MaxUserIDLen = 32
)

// IsValidUserID checks that user_id is 3-32 characters, alphanumeric + underscore.
func IsValidUserID(id string) bool {
	if len(id) < MinUserIDLen || len(id) > MaxUserIDLen {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_') {
			return false
		}
	}
	return true
}

// TrimSpace trims leading and trailing whitespace from a string.
func TrimSpace(s string) string {
	return strings.TrimSpace(s)
}

// fileIDRe matches a UUID v4 string. file_id is used directly as a disk
// filename (files/{file_id}.enc), so strict format validation is mandatory
// to prevent path traversal.
var fileIDRe = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsValidFileID checks that the given string is a well-formed UUID.
func IsValidFileID(id string) bool {
	return fileIDRe.MatchString(id)
}

// StartsWith checks if str starts with the given prefix.
func StartsWith(str, prefix string) bool {
	return strings.HasPrefix(str, prefix)
}

// IsPEM checks if the string looks like a PEM-encoded public key.
func IsPEM(s string) bool {
	return StartsWith(strings.TrimSpace(s), "-----BEGIN")
}

func PublicKeyID(publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("invalid public key: %w", err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal SPKI: %w", err)
	}

	sum := sha512.Sum512(der)
	return hex.EncodeToString(sum[:])[:10], nil
}

// GenerateMsgID creates a unique message ID using timestamp + random suffix.
func GenerateMsgID() string {
	return fmt.Sprintf("%d_%06d", time.Now().UnixMilli(), rand.Intn(900000)+100000)
}

// CurrentTimestamp returns epoch seconds as a float64 (with milliseconds).
func CurrentTimestamp() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}
