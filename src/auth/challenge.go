// Package auth implements challenge-response signature verification for login.
// Signature convention:
//	RSA:    MD5( challenge_hex )  →  RSA sign (PKCS1v15, SHA256)  →  base64
//	ECDSA:  SHA256( challenge )   →  ECDSA sign (ASN1 DER)         →  base64
//	Ed25519: raw challenge bytes  →  Ed25519 sign                  →  base64
// Login flow:
//  1. Client POSTs user_id → server generates random challenge, stores in SQLite (TTL 300s).
//  2. Client signs the challenge with their private key, sends base64(signature) back.
//  3. Server verifies signature against the stored public key, returns user info on success.
package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// ChallengeLength is the number of random bytes in a login challenge.
const ChallengeLength = 32

// GenerateChallenge creates a random challenge string (hex-encoded).
func GenerateChallenge() (string, error) {
	b := make([]byte, ChallengeLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate challenge: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// VerifySignature checks that the base64-encoded signature matches the
// challenge when verified with the given PEM-encoded public key.
// For RSA keys, the convention is:
//	MD5(challenge) → verify PKCS1v15 signature
// Returns nil if verification succeeds, or an error describing the failure.
func VerifySignature(pubKeyPEM string, challenge string, signatureB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	pubKey, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return err
	}

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// MD5(challenge) → hex string → RSA PKCS1v15 SHA256
		md5Hash := md5.Sum([]byte(challenge))
		md5Hex := fmt.Sprintf("%x", md5Hash)
		digest := sha256.Sum256([]byte(md5Hex))
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig)

	case *ecdsa.PublicKey:
		digest := sha256.Sum256([]byte(challenge))
		if !ecdsa.VerifyASN1(key, digest[:], sig) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil

	case ed25519.PublicKey:
		if !ed25519.Verify(key, []byte(challenge), sig) {
			return errors.New("Ed25519 signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", key)
	}
}

// ParsePublicKey decodes a PEM-encoded public key (PKIX/SPKI or PKCS1).
// It is exported so registration can validate the key before persisting it.
func ParsePublicKey(pemStr string) (interface{}, error) {
	return parsePublicKey(pemStr)
}

// parsePublicKey decodes a PEM-encoded public key (PKIX/SPKI or PKCS1).
func parsePublicKey(pemStr string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// PKIX/SPKI first (-----BEGIN PUBLIC KEY-----)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pub, nil
	}

	// PKCS1 legacy RSA (-----BEGIN RSA PUBLIC KEY-----)
	pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return pub, nil
	}

	return nil, fmt.Errorf("unsupported public key format: %s", block.Type)
}
