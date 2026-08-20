package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)


// ciphertext, iv, tag, wrapped_key, file_id, filename, size, sha256
func MessageDigest(fields ...string) []byte {
	h := sha256.New()
	for i, f := range fields {
		if i > 0 {
			h.Write([]byte{'\n'})
		}
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

func VerifyMessageSignature(pubKeyPEM string, digest []byte, signatureB64 string) error {
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
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig)

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, sig) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil

	case ed25519.PublicKey:
		if !ed25519.Verify(key, digest, sig) {
			return errors.New("Ed25519 signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", key)
	}
}
