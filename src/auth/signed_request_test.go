package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"testing"
	"time"
)

func testKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
	return priv, pubPEM
}

func signFields(t *testing.T, priv *rsa.PrivateKey, fields ...string) string {
	t.Helper()
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, MessageDigest(fields...))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestVerifySignedRequest(t *testing.T) {
	priv, pub := testKey(t)

	now := time.Now().UnixMilli()
	nonce := "0123456789abcdef0123456789abcdef"
	fields := []string{"alice", "bob"}

	sig := signFields(t, priv, fields[0], fields[1], strconv.FormatInt(now, 10), nonce)
	if err := VerifySignedRequest(pub, fields, strconv.FormatInt(now, 10), nonce, sig); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	old := now - (SignedRequestWindow + time.Minute).Milliseconds()
	sigOld := signFields(t, priv, fields[0], fields[1], strconv.FormatInt(old, 10), nonce)
	if err := VerifySignedRequest(pub, fields, strconv.FormatInt(old, 10), nonce, sigOld); err == nil {
		t.Fatal("expired timestamp accepted")
	}

	future := now + (SignedRequestWindow + time.Minute).Milliseconds()
	sigFut := signFields(t, priv, fields[0], fields[1], strconv.FormatInt(future, 10), nonce)
	if err := VerifySignedRequest(pub, fields, strconv.FormatInt(future, 10), nonce, sigFut); err == nil {
		t.Fatal("future timestamp accepted")
	}

	if err := VerifySignedRequest(pub, []string{"alice", "mallory"}, strconv.FormatInt(now, 10), nonce, sig); err == nil {
		t.Fatal("tampered fields accepted")
	}

	if err := VerifySignedRequest(pub, fields, strconv.FormatInt(now, 10), nonce, ""); err == nil {
		t.Fatal("missing signature accepted")
	}
}

func TestMessageDigestCrossLanguageAnchor(t *testing.T) {
	nonce := "abababababababababababababababab"
	digest := MessageDigest(
		"alice",
		"file-00000000-0000-0000-0000-000000000001",
		"1755000000123",
		nonce,
	)
	if got := hex.EncodeToString(digest); got != "9c951ff3125cba2f2ed75ea1914c6bdacb8b22892320c98307ccd0aec7bbcada" {
		t.Fatalf("cross-language anchor mismatch: %s", got)
	}
}

func TestCheckNonce(t *testing.T) {
	if CheckNonce("alice", "n1") {
		t.Fatal("first nonce reported as replay")
	}
	if !CheckNonce("alice", "n1") {
		t.Fatal("replayed nonce not detected")
	}
	if CheckNonce("alice", "n2") {
		t.Fatal("different nonce reported as replay")
	}
	if CheckNonce("bob", "n1") {
		t.Fatal("different user reported as replay")
	}
}

func TestVerifySignedRequestRequiresNonce(t *testing.T) {
	priv, pub := testKey(t)
	now := time.Now().UnixMilli()
	fields := []string{"alice", "bob"}
	nonce := "0123456789abcdef0123456789abcdef"
	sig := signFields(t, priv, fields[0], fields[1], strconv.FormatInt(now, 10), nonce)

	if err := VerifySignedRequest(pub, fields, strconv.FormatInt(now, 10), "", sig); err == nil {
		t.Fatal("missing nonce accepted")
	}
}

func TestCheckNonceMemoryBound(t *testing.T) {
	user := "memory-bound-test-user"
	for i := 0; i < nonceMaxPerUser+100; i++ {
		if CheckNonce(user, "nonce-"+strconv.Itoa(i)) {
			t.Fatalf("unexpected replay for new nonce %d", i)
		}
	}
	nonceMu.Lock()
	got := len(nonceSeen[user])
	nonceMu.Unlock()
	if got > nonceMaxPerUser {
		t.Fatalf("per-user nonce map grew to %d, want <= %d", got, nonceMaxPerUser)
	}
}
