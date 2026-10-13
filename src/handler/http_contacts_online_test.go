package handler

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"e2e-msg-server/auth"
	"e2e-msg-server/session"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// Presence visibility must match "can message": only **mutual** contacts see each other online. The old
// code asked only "who added me", so a one-way add could see a peer online yet not message them.
func TestContactsOnlineRequiresMutualContact(t *testing.T) {
	ensureTestConfig()
	st := newTestStore(t)
	ctx := context.Background()

	priv := map[string]*rsa.PrivateKey{}
	// Ids must be globally unique: the auth package caches public keys by userID across tests, so a generic
	// name like "alice" collides with TestWSConnectRequiresToken and the signature is checked against its key.
	const alice, bob, carol = "online-alice", "online-bob", "online-carol"
	for _, u := range []string{alice, bob, carol} {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv[u] = k
		if err := st.RegisterUser(ctx, u, pemOf(t, k)); err != nil {
			t.Fatal(err)
		}
	}
	// alice -> bob (one-way); alice <-> carol (mutual).
	if _, err := st.AddContact(ctx, alice, bob); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddContact(ctx, alice, carol); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddContact(ctx, carol, alice); err != nil {
		t.Fatal(err)
	}

	sm := session.NewManager()
	for _, u := range []string{alice, bob, carol} {
		sm.SetOnline(u)
	}

	// The request deliberately carries both bob (not mutual) and carol (mutual).
	contacts := []string{bob, carol}
	fields := append([]string{alice}, contacts...)
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	// The nonce must be unique: auth.nonceSeen is **package-global** across tests, so a fixed value would be rejected as DUPLICATE_REQUEST on a second run.
	nonce := "nonce-mutual-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	digest := auth.MessageDigest(append(append([]string{}, fields...), ts, nonce)...)
	rawSig, err := rsa.SignPKCS1v15(rand.Reader, priv[alice], crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(rawSig)

	// Self-check with the key registered in the store, ruling out a broken signature first.
	regPub, gerr := st.GetPublicKey(ctx, alice)
	if gerr != nil {
		t.Fatalf("GetPublicKey(%s): %v", alice, gerr)
	}
	if verr := auth.VerifyMessageSignature(regPub, digest, sig); verr != nil {
		t.Fatalf("self-check failed: cannot verify the signature with %s's public key from the store: %v", alice, verr)
	}
	if regPub != pemOf(t, priv[alice]) {
		t.Fatalf("the store's public key for %s does not match this test's private key", alice)
	}
	tsMs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"user_id": alice, "contacts": contacts,
		// Send the **same ts used for signing**: a second time.Now() would differ by 1ms from the digest and always fail. It is an int64, so a string is INVALID_JSON.
		"timestamp": tsMs, "nonce": nonce, "signature": sig,
	})

	req := httptest.NewRequest(http.MethodPost, "/contacts/online", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	HandleContactsOnline(st, sm)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status  string                       `json:"status"`
		Payload types.ContactsOnlineResponse `json:"payload"`
		Error   *types.APIError              `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	if resp.Status != "ok" {
		t.Fatalf("want status=ok, got %q err=%+v (raw response: %s)",
			resp.Status, resp.Error, rec.Body.String())
	}
	for _, c := range resp.Payload.Online {
		if c == bob {
			t.Fatalf("one-way contact bob must not appear in the online list: %v", resp.Payload.Online)
		}
	}
	if len(resp.Payload.Online) != 1 || resp.Payload.Online[0] != carol {
		t.Fatalf("expected only mutual and online carol, got: %v", resp.Payload.Online)
	}
}

// filterMutualContacts is the single gate shared by all three presence paths.
func TestFilterMutualContacts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	// Ids completely different from the previous test: keys are cached by userID, so sharing "alice"/"bob" would overwrite them and fail verification at random.
	const fa, fb, fc = "filter-a", "filter-b", "filter-c"
	for _, u := range []string{fa, fb, fc} {
		if err := st.RegisterUser(ctx, u, validPublicKeyPEM(t)); err != nil {
			t.Fatal(err)
		}
	}
	// fa -> fb one-way; fa <-> fc mutual.
	if _, err := st.AddContact(ctx, fa, fb); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddContact(ctx, fa, fc); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddContact(ctx, fc, fa); err != nil {
		t.Fatal(err)
	}

	if got := filterMutualContacts(ctx, st, fa, []string{fb, fc}); len(got) != 1 || got[0] != fc {
		t.Fatalf("filterMutualContacts(%s) = %v, want [%s]", fa, got, fc)
	}
	if got := filterMutualContacts(ctx, st, fa, []string{"filter-zzz"}); len(got) != 0 {
		t.Fatalf("unknown users must not pass: %v", got)
	}
	if got := filterMutualContacts(ctx, st, fa, nil); len(got) != 0 {
		t.Fatalf("empty input should return empty: %v", got)
	}
}

// pemOf returns a PKIX public key PEM (for registration).
func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

var _ = utils.TrimSpace
