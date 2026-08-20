package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"e2e-msg-server/config"
	"e2e-msg-server/session"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"

	"github.com/gorilla/websocket"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.New() error = %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func ensureTestConfig() {
	config.Cfg = &config.Config{
		WSReadTimeout:  300,
		WSPingInterval: 30,
		WSWriteTimeout: 10,
		WSMaxPayload:   20 * 1024 * 1024,
	}
}

func validPublicKeyPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestRegisterRejectsInvalidPublicKey(t *testing.T) {
	st := newTestStore(t)
	h := HandleRegister(st)

	body := `{"user_id":"alice","public_key":"not-a-pem"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)

	var resp types.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "error" || resp.Error == nil || resp.Error.Code != "INVALID_PUBLIC_KEY" {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
}

func TestRegisterAcceptsValidPublicKey(t *testing.T) {
	st := newTestStore(t)
	h := HandleRegister(st)

	pub := validPublicKeyPEM(t)
	id, err := utils.PublicKeyID(pub)
	if err != nil {
		t.Fatalf("PublicKeyID() error = %v", err)
	}
	payload := map[string]string{"user_id": id, "public_key": pub}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h(rec, req)

	var resp types.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
}

func TestJSONBodyLimit(t *testing.T) {
	st := newTestStore(t)
	h := HandleRegister(st)

	// Build a JSON body larger than 8 MiB.
	huge := strings.Repeat("A", (8<<20)+1)
	body := `{"user_id":"alice","public_key":"` + huge + `"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)

	var resp types.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != "INVALID_JSON" {
		t.Fatalf("expected INVALID_JSON for oversized body, got: %s", rec.Body.String())
	}
}

func TestWSOriginCheck(t *testing.T) {
	ensureTestConfig()
	st := newTestStore(t)
	sm := session.NewManager()
	wsHandler := NewWSHandler(st, sm)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsHandler.ServeWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	// Same-origin request should upgrade successfully.
	header := http.Header{}
	header.Set("Origin", srv.URL)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("same-origin WS dial failed: %v", err)
	}
	conn.Close()

	// Cross-origin request should be rejected.
	badHeader := http.Header{}
	badHeader.Set("Origin", "http://evil.example")
	if _, _, err := websocket.DefaultDialer.Dial(wsURL, badHeader); err == nil {
		t.Fatal("cross-origin WS dial should have failed")
	}
}

func TestWSConnectRequiresToken(t *testing.T) {
	ensureTestConfig()
	st := newTestStore(t)
	if err := st.RegisterUser(context.Background(), "alice", validPublicKeyPEM(t)); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager()
	wsHandler := NewWSHandler(st, sm)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsHandler.ServeWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial failed: %v", err)
	}
	defer conn.Close()

	// Register user and issue a challenge/token path is not needed; just try connect without token.
	msg := types.WSEnvelope{
		Type: "connect",
		Payload: map[string]string{
			"user_id": "alice",
		},
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp types.WSEnvelope
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if resp.Type != "error" || resp.Error == nil || resp.Error.Code != "TOKEN_INVALID" {
		t.Fatalf("expected TOKEN_INVALID, got: %#v", resp)
	}
}

func TestWSCloseAll(t *testing.T) {
	ensureTestConfig()
	st := newTestStore(t)
	sm := session.NewManager()
	wsHandler := NewWSHandler(st, sm)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsHandler.ServeWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial failed: %v", err)
	}
	defer conn.Close()

	wsHandler.CloseAll()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected connection to be closed after CloseAll")
	}
}
