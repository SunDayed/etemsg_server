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

	header := http.Header{}
	header.Set("Origin", srv.URL)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("same-origin WS dial failed: %v", err)
	}
	conn.Close()

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

// The read deadline must **slide**: a client that keeps heartbeating must not be dropped at WSReadTimeout (the old code set it once at connect).
func TestWSReadDeadlineSlidesOnInboundTraffic(t *testing.T) {
	ensureTestConfig()
	// 1s read timeout, long ping interval: any extension can only come from the client's own heartbeat, not from a pong triggered by a server ping.
	config.Cfg.WSReadTimeout = 1
	config.Cfg.WSPingInterval = 60

	st := newTestStore(t)
	ctx := context.Background()
	if err := st.RegisterUser(ctx, "alice", validPublicKeyPEM(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.StoreToken(ctx, "alice", "tok-1", time.Now().Add(time.Hour).Unix()); err != nil {
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

	if err := conn.WriteJSON(types.WSEnvelope{
		Type:    "connect",
		Payload: map[string]string{"user_id": "alice", "token": "tok-1"},
	}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var ack types.WSEnvelope
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read connect ack: %v", err)
	}
	if ack.Type != "connect" || ack.Error != nil {
		t.Fatalf("expected successful connect, got %#v", ack)
	}

	// Keep heartbeating across three WSReadTimeout periods.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := conn.WriteJSON(types.WSEnvelope{Type: "heartbeat"}); err != nil {
			t.Fatalf("heartbeat write failed (connection dropped by read timeout?): %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Well past the 1s read timeout: without sliding, the server would have dropped us long ago.
	if !sm.IsOnline("alice") {
		t.Fatal("connection dropped while heartbeating: the read timeout was not extended")
	}
	// Send another heartbeat and read the server reply: the connection is **still usable both ways** (stronger than reading a nonexistent message, which only blocks).
	if err := conn.WriteJSON(types.WSEnvelope{Type: "heartbeat"}); err != nil {
		t.Fatalf("heartbeat send failed: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var hb types.WSEnvelope
	if err := conn.ReadJSON(&hb); err != nil {
		t.Fatalf("heartbeat reply read failed (connection may have been dropped by read timeout): %v", err)
	}
	if hb.Type != "heartbeat" {
		t.Fatalf("want heartbeat reply, got %#v", hb)
	}
}

// An idle connection (no data at all) must still be reclaimed after WSReadTimeout so half-dead connections do not linger.
func TestWSReadDeadlineClosesIdleConnection(t *testing.T) {
	ensureTestConfig()
	config.Cfg.WSReadTimeout = 1
	config.Cfg.WSPingInterval = 60 // long, so pong refreshes do not interfere

	st := newTestStore(t)
	ctx := context.Background()
	if err := st.RegisterUser(ctx, "bob", validPublicKeyPEM(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.StoreToken(ctx, "bob", "tok-2", time.Now().Add(time.Hour).Unix()); err != nil {
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

	if err := conn.WriteJSON(types.WSEnvelope{
		Type:    "connect",
		Payload: map[string]string{"user_id": "bob", "token": "tok-2"},
	}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var ack types.WSEnvelope
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read connect ack: %v", err)
	}

	// Then send nothing and wait past the read timeout.
	time.Sleep(2500 * time.Millisecond)
	if sm.IsOnline("bob") {
		t.Fatal("idle connection should be reclaimed after WSReadTimeout, but is still online")
	}
}
