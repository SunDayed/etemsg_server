package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"e2e-msg-server/types"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestUserLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.RegisterUser(ctx, "alice", "PUBLIC_KEY"); err != nil {
		t.Fatalf("RegisterUser() error = %v", err)
	}

	exists, err := st.UserExists(ctx, "alice")
	if err != nil {
		t.Fatalf("UserExists() error = %v", err)
	}
	if !exists {
		t.Fatal("expected user to exist")
	}

	pub, err := st.GetPublicKey(ctx, "alice")
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}
	if pub != "PUBLIC_KEY" {
		t.Fatalf("GetPublicKey() = %q, want PUBLIC_KEY", pub)
	}

	_, contacts, err := st.GetUserInfo(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserInfo() error = %v", err)
	}
	if len(contacts) != 0 {
		t.Fatalf("expected no contacts, got %v", contacts)
	}
}

func TestContactsAndMutualCheck(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.RegisterUser(ctx, "alice", "PUBLIC_KEY_A"); err != nil {
		t.Fatal(err)
	}
	if err := st.RegisterUser(ctx, "bob", "PUBLIC_KEY_B"); err != nil {
		t.Fatal(err)
	}

	if _, err := st.AddContact(ctx, "alice", "bob"); err != nil {
		t.Fatalf("AddContact() error = %v", err)
	}

	mutual, err := st.IsMutualContact(ctx, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if mutual {
		t.Fatal("expected not mutual with only one direction")
	}

	if _, err := st.AddContact(ctx, "bob", "alice"); err != nil {
		t.Fatalf("AddContact() error = %v", err)
	}

	mutual, err = st.IsMutualContact(ctx, "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if !mutual {
		t.Fatal("expected mutual after both directions added")
	}
}

func TestOfflineMessagesFetchAndClear(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	msg := &types.OfflineMessage{
		From:       "alice",
		Ciphertext: "cipher",
		IV:         "iv",
		Tag:        "tag",
		MsgID:      "msg-1",
		Timestamp:  123.456,
		MsgType:    "text",
		Signature:  "sig",
	}
	if err := st.PushOfflineMsg(ctx, "bob", msg); err != nil {
		t.Fatalf("PushOfflineMsg() error = %v", err)
	}

	msgs, err := st.FetchAndClearOfflineMsgs(ctx, "bob")
	if err != nil {
		t.Fatalf("FetchAndClearOfflineMsgs() error = %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].MsgID != "msg-1" || msgs[0].Signature != "sig" {
		t.Fatalf("unexpected offline message: %#v", msgs[0])
	}

	msgs, err = st.FetchAndClearOfflineMsgs(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected empty queue after fetch-and-clear, got %d", len(msgs))
	}
}

func TestAuthTokenStoreAndGet(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.StoreToken(ctx, "alice", "token-1", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("StoreToken() error = %v", err)
	}

	token, expiresAt, err := st.GetToken(ctx, "alice")
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if token != "token-1" {
		t.Fatalf("token = %q, want token-1", token)
	}
	if expiresAt <= time.Now().Unix() {
		t.Fatalf("expiresAt = %d, want future", expiresAt)
	}
}

func TestFileMetaLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	meta := &FileMeta{
		FileID:    "6c5c869d-d4ff-4b79-8d66-71090d3ae026",
		Sender:    "alice",
		Owner:     "bob",
		Filename:  "name",
		Size:      123,
		SHA256:    "abc",
		Status:    "ready",
		CreatedAt: time.Now().Unix(),
	}
	if err := st.SaveFileMeta(ctx, meta); err != nil {
		t.Fatalf("SaveFileMeta() error = %v", err)
	}

	got, err := st.GetFileMeta(ctx, meta.FileID)
	if err != nil {
		t.Fatalf("GetFileMeta() error = %v", err)
	}
	if got.Owner != "bob" || got.Size != 123 {
		t.Fatalf("unexpected file meta: %#v", got)
	}

	if err := st.DeleteFileMeta(ctx, meta.FileID); err != nil {
		t.Fatalf("DeleteFileMeta() error = %v", err)
	}
	if _, err := st.GetFileMeta(ctx, meta.FileID); err != ErrFileNotFound {
		t.Fatalf("expected ErrFileNotFound, got %v", err)
	}
}

func TestOfflineMessageQueueLimit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < MaxOfflineMessagesPerUser; i++ {
		msg := &types.OfflineMessage{
			From:       "alice",
			Ciphertext: "cipher",
			MsgID:      "msg-" + string(rune('a'+i%26)) + string(rune('0'+i%10)),
			Timestamp:  float64(i),
		}
		if err := st.PushOfflineMsg(ctx, "bob", msg); err != nil {
			t.Fatalf("PushOfflineMsg(%d) error = %v", i, err)
		}
	}

	overflow := &types.OfflineMessage{
		From:       "alice",
		Ciphertext: "overflow",
		MsgID:      "overflow",
		Timestamp:  999,
	}
	if err := st.PushOfflineMsg(ctx, "bob", overflow); err != ErrOfflineQueueFull {
		t.Fatalf("expected ErrOfflineQueueFull, got %v", err)
	}
}
