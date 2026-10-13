package store

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
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

func TestGroupDeleteCascadesChildren(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	gid := "cascade-group"
	if err := st.CreateGroup(ctx, &Group{GroupID: gid, NameEnc: []byte("n"), Creator: "cascade-owner"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddGroupMember(ctx, gid, "cascade-member", GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertGroupCursor(ctx, "cascade-member", gid, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendGroupMessage(ctx, &GroupMessage{
		GroupID: gid, Epoch: 0, Sender: "cascade-owner", MsgID: "cascade-msg", Ciphertext: "ct",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := st.DB().ExecContext(ctx, "DELETE FROM groups WHERE group_id = ?", gid); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"group_members", "group_cursor", "group_messages"} {
		var count int
		if err := st.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE group_id = ?", gid).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s still has %d orphan row(s); ON DELETE CASCADE is not active", table, count)
		}
	}
}

func TestConsumeLoginChallengeIsOneShot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.StoreLoginChallenge(ctx, "challenge-user", "challenge-one"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ConsumeLoginChallenge(ctx, "challenge-user")
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if got != "challenge-one" {
		t.Fatalf("consume = %q, want challenge-one", got)
	}
	if _, err := st.ConsumeLoginChallenge(ctx, "challenge-user"); err == nil {
		t.Fatal("second consume must fail; a challenge is one-shot")
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

// ContactsOf: reverse lookup of "who added me", which decides who receives presence broadcasts.
func TestContactsOfReverseLookup(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	for _, u := range []string{"alice", "bob", "carol"} {
		if err := st.RegisterUser(ctx, u, "KEY_"+u); err != nil {
			t.Fatal(err)
		}
	}
	// alice -> bob, carol -> bob (a one-way add is enough to see bob's presence).
	if _, err := st.AddContact(ctx, "alice", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddContact(ctx, "carol", "bob"); err != nil {
		t.Fatal(err)
	}
	// bob -> alice: bob added alice, so bob can see alice, but not the other way round.
	if _, err := st.AddContact(ctx, "bob", "alice"); err != nil {
		t.Fatal(err)
	}

	got, err := st.ContactsOf(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "alice" || got[1] != "carol" {
		t.Fatalf("ContactsOf(bob) = %#v, want [alice carol]", got)
	}

	// alice is added only by bob -> only bob can see alice online.
	got, err = st.ContactsOf(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "bob" {
		t.Fatalf("ContactsOf(alice) = %#v, want [bob]", got)
	}

	// A user nobody added -> empty (not nil, so callers can range directly).
	got, err = st.ContactsOf(ctx, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("should return an empty slice, not nil")
	}
	if len(got) != 0 {
		t.Fatalf("ContactsOf(carol) = %#v, want empty", got)
	}
}

// idx_contacts_contact must exist: the presence reverse lookup (WHERE contact_id = ?) depends on it, or every connect/disconnect does a full scan.
func TestContactsContactIDIndexExists(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	rows, err := st.DB().QueryContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='contacts'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	found := false
	for _, n := range names {
		if n == "idx_contacts_contact" {
			found = true
		}
	}
	if !found {
		t.Fatalf("contacts table is missing the idx_contacts_contact index; existing indexes: %v", names)
	}
}

// TestAppendWelcomeEnforcesGroupMemberLimit guards the member cap (MaxGroupMembers), which applies
// only when a Welcome **really adds** someone: a repeat Welcome to an existing member stays idempotent.
func TestAppendWelcomeEnforcesGroupMemberLimit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	gid := "limitgroup1"
	if err := st.CreateGroup(ctx, &Group{
		GroupID: gid, NameEnc: []byte("n"), Creator: "owner_x",
	}); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// Creating the group already gives 1 member (the creator); top it up to exactly MaxGroupMembers.
	for i := 1; i < MaxGroupMembers; i++ {
		u := "m" + strconv.Itoa(i)
		if err := st.AddGroupMember(ctx, gid, u, GroupRoleMember, 0); err != nil {
			t.Fatalf("add member %s: %v", u, err)
		}
	}
	members, err := st.ListGroupMembers(ctx, gid)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(members) != MaxGroupMembers {
		t.Fatalf("expected %d members, got %d", MaxGroupMembers, len(members))
	}

	entry := func(target string) *GroupMLSLogEntry {
		return &GroupMLSLogEntry{
			GroupID: gid, Epoch: 1, Kind: "welcome",
			Sender: "owner_x", Target: target,
			DataB64: "AAAA", DataHash: "h",
		}
	}

	// Member 1001 must be rejected.
	if _, err := st.AppendWelcome(ctx, entry("too_late")); !errors.Is(err, ErrGroupFull) {
		t.Fatalf("expected ErrGroupFull for a new member on a full group, got %v", err)
	}

	// A repeat Welcome for an existing member must still succeed (idempotent) and add nobody.
	if _, err := st.AppendWelcome(ctx, entry("m1")); err != nil {
		t.Fatalf("re-welcome of an existing member must stay idempotent, got %v", err)
	}
	members, err = st.ListGroupMembers(ctx, gid)
	if err != nil {
		t.Fatalf("list members after re-welcome: %v", err)
	}
	if len(members) != MaxGroupMembers {
		t.Fatalf("member count must not change, got %d", len(members))
	}

	// After freeing a slot a newcomer can join again.
	if err := st.RemoveGroupMember(ctx, gid, "m1"); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if _, err := st.AppendWelcome(ctx, entry("now_ok")); err != nil {
		t.Fatalf("expected a free slot to accept a new member, got %v", err)
	}
}
