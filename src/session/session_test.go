package session

import (
	"testing"

	"e2e-msg-server/types"
)

func TestSetOnlineEnqueueAndSetOffline(t *testing.T) {
	m := NewManager()
	ch, gen := m.SetOnline("alice")

	if !m.IsOnline("alice") {
		t.Fatal("expected alice to be online after SetOnline")
	}

	msg := &types.WSEnvelope{Type: "new_message"}
	if !m.EnqueueMessage("alice", msg) {
		t.Fatal("expected enqueue to succeed while online")
	}

	got := <-ch
	if got != msg {
		t.Fatalf("received wrong message: %#v", got)
	}

	m.SetOffline("alice", gen)
	if m.IsOnline("alice") {
		t.Fatal("expected alice to be offline after SetOffline")
	}
	if m.EnqueueMessage("alice", msg) {
		t.Fatal("expected enqueue to fail after SetOffline")
	}
}

func TestSetOnlineReplacesOldChannel(t *testing.T) {
	m := NewManager()
	oldCh, oldGen := m.SetOnline("alice")
	newCh, _ := m.SetOnline("alice")

	if _, ok := <-oldCh; ok {
		t.Fatal("expected old channel to be closed after reconnect")
	}

	// An old connection cleanup with the old generation must NOT mark the
	// current connection offline or close the new channel.
	m.SetOffline("alice", oldGen)
	if !m.IsOnline("alice") {
		t.Fatal("old connection cleanup should not disconnect the new connection")
	}

	msg := &types.WSEnvelope{Type: "new_message"}
	if !m.EnqueueMessage("alice", msg) {
		t.Fatal("expected enqueue to succeed on new channel")
	}
	got := <-newCh
	if got != msg {
		t.Fatalf("received wrong message: %#v", got)
	}
}

func TestSetOfflineOnlyMatchingGeneration(t *testing.T) {
	m := NewManager()
	_, gen1 := m.SetOnline("alice")
	_, gen2 := m.SetOnline("alice")

	m.SetOffline("alice", gen1)
	if !m.IsOnline("alice") {
		t.Fatal("SetOffline with old generation should not remove current session")
	}

	m.SetOffline("alice", gen2)
	if m.IsOnline("alice") {
		t.Fatal("SetOffline with current generation should remove session")
	}
}

func TestEnqueueMessageToUnknownUser(t *testing.T) {
	m := NewManager()
	if m.EnqueueMessage("nobody", &types.WSEnvelope{Type: "new_message"}) {
		t.Fatal("expected enqueue to fail for unknown user")
	}
}

// The offline broadcast hinges on this: only the connection that really took the user offline should trigger presence(offline).
func TestSetOfflineReportsRealTransition(t *testing.T) {
	m := NewManager()
	_, oldGen := m.SetOnline("alice")
	_, newGen := m.SetOnline("alice") // reconnect: the old connection's generation is stale

	if m.SetOffline("alice", oldGen) {
		t.Fatal("SetOffline from a stale connection must not report a real offline transition (it would broadcast offline by mistake)")
	}
	if !m.IsOnline("alice") {
		t.Fatal("alice should still be online (the new connection is valid)")
	}
	if !m.SetOffline("alice", newGen) {
		t.Fatal("SetOffline from the current connection should report offline")
	}
	if m.IsOnline("alice") {
		t.Fatal("alice should be offline")
	}
	if m.SetOffline("alice", newGen) {
		t.Fatal("a repeated SetOffline must not report offline again")
	}
}

func TestOnlineIDsSnapshot(t *testing.T) {
	m := NewManager()
	m.SetOnline("alice")
	m.SetOnline("carol")
	// bob is offline; dave is unregistered.

	got := m.OnlineIDs([]string{"alice", "bob", "carol", "dave"})
	if len(got) != 2 || !got["alice"] || !got["carol"] {
		t.Fatalf("unexpected OnlineIDs result: %#v", got)
	}
	if got["bob"] || got["dave"] {
		t.Fatalf("offline users must not appear: %#v", got)
	}
	// Snapshot: going online after it returns does not affect the result already taken.
	m.SetOnline("bob")
	if got["bob"] {
		t.Fatal("OnlineIDs must be a snapshot and must not change when others come online later")
	}
}

func TestOnlineSetSnapshot(t *testing.T) {
	m := NewManager()
	m.SetOnline("alice")
	m.SetOnline("bob")

	got := m.OnlineSet()
	if len(got) != 2 || !got["alice"] || !got["bob"] {
		t.Fatalf("OnlineSet() = %#v, want alice+bob", got)
	}
	m.SetOnline("carol")
	if got["carol"] {
		t.Fatal("OnlineSet must be a snapshot and must not change when others come online later")
	}
	if len(m.OnlineSet()) != 3 {
		t.Fatal("a fresh snapshot should include carol")
	}
}
