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

	// Old channel must be closed by the replacement.
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
