// Package session tracks online users and delivers messages in-process: an RWMutex-guarded map from
// user to write channel. Each user's buffered channel is fed by senders and drained by their
// dispatcher goroutine, which keeps gorilla/websocket's single-writer-per-connection rule.
package session

import (
	"sync"

	"e2e-msg-server/types"
)

// QueueBufferSize is the capacity of each user's in-process message channel.
const QueueBufferSize = 256

// userState holds the state for one online user.
type userState struct {
	generation uint64
	ch         chan *types.WSEnvelope // buffered channel for message forwarding
}

// Manager tracks online users and their message queues.
type Manager struct {
	mu       sync.RWMutex
	users    map[string]*userState // userID → state
	sequence uint64
}

// NewManager creates a new session Manager.
func NewManager() *Manager {
	return &Manager{
		users: make(map[string]*userState),
	}
}

// SetOnline registers a user as online with their message channel; it returns the channel for the
// writer goroutine and a generation token that the same connection must pass to SetOffline.
func (m *Manager) SetOnline(userID string) (chan *types.WSEnvelope, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If already online (reconnect), close old channel and replace.
	if old, ok := m.users[userID]; ok {
		close(old.ch)
	}

	m.sequence++
	ch := make(chan *types.WSEnvelope, QueueBufferSize)
	m.users[userID] = &userState{generation: m.sequence, ch: ch}
	return ch, m.sequence
}

// SetOffline removes a user only when generation matches the current connection, so an old
// connection's cleanup cannot close a new one's channel. It returns true only if the user **really**
// went offline, which gates the offline broadcast: a stale connection must not report a reconnected user.
func (m *Manager) SetOffline(userID string, generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u, ok := m.users[userID]; ok && u.generation == generation {
		close(u.ch)
		delete(m.users, userID)
		return true
	}
	return false
}

// IsOnline returns true if the user has an active session.
func (m *Manager) IsOnline(userID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.users[userID]
	return ok
}

// OnlineIDs returns a snapshot of which of the given user IDs are online, copied under one RLock so the caller can query or enqueue afterwards without holding it.
func (m *Manager) OnlineIDs(candidates []string) map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]bool, len(candidates))
	for _, id := range candidates {
		if _, ok := m.users[id]; ok {
			out[id] = true
		}
	}
	return out
}

// OnlineSet returns a snapshot of all online users as a set; the periodic presence snapshot does database work afterwards and must not hold the manager lock.
func (m *Manager) OnlineSet() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]bool, len(m.users))
	for id := range m.users {
		out[id] = true
	}
	return out
}

// EnqueueMessage pushes a message to an online user's channel (non-blocking); a full queue drops it
// and returns false. The RLock is held across the send so SetOnline/SetOffline cannot close the
// channel concurrently and panic with "send on closed channel".
func (m *Manager) EnqueueMessage(userID string, msg *types.WSEnvelope) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.users[userID]
	if !ok || u.ch == nil {
		return false
	}

	select {
	case u.ch <- msg:
		return true
	default:
		return false
	}
}
