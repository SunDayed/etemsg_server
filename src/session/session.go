// Package session manages online user tracking and in-process message delivery.
// Design:
//   - A sync.RWMutex-protected map tracks online users and their WebSocket write channels.
//   - Per-user buffered channels serve as in-process message queues.
//   - A sender enqueues a message to the recipient's channel; the recipient's dispatcher
//     goroutine reads from the channel and writes to the WebSocket.
// This avoids the cross-goroutine WebSocket write issue (gorilla/websocket requires
// writes from a single goroutine per connection).
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

// SetOnline registers a user as online with their message channel.
// It returns the channel for the writer goroutine and a generation token
// that must be passed to SetOffline by the same connection.
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

// SetOffline removes a user from the online tracking table only if generation
// matches the current connection. This prevents an old connection's cleanup
// from closing the channel of a newer connection for the same user.
func (m *Manager) SetOffline(userID string, generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u, ok := m.users[userID]; ok && u.generation == generation {
		close(u.ch)
		delete(m.users, userID)
	}
}

// IsOnline returns true if the user has an active session.
func (m *Manager) IsOnline(userID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.users[userID]
	return ok
}

// EnqueueMessage pushes a message to an online user's channel (non-blocking).
// If the channel is full, the message is dropped (sender should be notified).
// Returns true if enqueued successfully.
// The RLock is held across the non-blocking send so SetOnline/SetOffline cannot
// close the channel concurrently and cause a send-on-closed-channel panic.
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
		// Queue full — drop the message
		return false
	}
}
