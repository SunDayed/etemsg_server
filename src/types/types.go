// Package types defines shared data structures used across all packages.
package types


// RegisterRequest is the JSON body for POST /register.
type RegisterRequest struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
}

// LoginChallengeRequest requests a challenge for login verification.
type LoginChallengeRequest struct {
	UserID string `json:"user_id"`
}

// LoginChallengeResponse returns a random challenge the client must sign.
type LoginChallengeResponse struct {
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
}

// LoginVerifyRequest sends the signed challenge to complete login.
type LoginVerifyRequest struct {
	UserID    string `json:"user_id"`
	Signature string `json:"signature"` // base64-encoded signature of the challenge
}

// LoginResponse is returned after successful login verification.
type LoginResponse struct {
	UserID    string   `json:"user_id"`
	PublicKey string   `json:"public_key"`
	Contacts  []string `json:"contacts"`
	Token     string   `json:"token,omitempty"`
}

// AddContactRequest is the JSON body for POST /add_contact.
type AddContactRequest struct {
	UserID        string `json:"user_id"`
	ContactUserID string `json:"contact_user_id"`
	Timestamp     int64  `json:"timestamp,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

// AddContactResponse is returned after adding a contact.
type AddContactResponse struct {
	ContactUserID string `json:"contact_user_id"`
	PublicKey     string `json:"public_key"`
}

// GetOfflineMsgRequest is the JSON body for POST /get_offline_msg.
type GetOfflineMsgRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GetOfflineMsgResponse wraps the array of offline messages.
type GetOfflineMsgResponse struct {
	Messages []OfflineMessage `json:"messages"`
}

// ContactsOnlineRequest asks for the online state of the caller's contacts. The caller submits the
// ids they explicitly added, so the server never leaks anyone else — matching the client's own policy.
type ContactsOnlineRequest struct {
	UserID    string   `json:"user_id"`
	Contacts  []string `json:"contacts"`
	Timestamp int64    `json:"timestamp,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	Signature string   `json:"signature,omitempty"`
}

// ContactsOnlineResponse lists which of the requested contacts are online.
type ContactsOnlineResponse struct {
	Online []string `json:"online"`
}

// PresencePayload is pushed over WebSocket when a contact goes online/offline.
type PresencePayload struct {
	UserID string `json:"user_id"`
	Online bool   `json:"online"`
}

// PresenceSnapshotPayload is pushed periodically (every 30s) to each online user: the authoritative
// presence of their contacts. Clients replace the map wholesale, so one lost delta self-heals in a period.
type PresenceSnapshotPayload struct {
	Contacts map[string]bool `json:"contacts"`
}

// OfflineMessage represents one stored encrypted message.
type OfflineMessage struct {
	From       string  `json:"from"`
	Ciphertext string  `json:"ciphertext"`
	IV         string  `json:"iv,omitempty"`
	Tag        string  `json:"tag,omitempty"`
	MsgID      string  `json:"msg_id"`
	Timestamp  float64 `json:"timestamp"`
	MsgType    string  `json:"msg_type,omitempty"` // "text" (default) | "file"
	FileID     string  `json:"file_id,omitempty"`  // uuid4, download index
	Filename   string  `json:"filename,omitempty"` // display metadata (plaintext)
	Size       int64   `json:"size,omitempty"`
	SHA256     string  `json:"sha256,omitempty"`
	WrappedKey string  `json:"wrapped_key,omitempty"` // RSA-encrypted AES key
	Signature  string  `json:"signature,omitempty"`
}


// Response is the standard HTTP JSON response envelope.
type Response struct {
	Status  string      `json:"status"`
	Payload interface{} `json:"payload,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// APIError represents an error code + message.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}


// WSEnvelope is the standard WebSocket JSON message envelope.
type WSEnvelope struct {
	Type      string      `json:"type"`
	Status    string      `json:"status,omitempty"`
	Payload   interface{} `json:"payload,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
}

// ConnectPayload is the payload for the WS "connect" message.
type ConnectPayload struct {
	UserID string `json:"user_id"`
	Token  string `json:"token,omitempty"`
}

// SendMessagePayload is the payload the sender submits for "send_message".
type SendMessagePayload struct {
	To         string  `json:"to"`
	Ciphertext string  `json:"ciphertext"`
	IV         string  `json:"iv,omitempty"`
	Tag        string  `json:"tag,omitempty"`
	MsgID      string  `json:"msg_id,omitempty"`
	Timestamp  float64 `json:"timestamp,omitempty"`
	MsgType    string  `json:"msg_type,omitempty"` // "text" (default) | "file"
	FileID     string  `json:"file_id,omitempty"`  // uuid4, download index
	Filename   string  `json:"filename,omitempty"` // display metadata (plaintext)
	Size       int64   `json:"size,omitempty"`
	SHA256     string  `json:"sha256,omitempty"`
	WrappedKey string  `json:"wrapped_key,omitempty"` // RSA-encrypted AES key
	Signature  string  `json:"signature,omitempty"`
}

// FileUploadResponse is returned by POST /upload_file after the ciphertext is stored.
type FileUploadResponse struct {
	FileID string `json:"file_id"`
	Size   int64  `json:"size"`
}

// SendMessageAck is the acknowledgment sent back to the sender; on rejection Error is set and
// Delivered=false, e.g. NOT_MUTUAL or MESSAGE_NOT_ENCRYPTED (a text message missing wrapped_key/iv/tag).
type SendMessageAck struct {
	MsgID     string    `json:"msg_id"`
	To        string    `json:"to"`
	Delivered bool      `json:"delivered"`
	Timestamp float64   `json:"timestamp"`
	Error     *APIError `json:"error,omitempty"`
}

// NewMessagePayload is pushed to the recipient when a message is forwarded.
type NewMessagePayload struct {
	From       string  `json:"from"`
	Ciphertext string  `json:"ciphertext"`
	IV         string  `json:"iv,omitempty"`
	Tag        string  `json:"tag,omitempty"`
	MsgID      string  `json:"msg_id"`
	Timestamp  float64 `json:"timestamp"`
	MsgType    string  `json:"msg_type,omitempty"` // "text" (default) | "file"
	FileID     string  `json:"file_id,omitempty"`  // uuid4, download index
	Filename   string  `json:"filename,omitempty"` // display metadata (plaintext)
	Size       int64   `json:"size,omitempty"`
	SHA256     string  `json:"sha256,omitempty"`
	WrappedKey string  `json:"wrapped_key,omitempty"` // RSA-encrypted AES key
	Signature  string  `json:"signature,omitempty"`
}

// HeartbeatPayload is the payload for heartbeat responses.
type HeartbeatPayload struct {
	Online bool `json:"online"`
}

// PendingContactsRequest is the body of POST /contacts/pending_incoming.
type PendingContactsRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// PendingContactInfo is one inbound, not-yet-reciprocated contact request.
type PendingContactInfo struct {
	UserID string `json:"user_id"`
}

// ContactNotifyPayload is the WS payload of `contact_notify`, pushed to the target of a one-sided
// contact add so they can add back from the notification centre. No group_id: not a group notification.
type ContactNotifyPayload struct {
	From   string `json:"from"`
	Reason string `json:"reason"`
}
