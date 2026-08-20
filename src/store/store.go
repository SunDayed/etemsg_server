// Package store provides SQLite persistence for the E2E message server.
// It stores users, contacts, offline messages, login challenges, and file
// metadata. SQLite (modernc.org/sqlite, pure Go, no CGO) replaces the former
// SQLite backend — suitable for single-instance deployment. Online status is
// NOT persisted here: it lives in the in-process session.Manager, which is the
// authoritative source for message delivery decisions.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"e2e-msg-server/types"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database handle.
type Store struct {
	db *sql.DB
}

// FileMeta describes an encrypted file stored on disk (files/{file_id}.enc).
// The server only ever holds ciphertext; FileMeta carries display metadata.
type FileMeta struct {
	FileID    string `json:"file_id"`
	Sender    string `json:"sender"` // uploader
	Owner     string `json:"owner"`  // recipient — download authorization
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Status    string `json:"status"` // "ready"
	CreatedAt int64  `json:"created_at"`
}

// New opens (or creates) the SQLite database at dbPath and ensures all tables exist.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite allows a single writer — serialize all database access.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite pragma %q: %w", pragma, err)
		}
	}

	if err := createTables(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

func createTables(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			user_id    TEXT PRIMARY KEY,
			public_key TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS contacts (
			user_id    TEXT NOT NULL,
			contact_id TEXT NOT NULL,
			PRIMARY KEY (user_id, contact_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id)`,
		`CREATE TABLE IF NOT EXISTS offline_messages (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			recipient    TEXT NOT NULL,
			sender       TEXT NOT NULL,
			ciphertext   TEXT NOT NULL,
			iv           TEXT DEFAULT '',
			tag          TEXT DEFAULT '',
			msg_id       TEXT NOT NULL,
			timestamp    REAL,
			created_at   INTEGER NOT NULL,
			msg_type     TEXT DEFAULT '',
			file_id      TEXT DEFAULT '',
			filename     TEXT DEFAULT '',
			size         INTEGER DEFAULT 0,
			sha256       TEXT DEFAULT '',
			wrapped_key  TEXT DEFAULT '',
			signature    TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_offline_recipient ON offline_messages(recipient)`,
		`CREATE TABLE IF NOT EXISTS login_challenges (
			user_id    TEXT PRIMARY KEY,
			challenge  TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS auth_tokens (
			user_id    TEXT PRIMARY KEY,
			token      TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS files (
			file_id    TEXT PRIMARY KEY,
			sender     TEXT NOT NULL,
			owner      TEXT NOT NULL,
			filename   TEXT NOT NULL,
			size       INTEGER NOT NULL,
			sha256     TEXT NOT NULL,
			status     TEXT NOT NULL DEFAULT 'ready',
			created_at INTEGER NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
	}
	if err := migrateOfflineMsgColumns(db); err != nil {
		return err
	}
	return nil
}

// migrateOfflineMsgColumns adds the file-transfer columns to offline_messages
// on databases created before the feature existed (ALTER TABLE ADD COLUMN).
func migrateOfflineMsgColumns(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(offline_messages)")
	if err != nil {
		return fmt.Errorf("inspect offline_messages: %w", err)
	}
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype, dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan table_info: %w", err)
		}
		cols[name.(string)] = true
	}
	rows.Close()

	adds := []string{
		"msg_type TEXT DEFAULT ''",
		"file_id TEXT DEFAULT ''",
		"filename TEXT DEFAULT ''",
		"size INTEGER DEFAULT 0",
		"sha256 TEXT DEFAULT ''",
		"wrapped_key TEXT DEFAULT ''",
		"signature TEXT DEFAULT ''",
	}
	for _, def := range adds {
		col := strings.Fields(def)[0]
		if cols[col] {
			continue
		}
		if _, err := db.Exec("ALTER TABLE offline_messages ADD COLUMN " + def); err != nil {
			return fmt.Errorf("migrate offline_messages.%s: %w", col, err)
		}
	}
	return nil
}

// ─── Users ──────────────────────────────────────────────────────────

// UserExists returns true if the user is already registered.
func (s *Store) UserExists(ctx context.Context, userID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM users WHERE user_id = ?", userID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check user exists: %w", err)
	}
	return true, nil
}

// RegisterUser stores a user's public key.
func (s *Store) RegisterUser(ctx context.Context, userID, publicKey string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO users (user_id, public_key, created_at) VALUES (?, ?, ?)",
		userID, publicKey, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("register user: %w", err)
	}
	return nil
}

// ErrUserNotFound is returned when a user does not exist.
var ErrUserNotFound = errors.New("user not found")

// GetPublicKey returns the PEM-encoded public key for a user.
func (s *Store) GetPublicKey(ctx context.Context, userID string) (string, error) {
	var pubKey string
	err := s.db.QueryRowContext(ctx,
		"SELECT public_key FROM users WHERE user_id = ?", userID).Scan(&pubKey)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}
	if err != nil {
		return "", fmt.Errorf("get public key: %w", err)
	}
	return pubKey, nil
}

// GetContacts returns the list of contact user IDs for a user.
func (s *Store) GetContacts(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT contact_id FROM contacts WHERE user_id = ? ORDER BY contact_id", userID)
	if err != nil {
		return nil, fmt.Errorf("get contacts: %w", err)
	}
	defer rows.Close()

	contacts := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("scan contact: %w", err)
		}
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

// GetUserInfo returns the public key and contacts for a user.
func (s *Store) GetUserInfo(ctx context.Context, userID string) (pubKey string, contacts []string, err error) {
	pubKey, err = s.GetPublicKey(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	contacts, err = s.GetContacts(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	if contacts == nil {
		contacts = []string{}
	}
	return pubKey, contacts, nil
}

// ─── Contacts ───────────────────────────────────────────────────────

// ContactExists returns true if the user exists in the global user index.
func (s *Store) ContactExists(ctx context.Context, contactID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM users WHERE user_id = ?", contactID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check contact exists: %w", err)
	}
	return true, nil
}

// AddContact adds a one-way contact relationship (userID → contactID) and
// returns the contact's public key.
func (s *Store) AddContact(ctx context.Context, userID, contactID string) (string, error) {
	var pubKey string
	err := s.db.QueryRowContext(ctx,
		"SELECT public_key FROM users WHERE user_id = ?", contactID).Scan(&pubKey)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("user not found: %s", contactID)
	}
	if err != nil {
		return "", fmt.Errorf("add contact: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("add contact tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		"INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)",
		userID, contactID); err != nil {
		return "", fmt.Errorf("add contact: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("add contact commit: %w", err)
	}
	return pubKey, nil
}

// IsMutualContact reports whether both directions of the relationship exist:
// (a → b) AND (b → a). Messaging (WS send_message / upload_file) requires a
// mutual relationship — a one-way add is not enough to exchange messages.
func (s *Store) IsMutualContact(ctx context.Context, a, b string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM contacts
		 WHERE (user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)`,
		a, b, b, a).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check mutual contact: %w", err)
	}
	return n == 2, nil
}

// MaxOfflineMessagesPerUser is the maximum number of queued offline messages per user.
const MaxOfflineMessagesPerUser = 1000

// ErrOfflineQueueFull is returned when a user already has MaxOfflineMessagesPerUser messages.
var ErrOfflineQueueFull = errors.New("offline message queue full")

// ─── Offline messages ───────────────────────────────────────────────

// PushOfflineMsg stores an encrypted message in the user's offline queue.
// It rejects the message when the queue already has MaxOfflineMessagesPerUser entries.
func (s *Store) PushOfflineMsg(ctx context.Context, userID string, msg *types.OfflineMessage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("push offline tx: %w", err)
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM offline_messages WHERE recipient = ?", userID).Scan(&count); err != nil {
		return fmt.Errorf("count offline msgs: %w", err)
	}
	if count >= MaxOfflineMessagesPerUser {
		return ErrOfflineQueueFull
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO offline_messages
		   (recipient, sender, ciphertext, iv, tag, msg_id, timestamp, created_at,
		    msg_type, file_id, filename, size, sha256, wrapped_key, signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, msg.From, msg.Ciphertext, msg.IV, msg.Tag, msg.MsgID, msg.Timestamp, time.Now().Unix(),
		msg.MsgType, msg.FileID, msg.Filename, msg.Size, msg.SHA256, msg.WrappedKey, msg.Signature)
	if err != nil {
		return fmt.Errorf("push offline msg: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit offline msg: %w", err)
	}
	return nil
}

// FetchAndClearOfflineMsgs atomically fetches all offline messages and clears the queue.
func (s *Store) FetchAndClearOfflineMsgs(ctx context.Context, userID string) ([]types.OfflineMessage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch offline tx: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx,
		`SELECT sender, ciphertext, iv, tag, msg_id, timestamp,
		        msg_type, file_id, filename, size, sha256, wrapped_key, signature
		 FROM offline_messages WHERE recipient = ? ORDER BY id`, userID)
	if err != nil {
		return nil, fmt.Errorf("fetch offline msgs: %w", err)
	}

	msgs := []types.OfflineMessage{}
	for rows.Next() {
		var m types.OfflineMessage
		if err := rows.Scan(&m.From, &m.Ciphertext, &m.IV, &m.Tag, &m.MsgID, &m.Timestamp,
			&m.MsgType, &m.FileID, &m.Filename, &m.Size, &m.SHA256, &m.WrappedKey, &m.Signature); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan offline msg: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM offline_messages WHERE recipient = ?", userID); err != nil {
		return nil, fmt.Errorf("clear offline msgs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit offline fetch: %w", err)
	}
	return msgs, nil
}

// ─── Login challenges ───────────────────────────────────────────────

// ChallengeTTL is how long a login challenge stays valid.
const ChallengeTTL = 300 * time.Second

// StoreLoginChallenge saves a challenge string for the user with a TTL.
func (s *Store) StoreLoginChallenge(ctx context.Context, userID, challenge string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO login_challenges (user_id, challenge, expires_at)
		 VALUES (?, ?, ?)`,
		userID, challenge, time.Now().Add(ChallengeTTL).Unix())
	if err != nil {
		return fmt.Errorf("store challenge: %w", err)
	}
	return nil
} // PeekLoginChallenge returns the stored challenge without consuming it.
// Expired challenges are treated as absent.
func (s *Store) PeekLoginChallenge(ctx context.Context, userID string) (string, error) {
	var challenge string
	err := s.db.QueryRowContext(ctx,
		"SELECT challenge FROM login_challenges WHERE user_id = ? AND expires_at > ?",
		userID, time.Now().Unix()).Scan(&challenge)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no challenge found for user: %s", userID)
	}
	if err != nil {
		return "", fmt.Errorf("peek challenge: %w", err)
	}
	return challenge, nil
}

// DeleteLoginChallenge removes a login challenge after successful login.
func (s *Store) DeleteLoginChallenge(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM login_challenges WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("delete challenge: %w", err)
	}
	return nil
}

// ─── Auth tokens ────────────────────────────────────────────────────

// ErrTokenNotFound is returned when no active token exists for the user.
var ErrTokenNotFound = errors.New("token not found")

// StoreToken saves (or replaces) the session token for a user.
func (s *Store) StoreToken(ctx context.Context, userID, token string, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO auth_tokens (user_id, token, expires_at)
		 VALUES (?, ?, ?)`,
		userID, token, expiresAt)
	if err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	return nil
}

// GetToken returns the stored token and its expiry for a user.
// Expired tokens are treated as absent (and cleaned up).
func (s *Store) GetToken(ctx context.Context, userID string) (string, int64, error) {
	var token string
	var expiresAt int64
	err := s.db.QueryRowContext(ctx,
		"SELECT token, expires_at FROM auth_tokens WHERE user_id = ?", userID).
		Scan(&token, &expiresAt)
	if err == sql.ErrNoRows {
		return "", 0, ErrTokenNotFound
	}
	if err != nil {
		return "", 0, fmt.Errorf("get token: %w", err)
	}
	return token, expiresAt, nil
}

// ─── File metadata ──────────────────────────────────────────────────

// ErrFileNotFound is returned when a file's metadata does not exist.
var ErrFileNotFound = errors.New("file not found")

// SaveFileMeta inserts or updates the metadata row for an uploaded file.
func (s *Store) SaveFileMeta(ctx context.Context, m *FileMeta) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO files (file_id, sender, owner, filename, size, sha256, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		m.FileID, m.Sender, m.Owner, m.Filename, m.Size, m.SHA256, m.Status, m.CreatedAt)
	if err != nil {
		return fmt.Errorf("save file meta: %w", err)
	}
	return nil
}

// GetFileMeta returns the metadata row for a file, or ErrFileNotFound.
func (s *Store) GetFileMeta(ctx context.Context, fileID string) (*FileMeta, error) {
	var m FileMeta
	err := s.db.QueryRowContext(ctx,
		`SELECT file_id, sender, owner, filename, size, sha256, status, created_at
		 FROM files WHERE file_id = ?`, fileID).
		Scan(&m.FileID, &m.Sender, &m.Owner, &m.Filename, &m.Size, &m.SHA256, &m.Status, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get file meta: %w", err)
	}
	return &m, nil
}

// DeleteFileMeta removes the metadata row for a file.
func (s *Store) DeleteFileMeta(ctx context.Context, fileID string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM files WHERE file_id = ?", fileID)
	if err != nil {
		return fmt.Errorf("delete file meta: %w", err)
	}
	return nil
}

// ListExpiredFileIDs returns file_ids whose metadata is older than `before` (unix seconds).
func (s *Store) ListExpiredFileIDs(ctx context.Context, before int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT file_id FROM files WHERE created_at < ?", before)
	if err != nil {
		return nil, fmt.Errorf("list expired files: %w", err)
	}
	defer rows.Close()

	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
