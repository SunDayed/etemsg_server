// Package store provides SQLite persistence for the E2E message server: users, contacts, offline
// messages, login challenges and file metadata (modernc.org/sqlite, pure Go, single-instance). Online presence lives in session.Manager instead.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"e2e-msg-server/types"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database handle.
type Store struct {
	db *sql.DB
}

// FileMeta describes an encrypted file stored on disk (files/{file_id}.enc); the server only ever holds ciphertext — this is display metadata.
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

// DB exposes the underlying handle for diagnostics and tests (e.g. asserting an index exists).
func (s *Store) DB() *sql.DB {
	return s.db
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
		// contact_id backs the reverse lookup "who added me" (presence fan-out, online queries);
		// without it every lookup is a full scan. IF NOT EXISTS backfills it on the next start.
		`CREATE INDEX IF NOT EXISTS idx_contacts_contact ON contacts(contact_id)`,
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

		// MLS objects (KeyPackage / Commit / Welcome) are opaque Base64 only; group keys, epoch secrets and message keys are never generated, derived or stored here.
		`CREATE TABLE IF NOT EXISTS groups (
			group_id      TEXT PRIMARY KEY,
			name_enc      BLOB,
			creator       TEXT NOT NULL,
			state         TEXT NOT NULL,
			current_epoch INTEGER NOT NULL,
			min_seq       INTEGER NOT NULL DEFAULT 0,
			created_at    INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id     TEXT,
			user_id      TEXT,
			role         TEXT,
			joined_epoch INTEGER,
			joined_at    INTEGER,
			PRIMARY KEY (group_id, user_id),
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS group_join_requests (
			request_id       TEXT PRIMARY KEY,
			group_id         TEXT,
			applicant        TEXT,
			kp_id            TEXT,
			kp_hash          TEXT,
			text_ct          TEXT,
			text_iv          TEXT,
			text_tag         TEXT,
			text_wrapped_key TEXT,
			status           TEXT NOT NULL DEFAULT 'pending',
			decided_by       TEXT,
			decided_at       INTEGER,
			created_at       INTEGER NOT NULL,
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS mls_key_packages (
			kp_id      TEXT PRIMARY KEY,
			user_id    TEXT,
			group_id   TEXT,
			kp_b64     TEXT,
			kp_hash    TEXT,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS group_mls_log (
			group_id   TEXT,
			seq        INTEGER,
			epoch      INTEGER,
			kind       TEXT,
			sender     TEXT,
			target     TEXT DEFAULT '',
			data_b64   TEXT,
			data_hash  TEXT,
			created_at INTEGER,
			PRIMARY KEY (group_id, seq),
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS group_messages (
			group_id   TEXT,
			seq        INTEGER,
			epoch      INTEGER,
			sender     TEXT,
			msg_id     TEXT,
			ciphertext TEXT,
			msg_type   TEXT DEFAULT '',
			file_id    TEXT DEFAULT '',
			timestamp  TEXT DEFAULT '',
			created_at INTEGER,
			PRIMARY KEY (group_id, seq),
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS group_cursor (
			user_id    TEXT,
			group_id   TEXT,
			last_seq   INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,
		// Pending removals: booked when someone leaves and cleared by the owner's later MLS Remove commit; the (group_id,user_id) primary key makes it idempotent.
		`CREATE TABLE IF NOT EXISTS group_pending_removals (
			group_id   TEXT NOT NULL,
			user_id    TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (group_id, user_id),
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,

		// Owner transfers: one pending row means "awaiting the designee's confirmation". A separate table rather than extra groups columns, since there are no column migrations.
		`CREATE TABLE IF NOT EXISTS group_owner_transfers (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			group_id   TEXT NOT NULL,
			prev_owner TEXT NOT NULL,
			designee   TEXT NOT NULL,
			state      TEXT NOT NULL DEFAULT 'pending',
			created_at INTEGER NOT NULL,
			decided_at INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
		)`,

		`CREATE INDEX IF NOT EXISTS idx_group_owner_transfers_group
			ON group_owner_transfers(group_id, state)`,

		`CREATE INDEX IF NOT EXISTS idx_group_messages_group_epoch
			ON group_messages(group_id, epoch)`,
		`CREATE INDEX IF NOT EXISTS idx_group_cursor_group
			ON group_cursor(group_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_group_messages_msg_id
			ON group_messages(group_id, msg_id)`,
		// Commit fork guard: at most one non-welcome MLS log row per (group, epoch); a Welcome intentionally shares the epoch of the Commit that accepted it.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_group_mls_log_commit_epoch
			ON group_mls_log(group_id, epoch) WHERE kind <> 'welcome'`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
	}
	return nil
}

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

// ContactsOf returns the users who have `userID` in their contact list — the ones entitled to see
// `userID`'s presence. /add_contact is one-way, so presence must not leak to strangers.
func (s *Store) ContactsOf(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT DISTINCT user_id FROM contacts WHERE contact_id = ? ORDER BY user_id", userID)
	if err != nil {
		return nil, fmt.Errorf("contacts of: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("scan contacts of: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
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

// AddContact adds a one-way contact relationship (userID → contactID) and returns the contact's public key.
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

// PendingIncomingContacts lists users who added me but whom I have not added back — the incoming
// half of a one-sided contact request. Adding is a **one-way** write (A→B is a single row), so
// "they added me, I have not added back" is a real, queryable state: my pending friend requests.
func (s *Store) PendingIncomingContacts(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.user_id FROM contacts c
		  WHERE c.contact_id = ?
		    AND NOT EXISTS (SELECT 1 FROM contacts r
		                     WHERE r.user_id = ? AND r.contact_id = c.user_id)
		  ORDER BY c.user_id`, userID, userID)
	if err != nil {
		return nil, fmt.Errorf("pending incoming contacts: %w", err)
	}
	defer rows.Close()
	out := make([]string, 0, 8)
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("scan pending contact: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// IsMutualContact reports whether both directions exist: (a → b) AND (b → a). Messaging requires a mutual contact.
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

// MutualContactIDs returns the set of users with a verified two-way contact relationship to userID.
// The JOIN is the batch form of IsMutualContact, replacing the old per-candidate N+1 pattern used by
// presence filtering/snapshots: one indexed query per user instead of one query per contact.
func (s *Store) MutualContactIDs(ctx context.Context, userID string) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT c1.contact_id
		   FROM contacts c1
		   JOIN contacts c2
		     ON c2.user_id = c1.contact_id AND c2.contact_id = c1.user_id
		  WHERE c1.user_id = ?
		  ORDER BY c1.contact_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("get mutual contacts: %w", err)
	}
	defer rows.Close()

	out := make(map[string]struct{})
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan mutual contact: %w", err)
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

// MaxOfflineMessagesPerUser is the maximum number of queued offline messages per user.
const MaxOfflineMessagesPerUser = 1000

// ErrOfflineQueueFull is returned when a user already has MaxOfflineMessagesPerUser messages.
var ErrOfflineQueueFull = errors.New("offline message queue full")

// PushOfflineMsg stores an encrypted message in the user's offline queue; returns ErrOfflineQueueFull once it holds MaxOfflineMessagesPerUser.
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

// ChallengeTTL is how long a login challenge stays valid; expired challenges and tokens count as absent.
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

// ConsumeLoginChallenge atomically removes and returns the user's active challenge.
// Using DELETE ... RETURNING makes the read-and-delete one statement, so two concurrent
// /login requests cannot both validate the same challenge and receive a token.
func (s *Store) ConsumeLoginChallenge(ctx context.Context, userID string) (string, error) {
	var challenge string
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM login_challenges
		 WHERE user_id = ? AND expires_at > ?
		 RETURNING challenge`, userID, time.Now().Unix()).Scan(&challenge)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no challenge found for user: %s", userID)
	}
	if err != nil {
		return "", fmt.Errorf("consume challenge: %w", err)
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

// GetToken returns the stored token and its expiry; expired ones count as absent (and get cleaned up).
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
