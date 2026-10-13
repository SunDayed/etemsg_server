package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RED LINE: MLS objects (KeyPackage / Commit / Welcome) and group ciphertext are stored as opaque
// strings; keys are never derived, decrypted or parsed, hence no group_key/epoch_secret/private_tree columns.

// Group roles. `admin` is never written by production code (only tests insert it directly); owner and admin approve/commit alike, but kick/clear-pending-removals/dissolve are **owner only**.
const (
	GroupRoleOwner  = "owner"
	GroupRoleAdmin  = "admin"
	GroupRoleMember = "member"
)

const (
	GroupStateActive    = "active"
	GroupStateDissolved = "dissolved"
)

const (
	JoinRequestPending  = "pending"
	JoinRequestApproved = "approved"
	JoinRequestDenied   = "denied"
)

// GroupQueueMaxMessages is the per-group queue retention limit; exceeding it drops the oldest
// rows and raises groups.min_seq so clients can notice the truncation.
const GroupQueueMaxMessages = 10000

// MaxGroupMembers is the hard member cap, checked only when a Welcome actually adds a row; a
// Welcome re-sent to an existing member stays idempotent and does not fail on a full group.
const MaxGroupMembers = 1000

// Errors returned by the group store. Handlers map them to API error codes.
var (
	ErrGroupNotFound            = errors.New("group not found")
	ErrGroupFull                = errors.New("group is full")
	ErrSuccessorRequired        = errors.New("group owner must name a successor before leaving")
	ErrInvalidSuccessor         = errors.New("invalid successor")
	ErrDuplicateGroup           = errors.New("group already exists")
	ErrGroupMemberNotFound      = errors.New("group member not found")
	ErrDuplicateJoinRequest     = errors.New("pending join request already exists")
	ErrDuplicateRequestID       = errors.New("join request id already exists")
	ErrJoinRequestNotFound      = errors.New("join request not found")
	ErrJoinRequestGroupMismatch = errors.New("join request belongs to another group")
	ErrJoinRequestNotPending    = errors.New("join request is not pending")
	ErrKeyPackageNotFound       = errors.New("key package not found")
	ErrDuplicateKeyPackage      = errors.New("key package already exists")
	ErrDuplicateGroupMsg        = errors.New("duplicate group message id")
	ErrDuplicateCommitEpoch     = errors.New("a commit for this epoch already exists")
	ErrEpochParentMismatch      = errors.New("parent_epoch does not match current_epoch")
	ErrEpochNotMonotonic        = errors.New("epoch must be greater than current_epoch")
)

// Group mirrors one row of `groups`.
type Group struct {
	GroupID      string `json:"group_id"`
	NameEnc      []byte `json:"name_enc"`
	Creator      string `json:"creator"`
	State        string `json:"state"`
	CurrentEpoch int64  `json:"current_epoch"`
	MinSeq       int64  `json:"min_seq"`
	CreatedAt    int64  `json:"created_at"`
}

// GroupMember mirrors one row of `group_members`.
type GroupMember struct {
	GroupID     string `json:"group_id"`
	UserID      string `json:"user_id"`
	Role        string `json:"role"`
	JoinedEpoch int64  `json:"joined_epoch"`
	JoinedAt    int64  `json:"joined_at"`
}

// GroupSummary is the per-user view returned by GET /groups.
type GroupSummary struct {
	GroupID      string `json:"group_id"`
	NameEnc      []byte `json:"name_enc"`
	MyRole       string `json:"my_role"`
	CurrentEpoch int64  `json:"current_epoch"`
	MinSeq       int64  `json:"min_seq"`
}

// GroupSearchResult is returned by GET /groups/search (by group id only).
type GroupSearchResult struct {
	GroupID     string `json:"group_id"`
	NameEnc     []byte `json:"name_enc"`
	Creator     string `json:"creator"`
	MemberCount int64  `json:"member_count"`
	CreatedAt   int64  `json:"created_at"`
}

// MLSKeyPackage mirrors one row of `mls_key_packages`.
type MLSKeyPackage struct {
	KPID      string `json:"kp_id"`
	UserID    string `json:"user_id"`
	GroupID   string `json:"group_id"`
	KPB64     string `json:"kp_b64"`
	KPHash    string `json:"kp_hash"`
	CreatedAt int64  `json:"created_at"`
}

// GroupJoinRequest mirrors one row of `group_join_requests`.
type GroupJoinRequest struct {
	RequestID      string `json:"request_id"`
	GroupID        string `json:"group_id"`
	Applicant      string `json:"applicant"`
	KPID           string `json:"kp_id"`
	KPHash         string `json:"kp_hash"`
	TextCT         string `json:"text_ct"`
	TextIV         string `json:"text_iv"`
	TextTag        string `json:"text_tag"`
	TextWrappedKey string `json:"text_wrapped_key"`
	Status         string `json:"status"`
	DecidedBy      string `json:"decided_by"`
	DecidedAt      int64  `json:"decided_at"`
	CreatedAt      int64  `json:"created_at"`
}

// GroupMLSLogEntry mirrors one row of `group_mls_log`; DataB64 is an opaque Base64 MLS object (Commit / Welcome), never decoded.
type GroupMLSLogEntry struct {
	GroupID   string `json:"group_id"`
	Seq       int64  `json:"seq"`
	Epoch     int64  `json:"epoch"`
	Kind      string `json:"kind"`
	Sender    string `json:"sender"`
	Target    string `json:"target"`
	DataB64   string `json:"data_b64"`
	DataHash  string `json:"data_hash"`
	CreatedAt int64  `json:"created_at"`
}

// GroupMessage mirrors one row of `group_messages`; Ciphertext is opaque Base64 and the queue keeps one copy per group.
type GroupMessage struct {
	GroupID    string `json:"group_id"`
	Seq        int64  `json:"seq"`
	Epoch      int64  `json:"epoch"`
	Sender     string `json:"sender"`
	MsgID      string `json:"msg_id"`
	Ciphertext string `json:"ciphertext"`
	MsgType    string `json:"msg_type"`
	FileID     string `json:"file_id"`
	Timestamp  string `json:"timestamp"`
	CreatedAt  int64  `json:"created_at"`
}

// GroupReclaimResult reports what one reclaim pass removed.
type GroupReclaimResult struct {
	GroupID         string `json:"group_id"`
	DeletedByCursor int64  `json:"deleted_by_cursor"`
	DeletedByCap    int64  `json:"deleted_by_cap"`
	MinSeq          int64  `json:"min_seq"`
}

// isUniqueConstraint reports whether err is a SQLite UNIQUE violation; it backstops races the explicit pre-checks miss.
func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateGroup atomically inserts a group and its creator's owner membership; returns ErrDuplicateGroup if the id exists.
func (s *Store) CreateGroup(ctx context.Context, g *Group) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create group tx: %w", err)
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRowContext(ctx,
		"SELECT 1 FROM groups WHERE group_id = ?", g.GroupID).Scan(&one)
	if err == nil {
		return ErrDuplicateGroup
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("check group exists: %w", err)
	}

	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO groups (group_id, name_enc, creator, state, current_epoch, min_seq, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		g.GroupID, g.NameEnc, g.Creator, GroupStateActive, g.CurrentEpoch, g.MinSeq, now); err != nil {
		if isUniqueConstraint(err) {
			return ErrDuplicateGroup
		}
		return fmt.Errorf("insert group: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_members (group_id, user_id, role, joined_epoch, joined_at)
		 VALUES (?, ?, ?, ?, ?)`,
		g.GroupID, g.Creator, GroupRoleOwner, g.CurrentEpoch, now); err != nil {
		return fmt.Errorf("insert group owner: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create group commit: %w", err)
	}
	g.State = GroupStateActive
	g.CreatedAt = now
	return nil
}

// GetGroup loads a group by id. It returns ErrGroupNotFound when absent.
func (s *Store) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	var g Group
	var nameEnc []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT group_id, name_enc, creator, state, current_epoch, min_seq, created_at
		 FROM groups WHERE group_id = ?`, groupID).
		Scan(&g.GroupID, &nameEnc, &g.Creator, &g.State, &g.CurrentEpoch, &g.MinSeq, &g.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}
	g.NameEnc = nameEnc
	return &g, nil
}

// ListGroupsForUser returns the active groups the user belongs to, plus the caller's role and the group's epoch / queue floor.
func (s *Store) ListGroupsForUser(ctx context.Context, userID string) ([]GroupSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.group_id, g.name_enc, m.role, g.current_epoch, g.min_seq
		 FROM group_members m
		 JOIN groups g ON g.group_id = m.group_id
		 WHERE m.user_id = ? AND g.state = ?
		 ORDER BY g.created_at, g.group_id`, userID, GroupStateActive)
	if err != nil {
		return nil, fmt.Errorf("list groups for user: %w", err)
	}
	defer rows.Close()

	out := []GroupSummary{}
	for rows.Next() {
		var g GroupSummary
		var nameEnc []byte
		if err := rows.Scan(&g.GroupID, &nameEnc, &g.MyRole, &g.CurrentEpoch, &g.MinSeq); err != nil {
			return nil, fmt.Errorf("scan group summary: %w", err)
		}
		g.NameEnc = nameEnc
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListActiveGroupIDs returns the ids of all non-dissolved groups (reclaim scan).
func (s *Store) ListActiveGroupIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT group_id FROM groups WHERE state = ? ORDER BY group_id", GroupStateActive)
	if err != nil {
		return nil, fmt.Errorf("list active groups: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan group id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListActiveGroupIDsPage returns a bounded, ordered page of non-dissolved group IDs.
// The periodic reclaimer uses it so one tick cannot hold the single SQLite connection for
// an unbounded number of groups; the caller advances the offset between ticks.
func (s *Store) ListActiveGroupIDsPage(ctx context.Context, limit, offset int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT group_id FROM groups WHERE state = ? ORDER BY group_id LIMIT ? OFFSET ?",
		GroupStateActive, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list active groups page: %w", err)
	}
	defer rows.Close()

	out := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan group id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SearchGroupsByID matches group-id equality or prefix; names are ciphertext and never searchable.
func (s *Store) SearchGroupsByID(ctx context.Context, q string) ([]GroupSearchResult, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.group_id, g.name_enc, g.creator, g.created_at,
		        (SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.group_id)
		 FROM groups g
		 WHERE g.state = ? AND (g.group_id = ? OR g.group_id LIKE ? || '%')
		 ORDER BY g.created_at DESC, g.group_id
		 LIMIT 50`, GroupStateActive, q, q)
	if err != nil {
		return nil, fmt.Errorf("search groups: %w", err)
	}
	defer rows.Close()

	out := []GroupSearchResult{}
	for rows.Next() {
		var g GroupSearchResult
		var nameEnc []byte
		if err := rows.Scan(&g.GroupID, &nameEnc, &g.Creator, &g.CreatedAt, &g.MemberCount); err != nil {
			return nil, fmt.Errorf("scan group search result: %w", err)
		}
		g.NameEnc = nameEnc
		out = append(out, g)
	}
	return out, rows.Err()
}

// DissolveGroup marks a group as dissolved (owner-only at the handler level).
func (s *Store) DissolveGroup(ctx context.Context, groupID string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE groups SET state = ? WHERE group_id = ?", GroupStateDissolved, groupID)
	if err != nil {
		return fmt.Errorf("dissolve group: %w", err)
	}
	return nil
}

// GetGroupMember returns one membership row, or ErrGroupMemberNotFound.
func (s *Store) GetGroupMember(ctx context.Context, groupID, userID string) (*GroupMember, error) {
	var m GroupMember
	err := s.db.QueryRowContext(ctx,
		`SELECT group_id, user_id, role, joined_epoch, joined_at
		 FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID).
		Scan(&m.GroupID, &m.UserID, &m.Role, &m.JoinedEpoch, &m.JoinedAt)
	if err == sql.ErrNoRows {
		return nil, ErrGroupMemberNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get group member: %w", err)
	}
	return &m, nil
}

// IsGroupMember reports whether the user currently belongs to the group.
func (s *Store) IsGroupMember(ctx context.Context, groupID, userID string) (bool, error) {
	_, err := s.GetGroupMember(ctx, groupID, userID)
	if errors.Is(err, ErrGroupMemberNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListGroupMembers returns all members of a group in join order.
func (s *Store) ListGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_id, user_id, role, joined_epoch, joined_at
		 FROM group_members WHERE group_id = ? ORDER BY joined_at, user_id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	defer rows.Close()

	out := []GroupMember{}
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.GroupID, &m.UserID, &m.Role, &m.JoinedEpoch, &m.JoinedAt); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GroupMemberIDs returns just the member user ids (used for WS fan-out).
func (s *Store) GroupMemberIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT user_id FROM group_members WHERE group_id = ?", groupID)
	if err != nil {
		return nil, fmt.Errorf("list group member ids: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan group member id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AddGroupMember inserts a membership row with INSERT OR IGNORE, so a Welcome never demotes the
// owner. It is the only path that makes a member visible after their Commit is accepted.
func (s *Store) AddGroupMember(ctx context.Context, groupID, userID, role string, joinedEpoch int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_members (group_id, user_id, role, joined_epoch, joined_at)
		 VALUES (?, ?, ?, ?, ?)`,
		groupID, userID, role, joinedEpoch, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

// LeaveResult describes what a leave actually did.
type LeaveResult struct {
	// Dissolved: the leaver was the last member and the group is dissolved, so nobody needs removing.
	Dissolved bool
	// PendingRemoval: booked for the owner/admin to remove them from the MLS tree (group_pending_removals).
	PendingRemoval bool
	// Successor: the new owner when the leaver was the owner.
	Successor string
}

// LeaveGroup removes userID in one transaction (enforced here, not in the handler): an owner with
// others left must name a successor or nobody can commit, and the last member dissolves the group.
// Same transaction: group_owner_transfers, membership + group_cursor deletion, group_pending_removals.
func (s *Store) LeaveGroup(ctx context.Context, groupID, userID, successor string) (*LeaveResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("leave group tx: %w", err)
	}
	defer tx.Rollback()

	var state string
	if err := tx.QueryRowContext(ctx,
		"SELECT state FROM groups WHERE group_id = ?", groupID).Scan(&state); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrGroupNotFound
		}
		return nil, fmt.Errorf("load group: %w", err)
	}

	var role string
	err = tx.QueryRowContext(ctx,
		"SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
		groupID, userID).Scan(&role)
	if err == sql.ErrNoRows {
		// Idempotent: not a member (or already left) counts as "left", with no changes.
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("leave group commit: %w", err)
		}
		return &LeaveResult{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load leaver: %w", err)
	}

	var others int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id <> ?",
		groupID, userID).Scan(&others); err != nil {
		return nil, fmt.Errorf("count other members: %w", err)
	}

	res := &LeaveResult{}
	if role == GroupRoleOwner {
		switch {
		case others == 0:
			// Last member: dissolve, or an empty group with no owner would linger forever.
			if _, err := tx.ExecContext(ctx,
				"UPDATE groups SET state = ? WHERE group_id = ?",
				GroupStateDissolved, groupID); err != nil {
				return nil, fmt.Errorf("dissolve on last leave: %w", err)
			}
			res.Dissolved = true
		default:
			successor = strings.TrimSpace(successor)
			if successor == "" {
				return nil, ErrSuccessorRequired
			}
			if successor == userID {
				return nil, ErrInvalidSuccessor
			}
			var ok int
			if err := tx.QueryRowContext(ctx,
				"SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?",
				groupID, successor).Scan(&ok); err != nil {
				return nil, fmt.Errorf("check successor: %w", err)
			}
			if ok == 0 {
				return nil, ErrInvalidSuccessor
			}
			// No immediate promotion: the owner is gone, so the group has no owner until the designee
			// confirms; createJoinRequest rejects joins until then (nobody may perform the MLS Add).
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO group_owner_transfers (group_id, prev_owner, designee, state, created_at)
				 VALUES (?, ?, ?, ?, ?)`,
				groupID, userID, successor, TransferPending, time.Now().Unix()); err != nil {
				return nil, fmt.Errorf("record pending transfer: %w", err)
			}
			res.Successor = successor
		}
	}

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM group_members WHERE group_id = ? AND user_id = ?", groupID, userID); err != nil {
		return nil, fmt.Errorf("delete leaver: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM group_cursor WHERE group_id = ? AND user_id = ?", groupID, userID); err != nil {
		return nil, fmt.Errorf("delete leaver cursor: %w", err)
	}

	// Only a live group needs the leaver removed from the ratchet tree.
	if !res.Dissolved {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO group_pending_removals (group_id, user_id, created_at)
			 VALUES (?, ?, ?)
			 ON CONFLICT(group_id, user_id) DO NOTHING`,
			groupID, userID, time.Now().Unix()); err != nil {
			return nil, fmt.Errorf("record pending removal: %w", err)
		}
		res.PendingRemoval = true
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("leave group commit: %w", err)
	}
	return res, nil
}

// PendingRemovalIDs lists members still to be removed from the MLS ratchet tree (they already lost server access).
func (s *Store) PendingRemovalIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT user_id FROM group_pending_removals WHERE group_id = ? ORDER BY created_at, user_id",
		groupID)
	if err != nil {
		return nil, fmt.Errorf("list pending removals: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("scan pending removal: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ClearPendingRemovals drops a group's removal tasks; owner/admin call it after actually pushing the Remove commit — the server cannot verify that without parsing MLS.
func (s *Store) ClearPendingRemovals(ctx context.Context, groupID string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM group_pending_removals WHERE group_id = ?", groupID)
	if err != nil {
		return fmt.Errorf("clear pending removals: %w", err)
	}
	return nil
}

// RemoveGroupMember deletes a membership row and the member's ack cursor (idempotent). The cursor
// must go too: reclamation uses MIN(last_seq) over current members, and a stale cursor would come
// back when they rejoin, pinning the group's retention floor until they ack again.
func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("remove group member tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM group_members WHERE group_id = ? AND user_id = ?", groupID, userID); err != nil {
		return fmt.Errorf("remove group member: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM group_cursor WHERE group_id = ? AND user_id = ?", groupID, userID); err != nil {
		return fmt.Errorf("remove group cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("remove group member commit: %w", err)
	}
	return nil
}

// CreateKeyPackage stores an opaque Base64 KeyPackage. kp_id must be unique.
func (s *Store) CreateKeyPackage(ctx context.Context, kp *MLSKeyPackage) error {
	var one int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM mls_key_packages WHERE kp_id = ?", kp.KPID).Scan(&one)
	if err == nil {
		return ErrDuplicateKeyPackage
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("check key package: %w", err)
	}

	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO mls_key_packages (kp_id, user_id, group_id, kp_b64, kp_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		kp.KPID, kp.UserID, kp.GroupID, kp.KPB64, kp.KPHash, now); err != nil {
		if isUniqueConstraint(err) {
			return ErrDuplicateKeyPackage
		}
		return fmt.Errorf("insert key package: %w", err)
	}
	kp.CreatedAt = now
	return nil
}

// GetKeyPackage loads a KeyPackage by id, or ErrKeyPackageNotFound.
func (s *Store) GetKeyPackage(ctx context.Context, kpID string) (*MLSKeyPackage, error) {
	var kp MLSKeyPackage
	err := s.db.QueryRowContext(ctx,
		`SELECT kp_id, user_id, group_id, kp_b64, kp_hash, created_at
		 FROM mls_key_packages WHERE kp_id = ?`, kpID).
		Scan(&kp.KPID, &kp.UserID, &kp.GroupID, &kp.KPB64, &kp.KPHash, &kp.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrKeyPackageNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get key package: %w", err)
	}
	return &kp, nil
}

// CreateJoinRequest stores a pending join request: at most one pending row per (group_id, applicant), and request_id must be unique.
func (s *Store) CreateJoinRequest(ctx context.Context, jr *GroupJoinRequest) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create join request tx: %w", err)
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRowContext(ctx,
		"SELECT 1 FROM group_join_requests WHERE request_id = ?", jr.RequestID).Scan(&one)
	if err == nil {
		return ErrDuplicateRequestID
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("check join request id: %w", err)
	}

	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM group_join_requests
		 WHERE group_id = ? AND applicant = ? AND status = ?`,
		jr.GroupID, jr.Applicant, JoinRequestPending).Scan(&one)
	if err == nil {
		return ErrDuplicateJoinRequest
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("check pending join request: %w", err)
	}

	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_join_requests
		   (request_id, group_id, applicant, kp_id, kp_hash, text_ct, text_iv, text_tag,
		    text_wrapped_key, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jr.RequestID, jr.GroupID, jr.Applicant, jr.KPID, jr.KPHash,
		jr.TextCT, jr.TextIV, jr.TextTag, jr.TextWrappedKey, JoinRequestPending, now); err != nil {
		if isUniqueConstraint(err) {
			return ErrDuplicateRequestID
		}
		return fmt.Errorf("insert join request: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create join request commit: %w", err)
	}
	jr.Status = JoinRequestPending
	jr.CreatedAt = now
	return nil
}

// GetJoinRequest loads a join request by id, or ErrJoinRequestNotFound.
func (s *Store) GetJoinRequest(ctx context.Context, requestID string) (*GroupJoinRequest, error) {
	var jr GroupJoinRequest
	var decidedBy sql.NullString
	var decidedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT request_id, group_id, applicant, kp_id, kp_hash, text_ct, text_iv, text_tag,
		        text_wrapped_key, status, decided_by, decided_at, created_at
		 FROM group_join_requests WHERE request_id = ?`, requestID).
		Scan(&jr.RequestID, &jr.GroupID, &jr.Applicant, &jr.KPID, &jr.KPHash,
			&jr.TextCT, &jr.TextIV, &jr.TextTag, &jr.TextWrappedKey, &jr.Status,
			&decidedBy, &decidedAt, &jr.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrJoinRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get join request: %w", err)
	}
	jr.DecidedBy = decidedBy.String
	jr.DecidedAt = decidedAt.Int64
	return &jr, nil
}

// ListPendingJoinRequests returns the pending requests of a group, oldest first.
func (s *Store) ListPendingJoinRequests(ctx context.Context, groupID string) ([]GroupJoinRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT request_id, group_id, applicant, kp_id, kp_hash, text_ct, text_iv, text_tag,
		        text_wrapped_key, status, created_at
		 FROM group_join_requests
		 WHERE group_id = ? AND status = ?
		 ORDER BY created_at, request_id`, groupID, JoinRequestPending)
	if err != nil {
		return nil, fmt.Errorf("list join requests: %w", err)
	}
	defer rows.Close()

	out := []GroupJoinRequest{}
	for rows.Next() {
		var jr GroupJoinRequest
		if err := rows.Scan(&jr.RequestID, &jr.GroupID, &jr.Applicant, &jr.KPID, &jr.KPHash,
			&jr.TextCT, &jr.TextIV, &jr.TextTag, &jr.TextWrappedKey, &jr.Status,
			&jr.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan join request: %w", err)
		}
		out = append(out, jr)
	}
	return out, rows.Err()
}

// DecideJoinRequest records an owner/admin decision, checking the request belongs to the group and
// is still pending. It does not touch group_members: membership lands with the MLS Commit/Welcome.
func (s *Store) DecideJoinRequest(ctx context.Context, groupID, requestID, decision, decidedBy string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("decide join request tx: %w", err)
	}
	defer tx.Rollback()

	var reqGroup, status string
	err = tx.QueryRowContext(ctx,
		"SELECT group_id, status FROM group_join_requests WHERE request_id = ?", requestID).
		Scan(&reqGroup, &status)
	if err == sql.ErrNoRows {
		return ErrJoinRequestNotFound
	}
	if err != nil {
		return fmt.Errorf("load join request: %w", err)
	}
	if reqGroup != groupID {
		return ErrJoinRequestGroupMismatch
	}
	if status != JoinRequestPending {
		return ErrJoinRequestNotPending
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE group_join_requests
		 SET status = ?, decided_by = ?, decided_at = ?
		 WHERE request_id = ?`,
		decision, decidedBy, time.Now().Unix(), requestID); err != nil {
		return fmt.Errorf("update join request: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("decide join request commit: %w", err)
	}
	return nil
}

// nextMLSSeq allocates the next monotonic seq for a group inside tx.
func nextMLSSeq(ctx context.Context, tx *sql.Tx, groupID string) (int64, error) {
	var maxSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		"SELECT MAX(seq) FROM group_mls_log WHERE group_id = ?", groupID).Scan(&maxSeq); err != nil {
		return 0, fmt.Errorf("read mls log max seq: %w", err)
	}
	if maxSeq.Valid {
		return maxSeq.Int64 + 1, nil
	}
	return 1, nil
}

// AppendGroupCommit atomically validates and appends an opaque MLS Commit and advances
// groups.current_epoch: fork guard, parent_epoch == current_epoch, then epoch > current_epoch.
func (s *Store) AppendGroupCommit(ctx context.Context, e *GroupMLSLogEntry, parentEpoch int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("append commit tx: %w", err)
	}
	defer tx.Rollback()

	var currentEpoch int64
	err = tx.QueryRowContext(ctx,
		"SELECT current_epoch FROM groups WHERE group_id = ?", e.GroupID).Scan(&currentEpoch)
	if err == sql.ErrNoRows {
		return 0, ErrGroupNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("load group epoch: %w", err)
	}

	var one int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM group_mls_log
		 WHERE group_id = ? AND epoch = ? AND kind <> 'welcome' LIMIT 1`,
		e.GroupID, e.Epoch).Scan(&one)
	if err == nil {
		return 0, ErrDuplicateCommitEpoch
	}
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("check commit epoch: %w", err)
	}

	if parentEpoch != currentEpoch {
		return 0, ErrEpochParentMismatch
	}
	if e.Epoch <= currentEpoch {
		return 0, ErrEpochNotMonotonic
	}

	seq, err := nextMLSSeq(ctx, tx, e.GroupID)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_mls_log
		   (group_id, seq, epoch, kind, sender, target, data_b64, data_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.GroupID, seq, e.Epoch, e.Kind, e.Sender, e.Target, e.DataB64, e.DataHash, now); err != nil {
		if isUniqueConstraint(err) {
			return 0, ErrDuplicateCommitEpoch
		}
		return 0, fmt.Errorf("insert commit: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		"UPDATE groups SET current_epoch = ? WHERE group_id = ?", e.Epoch, e.GroupID); err != nil {
		return 0, fmt.Errorf("advance group epoch: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("append commit commit: %w", err)
	}
	e.Seq = seq
	e.CreatedAt = now
	return seq, nil
}

// AppendWelcome atomically appends a Welcome and adds target_user to group_members at that epoch;
// this is where membership takes effect, as the Welcome implies the Commit already Add-ed them.
func (s *Store) AppendWelcome(ctx context.Context, e *GroupMLSLogEntry) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("append welcome tx: %w", err)
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRowContext(ctx, "SELECT 1 FROM groups WHERE group_id = ?", e.GroupID).Scan(&one)
	if err == sql.ErrNoRows {
		return 0, ErrGroupNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("check group for welcome: %w", err)
	}

	seq, err := nextMLSSeq(ctx, tx, e.GroupID)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_mls_log
		   (group_id, seq, epoch, kind, sender, target, data_b64, data_hash, created_at)
		 VALUES (?, ?, ?, 'welcome', ?, ?, ?, ?, ?)`,
		e.GroupID, seq, e.Epoch, e.Sender, e.Target, e.DataB64, e.DataHash, now); err != nil {
		return 0, fmt.Errorf("insert welcome: %w", err)
	}

	// The cap is checked only on a real insert: a repeat Welcome to an existing member is idempotent and must not fail on a full group.
	var alreadyMember int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?",
		e.GroupID, e.Target).Scan(&alreadyMember); err != nil {
		return 0, fmt.Errorf("check welcomed member: %w", err)
	}
	if alreadyMember == 0 {
		var memberCount int
		if err := tx.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM group_members WHERE group_id = ?",
			e.GroupID).Scan(&memberCount); err != nil {
			return 0, fmt.Errorf("count group members: %w", err)
		}
		if memberCount >= MaxGroupMembers {
			return 0, ErrGroupFull
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_members (group_id, user_id, role, joined_epoch, joined_at)
		 VALUES (?, ?, ?, ?, ?)`,
		e.GroupID, e.Target, GroupRoleMember, e.Epoch, now); err != nil {
		return 0, fmt.Errorf("add welcomed member: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("append welcome commit: %w", err)
	}
	e.Seq = seq
	e.CreatedAt = now
	return seq, nil
}

// ListMLSLogSince returns non-welcome entries with epoch > sinceEpoch, ascending;
// kind/target filtering is left to dedicated helpers at the call site.
func (s *Store) ListMLSLogSince(ctx context.Context, groupID string, sinceEpoch int64) ([]GroupMLSLogEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_id, seq, epoch, kind, sender, COALESCE(target, ''),
		        COALESCE(data_b64, ''), COALESCE(data_hash, ''), COALESCE(created_at, 0)
		 FROM group_mls_log
		 WHERE group_id = ? AND epoch > ? AND kind <> 'welcome'
		 ORDER BY epoch ASC, seq ASC`, groupID, sinceEpoch)
	if err != nil {
		return nil, fmt.Errorf("list mls log: %w", err)
	}
	defer rows.Close()

	out := []GroupMLSLogEntry{}
	for rows.Next() {
		var e GroupMLSLogEntry
		if err := rows.Scan(&e.GroupID, &e.Seq, &e.Epoch, &e.Kind, &e.Sender,
			&e.Target, &e.DataB64, &e.DataHash, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan mls log: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListWelcomesFor returns the Welcome entries addressed to targetUser, by seq.
func (s *Store) ListWelcomesFor(ctx context.Context, groupID, targetUser string) ([]GroupMLSLogEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_id, seq, epoch, kind, sender, COALESCE(target, ''),
		        COALESCE(data_b64, ''), COALESCE(data_hash, ''), COALESCE(created_at, 0)
		 FROM group_mls_log
		 WHERE group_id = ? AND kind = 'welcome' AND target = ?
		 ORDER BY seq ASC`, groupID, targetUser)
	if err != nil {
		return nil, fmt.Errorf("list welcomes: %w", err)
	}
	defer rows.Close()

	out := []GroupMLSLogEntry{}
	for rows.Next() {
		var e GroupMLSLogEntry
		if err := rows.Scan(&e.GroupID, &e.Seq, &e.Epoch, &e.Kind, &e.Sender,
			&e.Target, &e.DataB64, &e.DataHash, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan welcome: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AppendGroupMessage appends one ciphertext to the group's single queue; seq is MAX(seq)+1 inside the transaction, and a duplicate (group_id, msg_id) gives ErrDuplicateGroupMsg.
func (s *Store) AppendGroupMessage(ctx context.Context, m *GroupMessage) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("append group message tx: %w", err)
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRowContext(ctx,
		"SELECT 1 FROM group_messages WHERE group_id = ? AND msg_id = ?", m.GroupID, m.MsgID).Scan(&one)
	if err == nil {
		return 0, ErrDuplicateGroupMsg
	}
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("check group message id: %w", err)
	}

	var maxSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		"SELECT MAX(seq) FROM group_messages WHERE group_id = ?", m.GroupID).Scan(&maxSeq); err != nil {
		return 0, fmt.Errorf("read group message max seq: %w", err)
	}
	seq := int64(1)
	if maxSeq.Valid {
		seq = maxSeq.Int64 + 1
	}

	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_messages
		   (group_id, seq, epoch, sender, msg_id, ciphertext, msg_type, file_id, timestamp, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.GroupID, seq, m.Epoch, m.Sender, m.MsgID, m.Ciphertext,
		m.MsgType, m.FileID, m.Timestamp, now); err != nil {
		if isUniqueConstraint(err) {
			return 0, ErrDuplicateGroupMsg
		}
		return 0, fmt.Errorf("insert group message: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("append group message commit: %w", err)
	}
	m.Seq = seq
	m.CreatedAt = now
	return seq, nil
}

// ListGroupMessages returns messages with seq > sinceSeq in ascending order.
func (s *Store) ListGroupMessages(ctx context.Context, groupID string, sinceSeq int64, limit int) ([]GroupMessage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_id, seq, epoch, sender, msg_id, ciphertext,
		        COALESCE(msg_type, ''), COALESCE(file_id, ''), COALESCE(timestamp, ''),
		        COALESCE(created_at, 0)
		 FROM group_messages
		 WHERE group_id = ? AND seq > ?
		 ORDER BY seq ASC LIMIT ?`, groupID, sinceSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("list group messages: %w", err)
	}
	defer rows.Close()

	out := []GroupMessage{}
	for rows.Next() {
		var m GroupMessage
		if err := rows.Scan(&m.GroupID, &m.Seq, &m.Epoch, &m.Sender, &m.MsgID, &m.Ciphertext,
			&m.MsgType, &m.FileID, &m.Timestamp, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group message: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MaxGroupMessageSeq returns the highest queued seq (0 when the queue is empty).
func (s *Store) MaxGroupMessageSeq(ctx context.Context, groupID string) (int64, error) {
	var maxSeq sql.NullInt64
	if err := s.db.QueryRowContext(ctx,
		"SELECT MAX(seq) FROM group_messages WHERE group_id = ?", groupID).Scan(&maxSeq); err != nil {
		return 0, fmt.Errorf("max group message seq: %w", err)
	}
	if maxSeq.Valid {
		return maxSeq.Int64, nil
	}
	return 0, nil
}

// GetGroupCursor returns the user's ack cursor for a group (0 when unset).
func (s *Store) GetGroupCursor(ctx context.Context, userID, groupID string) (int64, error) {
	var lastSeq int64
	err := s.db.QueryRowContext(ctx,
		"SELECT last_seq FROM group_cursor WHERE user_id = ? AND group_id = ?", userID, groupID).Scan(&lastSeq)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get group cursor: %w", err)
	}
	return lastSeq, nil
}

// UpsertGroupCursor advances the ack cursor monotonically: an older last_seq never pulls it back.
func (s *Store) UpsertGroupCursor(ctx context.Context, userID, groupID string, lastSeq int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO group_cursor (user_id, group_id, last_seq, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(user_id, group_id) DO UPDATE SET
		   last_seq = CASE WHEN excluded.last_seq > group_cursor.last_seq
		                   THEN excluded.last_seq ELSE group_cursor.last_seq END,
		   updated_at = excluded.updated_at`,
		userID, groupID, lastSeq, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("upsert group cursor: %w", err)
	}
	return nil
}

// ReclaimGroupMessages performs one retention pass in a single transaction:
//  1. safe_seq = MIN(last_seq) over current members (no cursor counts as 0, so an un-acked member
//     blocks reclamation — intentional); delete seq <= safe_seq and raise min_seq to at least it.
//  2. If the queue still exceeds GroupQueueMaxMessages, drop the oldest rows down to exactly that
//     many and raise min_seq to the highest deleted seq. Deletes and the min_seq bump are atomic.
func (s *Store) ReclaimGroupMessages(ctx context.Context, groupID string) (*GroupReclaimResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("reclaim tx: %w", err)
	}
	defer tx.Rollback()

	res := &GroupReclaimResult{GroupID: groupID}

	var minSeq int64
	err = tx.QueryRowContext(ctx, "SELECT min_seq FROM groups WHERE group_id = ?", groupID).Scan(&minSeq)
	if err == sql.ErrNoRows {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reclaim read min_seq: %w", err)
	}

	// Members without a cursor count via COALESCE(...,0); an empty member set gives NULL, also treated as 0.
	var safeSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MIN(COALESCE(c.last_seq, 0))
		 FROM group_members m
		 LEFT JOIN group_cursor c
		   ON c.group_id = m.group_id AND c.user_id = m.user_id
		 WHERE m.group_id = ?`, groupID).Scan(&safeSeq); err != nil {
		return nil, fmt.Errorf("reclaim safe seq: %w", err)
	}

	if safeSeq.Valid && safeSeq.Int64 > 0 {
		r, err := tx.ExecContext(ctx,
			"DELETE FROM group_messages WHERE group_id = ? AND seq <= ?", groupID, safeSeq.Int64)
		if err != nil {
			return nil, fmt.Errorf("reclaim delete by cursor: %w", err)
		}
		n, _ := r.RowsAffected()
		res.DeletedByCursor = n
		if safeSeq.Int64 > minSeq {
			minSeq = safeSeq.Int64
		}
	}

	var count int64
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM group_messages WHERE group_id = ?", groupID).Scan(&count); err != nil {
		return nil, fmt.Errorf("reclaim count: %w", err)
	}

	if count > GroupQueueMaxMessages {
		offset := count - GroupQueueMaxMessages - 1
		var cutoff int64
		err := tx.QueryRowContext(ctx,
			`SELECT seq FROM group_messages WHERE group_id = ?
			 ORDER BY seq ASC LIMIT 1 OFFSET ?`, groupID, offset).Scan(&cutoff)
		if err != nil {
			return nil, fmt.Errorf("reclaim cap cutoff: %w", err)
		}
		r, err := tx.ExecContext(ctx,
			"DELETE FROM group_messages WHERE group_id = ? AND seq <= ?", groupID, cutoff)
		if err != nil {
			return nil, fmt.Errorf("reclaim delete by cap: %w", err)
		}
		n, _ := r.RowsAffected()
		res.DeletedByCap = n
		if cutoff > minSeq {
			minSeq = cutoff
		}
	}

	if minSeq != 0 {
		if _, err := tx.ExecContext(ctx,
			"UPDATE groups SET min_seq = ? WHERE group_id = ? AND min_seq < ?",
			minSeq, groupID, minSeq); err != nil {
			return nil, fmt.Errorf("reclaim raise min_seq: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("reclaim commit: %w", err)
	}
	res.MinSeq = minSeq
	return res, nil
}

// Owner transfer (confirmed by the designee): a plain transfer keeps the old owner — and their join
// approvals — until confirmation; leaving with a successor leaves at once with no owner, so joins
// are refused until the successor confirms. The old owner keeps rights over requests predating it.

// OwnerTransfer mirrors one row of group_owner_transfers.
type OwnerTransfer struct {
	ID        int64  `json:"id"`
	GroupID   string `json:"group_id"`
	PrevOwner string `json:"prev_owner"`
	Designee  string `json:"designee"`
	State     string `json:"state"`
	CreatedAt int64  `json:"created_at"`
	DecidedAt int64  `json:"decided_at"`
}

const (
	TransferPending  = "pending"
	TransferAccepted = "accepted"
	TransferDeclined = "declined"
)

var (
	ErrTransferNotFound = errors.New("owner transfer not found")
	ErrTransferPending  = errors.New("an owner transfer is already pending")
	ErrNotDesignee      = errors.New("caller is not the designated successor")
)

// CreateOwnerTransfer records a pending transfer (the handler sends the notification); designee must be a current member.
func (s *Store) CreateOwnerTransfer(ctx context.Context, groupID, prevOwner, designee string) error {
	if prevOwner == designee {
		return ErrInvalidSuccessor
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create transfer tx: %w", err)
	}
	defer tx.Rollback()

	var one int
	if err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM group_owner_transfers WHERE group_id = ? AND state = ?`,
		groupID, TransferPending).Scan(&one); err == nil {
		return ErrTransferPending
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("check pending transfer: %w", err)
	}

	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?`,
		groupID, designee).Scan(&one); err != nil {
		return fmt.Errorf("check designee: %w", err)
	}
	if one == 0 {
		return ErrInvalidSuccessor
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_owner_transfers (group_id, prev_owner, designee, state, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		groupID, prevOwner, designee, TransferPending, time.Now().Unix()); err != nil {
		return fmt.Errorf("insert transfer: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create transfer commit: %w", err)
	}
	return nil
}

// PendingOwnerTransfer returns the group's pending transfer, or ErrTransferNotFound when there is none.
func (s *Store) PendingOwnerTransfer(ctx context.Context, groupID string) (*OwnerTransfer, error) {
	var t OwnerTransfer
	err := s.db.QueryRowContext(ctx,
		`SELECT id, group_id, prev_owner, designee, state, created_at, decided_at
		   FROM group_owner_transfers WHERE group_id = ? AND state = ?
		  ORDER BY created_at DESC, id DESC LIMIT 1`,
		groupID, TransferPending).
		Scan(&t.ID, &t.GroupID, &t.PrevOwner, &t.Designee, &t.State, &t.CreatedAt, &t.DecidedAt)
	if err == sql.ErrNoRows {
		return nil, ErrTransferNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load pending transfer: %w", err)
	}
	return &t, nil
}

// GroupOwnerID returns the current owner, or "" when there is none (owner left, successor
// unconfirmed). Join justifications are encrypted to this key, not the creator's, so a new owner can read them.
func (s *Store) GroupOwnerID(ctx context.Context, groupID string) (string, error) {
	var uid string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM group_members WHERE group_id = ? AND role = ?
		  ORDER BY joined_at, user_id LIMIT 1`, groupID, GroupRoleOwner).Scan(&uid)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load group owner: %w", err)
	}
	return uid, nil
}

// GroupHasOwner reports whether the group currently has at least one owner.
func (s *Store) GroupHasOwner(ctx context.Context, groupID string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM group_members WHERE group_id = ? AND role = ?`,
		groupID, GroupRoleOwner).Scan(&n); err != nil {
		return false, fmt.Errorf("count owners: %w", err)
	}
	return n > 0, nil
}

// DecideOwnerTransfer finishes the pending transfer in one transaction. accept promotes the designee
// (demoting the previous owner if still present) after re-checking membership; decline leaves a
// plain transfer intact, but dissolves the group when no owner remains — otherwise nobody can commit.
func (s *Store) DecideOwnerTransfer(ctx context.Context, groupID, designee string, accept bool) (*OwnerTransfer, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("decide transfer tx: %w", err)
	}
	defer tx.Rollback()

	var t OwnerTransfer
	err = tx.QueryRowContext(ctx,
		`SELECT id, group_id, prev_owner, designee, state, created_at, decided_at
		   FROM group_owner_transfers WHERE group_id = ? AND state = ?
		  ORDER BY created_at DESC, id DESC LIMIT 1`,
		groupID, TransferPending).
		Scan(&t.ID, &t.GroupID, &t.PrevOwner, &t.Designee, &t.State, &t.CreatedAt, &t.DecidedAt)
	if err == sql.ErrNoRows {
		return nil, ErrTransferNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load transfer to decide: %w", err)
	}
	if t.Designee != designee {
		return nil, ErrNotDesignee
	}

	now := time.Now().Unix()
	state := TransferDeclined
	if accept {
		state = TransferAccepted
		// The designee must still be a member.
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?`,
			groupID, designee).Scan(&n); err != nil {
			return nil, fmt.Errorf("check designee membership: %w", err)
		}
		if n == 0 {
			return nil, ErrInvalidSuccessor
		}
		// Demote the previous owner first (they may still be present) so there are never two owners.
		if _, err := tx.ExecContext(ctx,
			`UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ? AND role = ?`,
			GroupRoleMember, groupID, t.PrevOwner, GroupRoleOwner); err != nil {
			return nil, fmt.Errorf("demote previous owner: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?`,
			GroupRoleOwner, groupID, designee); err != nil {
			return nil, fmt.Errorf("promote designee: %w", err)
		}
	} else {
		// On decline: if no owner remains (the owner already left), nobody can push Commits again.
		var owners int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM group_members WHERE group_id = ? AND role = ?`,
			groupID, GroupRoleOwner).Scan(&owners); err != nil {
			return nil, fmt.Errorf("count owners on decline: %w", err)
		}
		if owners == 0 {
			if _, err := tx.ExecContext(ctx,
				`UPDATE groups SET state = ? WHERE group_id = ?`,
				GroupStateDissolved, groupID); err != nil {
				return nil, fmt.Errorf("dissolve on declined transfer: %w", err)
			}
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE group_owner_transfers SET state = ?, decided_at = ? WHERE id = ?`,
		state, now, t.ID); err != nil {
		return nil, fmt.Errorf("update transfer state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("decide transfer commit: %w", err)
	}
	t.State = state
	t.DecidedAt = now
	return &t, nil
}

// OwnsJoinRequestBacklog reports whether user may still decide a request created at reqCreatedAt:
// they gave up ownership only after it was created, so the backlog stays theirs.
func (s *Store) OwnsJoinRequestBacklog(ctx context.Context, groupID, user string, reqCreatedAt int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM group_owner_transfers
		  WHERE group_id = ? AND prev_owner = ? AND created_at > ?`,
		groupID, user, reqCreatedAt).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check backlog ownership: %w", err)
	}
	return n > 0, nil
}

// JoinRequestCreatedAt returns a request's creation time (0 when unknown).
func (s *Store) JoinRequestCreatedAt(ctx context.Context, groupID, requestID string) (int64, error) {
	var ts int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(created_at, 0) FROM group_join_requests
		  WHERE group_id = ? AND request_id = ?`, groupID, requestID).Scan(&ts)
	if err == sql.ErrNoRows {
		return 0, ErrJoinRequestNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("load join request time: %w", err)
	}
	return ts, nil
}
