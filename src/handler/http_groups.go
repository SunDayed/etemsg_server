package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"e2e-msg-server/session"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleGroups routes every /groups* endpoint; ServeMux has no path-parameter patterns, so dispatch
// is manual here. All endpoints are signed: RSA-PKCS1v15/SHA-256 over fields+timestamp+nonce.
func HandleGroups(st *store.Store, sm *session.Manager) http.HandlerFunc {
	api := &groupAPI{st: st, sm: sm}
	return api.serve
}

type groupAPI struct {
	st *store.Store
	sm *session.Manager
}

const (
	groupIDLen         = 10 // 10-char lowercase base36; matches client GROUP_ID_LEN
	maxGroupNameEnc    = 4096
	maxKeyPackageLen   = 256 << 10 // 256 KiB Base64 KeyPackage
	maxMLSBlobLen      = 4 << 20   // 4 MiB Base64 Commit/Welcome
	maxGroupMsgLen     = 4 << 20   // 4 MiB Base64 ciphertext
	defaultMessagePage = 200
	maxMessagePage     = 500
)

func (a *groupAPI) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "/groups" {
		switch r.Method {
		case http.MethodPost:
			a.createGroup(w, r)
		case http.MethodGet:
			a.listGroups(w, r)
		default:
			methodNotAllowed(w)
		}
		return
	}

	rest := strings.TrimPrefix(path, "/groups/")
	if rest == path || rest == "" {
		notFoundGroupEndpoint(w)
		return
	}
	segs := strings.Split(rest, "/")

	// GET /groups/search?by=id&q=<gid> — must be matched before the {gid} branch.
	if segs[0] == "search" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		a.searchGroups(w, r)
		return
	}

	gid := utils.TrimSpace(segs[0])
	if !isGroupID(gid) {
		writeError(w, "INVALID_GROUP_ID", "group_id must be 10 lowercase base36 characters (digits + a-z)")
		return
	}

	if len(segs) == 1 {
		switch r.Method {
		case http.MethodGet:
			a.groupInfo(w, r, gid)
		case http.MethodDelete:
			a.dissolveGroup(w, r, gid)
		default:
			methodNotAllowed(w)
		}
		return
	}

	switch segs[1] {
	case "key-packages":
		if len(segs) != 2 {
			notFoundGroupEndpoint(w)
			return
		}
		switch r.Method {
		case http.MethodPost:
			a.uploadKeyPackage(w, r, gid)
		case http.MethodGet:
			a.getKeyPackage(w, r, gid)
		default:
			methodNotAllowed(w)
		}

	case "join_requests":
		if len(segs) == 2 {
			switch r.Method {
			case http.MethodPost:
				a.createJoinRequest(w, r, gid)
			case http.MethodGet:
				a.listJoinRequests(w, r, gid)
			default:
				methodNotAllowed(w)
			}
			return
		}
		if len(segs) == 4 && segs[3] == "decide" {
			if r.Method != http.MethodPost {
				methodNotAllowed(w)
				return
			}
			a.decideJoinRequest(w, r, gid, utils.TrimSpace(segs[2]))
			return
		}
		notFoundGroupEndpoint(w)

	case "commits":
		if len(segs) != 2 {
			notFoundGroupEndpoint(w)
			return
		}
		switch r.Method {
		case http.MethodPost:
			a.createCommit(w, r, gid)
		case http.MethodGet:
			a.listCommits(w, r, gid)
		default:
			methodNotAllowed(w)
		}

	case "welcomes":
		if len(segs) != 2 {
			notFoundGroupEndpoint(w)
			return
		}
		switch r.Method {
		case http.MethodPost:
			a.createWelcome(w, r, gid)
		case http.MethodGet:
			a.listWelcomes(w, r, gid)
		default:
			methodNotAllowed(w)
		}

	case "messages":
		if len(segs) == 3 && segs[2] == "ack" {
			if r.Method != http.MethodPost {
				methodNotAllowed(w)
				return
			}
			a.ackMessages(w, r, gid)
			return
		}
		if len(segs) != 2 {
			notFoundGroupEndpoint(w)
			return
		}
		switch r.Method {
		case http.MethodPost:
			a.sendMessage(w, r, gid)
		case http.MethodGet:
			a.listMessages(w, r, gid)
		default:
			methodNotAllowed(w)
		}

	case "transfer":
		// transfer subroutes: GET inspects, POST starts, POST /accept|/decline is the designee's call.
		if len(segs) == 2 {
			switch r.Method {
			case http.MethodPost:
				a.startOwnerTransfer(w, r, gid)
			case http.MethodGet:
				a.getOwnerTransfer(w, r, gid)
			default:
				methodNotAllowed(w)
			}
			break
		}
		if len(segs) == 3 && r.Method == http.MethodPost {
			switch segs[2] {
			case "accept":
				a.decideOwnerTransfer(w, r, gid, true)
			case "decline":
				a.decideOwnerTransfer(w, r, gid, false)
			default:
				notFoundGroupEndpoint(w)
			}
			break
		}
		notFoundGroupEndpoint(w)

	case "leave":
		if len(segs) != 2 || r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		a.leaveGroup(w, r, gid)

	case "pending-removals":
		// GET lists pending removals; POST /clear empties them after the Remove commit.
		if len(segs) == 2 && r.Method == http.MethodGet {
			a.listPendingRemovals(w, r, gid)
			break
		}
		if len(segs) == 3 && segs[2] == "clear" && r.Method == http.MethodPost {
			a.clearPendingRemovals(w, r, gid)
			break
		}
		notFoundGroupEndpoint(w)

	case "kick":
		if len(segs) != 2 || r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		a.kickMember(w, r, gid)

	default:
		notFoundGroupEndpoint(w)
	}
}

// POST /groups — create a group and its owner membership.
func (a *groupAPI) createGroup(w http.ResponseWriter, r *http.Request) {
	var req types.GroupCreateRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}

	groupID := utils.TrimSpace(req.GroupID)
	creator := utils.TrimSpace(req.Creator)
	if groupID == "" || creator == "" || req.NameEnc == "" {
		writeError(w, "MISSING_PAYLOAD", "group_id, name_enc and creator are required")
		return
	}
	if !isGroupID(groupID) {
		writeError(w, "INVALID_GROUP_ID", "group_id must be 10 lowercase base36 characters (digits + a-z)")
		return
	}
	nameEnc, err := base64.StdEncoding.DecodeString(req.NameEnc)
	if err != nil {
		writeError(w, "INVALID_NAME_ENC", "name_enc must be valid Base64")
		return
	}
	if len(nameEnc) > maxGroupNameEnc {
		writeError(w, "PAYLOAD_TOO_LARGE", "name_enc too large")
		return
	}

	// signed fields: [group_id, name_enc, creator] (+ timestamp + nonce)
	if !verifySignedRequestFields(a.st, w, creator,
		[]string{groupID, req.NameEnc, creator}, req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	g := &store.Group{
		GroupID:      groupID,
		NameEnc:      nameEnc,
		Creator:      creator,
		State:        store.GroupStateActive,
		CurrentEpoch: 0,
		MinSeq:       0,
	}
	if err := a.st.CreateGroup(ctx, g); err != nil {
		if errors.Is(err, store.ErrDuplicateGroup) {
			writeError(w, "DUPLICATE_GROUP_ID", "Group ID already exists")
			return
		}
		log.Printf("ERROR: create group %s: %v", groupID, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}

	LogAccess("[GROUP] create group=%s creator=%s", groupID, creator)
	writeOK(w, types.GroupCreateResponse{GroupID: groupID})
}

// GET /groups — list the caller's active groups.
func (a *groupAPI) listGroups(w http.ResponseWriter, r *http.Request) {
	var req types.GroupListRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [user_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	groups, err := a.st.ListGroupsForUser(ctx, userID)
	if err != nil {
		log.Printf("ERROR: list groups for %s: %v", userID, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	out := make([]types.GroupSummary, 0, len(groups))
	for _, g := range groups {
		out = append(out, types.GroupSummary{
			GroupID:      g.GroupID,
			NameEnc:      encodeGroupName(g.NameEnc),
			MyRole:       g.MyRole,
			CurrentEpoch: g.CurrentEpoch,
			MinSeq:       g.MinSeq,
		})
	}
	writeOK(w, out)
}

// GET /groups/{gid} — group metadata + member list (members only).
func (a *groupAPI) groupInfo(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupInfoRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, user_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	g, _, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	members, err := a.st.ListGroupMembers(ctx, gid)
	if err != nil {
		log.Printf("ERROR: list group members %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	out := make([]types.GroupMemberInfo, 0, len(members))
	for _, m := range members {
		out = append(out, types.GroupMemberInfo{UserID: m.UserID, Role: m.Role, JoinedEpoch: m.JoinedEpoch})
	}
	writeOK(w, types.GroupInfoResponse{
		GroupID:      g.GroupID,
		NameEnc:      encodeGroupName(g.NameEnc),
		Creator:      g.Creator,
		CurrentEpoch: g.CurrentEpoch,
		State:        g.State,
		Members:      out,
	})
}

// GET /groups/search?by=id&q=<gid> — ID search only; by=name is rejected (names are ciphertext).
func (a *groupAPI) searchGroups(w http.ResponseWriter, r *http.Request) {
	var req types.GroupSearchRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	by := utils.TrimSpace(req.By)
	q := utils.TrimSpace(req.Q)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [user_id, by, q]
	if !verifySignedRequestFields(a.st, w, userID, []string{userID, by, q},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	if by != "id" {
		writeError(w, "UNSUPPORTED_SEARCH_BY", "Only search by group ID is supported (by=id); searching by group name is not supported")
		return
	}
	if !isGroupIDPrefix(q) {
		writeError(w, "INVALID_QUERY", "q must be a 10-character lowercase base36 group ID or a prefix of one")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	results, err := a.st.SearchGroupsByID(ctx, q)
	if err != nil {
		log.Printf("ERROR: search groups %s: %v", q, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	out := make([]types.GroupSearchResult, 0, len(results))
	for _, g := range results {
		// Applicants verify the key belongs to the creator (user_id == public_key_id(pub, 10)); a creator without a public key is skipped, not returned unverifiable.
		pubKey, err := a.st.GetPublicKey(ctx, g.Creator)
		if err != nil {
			log.Printf("WARN: search group %s: creator %s public key unavailable: %v",
				g.GroupID, g.Creator, err)
			continue
		}
		// The justification is encrypted to the *current* owner's owner_public_key, which differs
		// from creator after a transfer; empty when the owner is gone (GROUP_OWNER_UPDATING refuses then).
		owner, ownerPub := "", ""
		if oid, oerr := a.st.GroupOwnerID(ctx, g.GroupID); oerr != nil {
			log.Printf("WARN: search group %s: owner lookup: %v", g.GroupID, oerr)
		} else if oid != "" {
			if opk, perr := a.st.GetPublicKey(ctx, oid); perr != nil {
				log.Printf("WARN: search group %s: owner %s public key unavailable: %v",
					g.GroupID, oid, perr)
			} else {
				owner, ownerPub = oid, opk
			}
		}
		out = append(out, types.GroupSearchResult{
			GroupID:          g.GroupID,
			NameEnc:          encodeGroupName(g.NameEnc),
			Creator:          g.Creator,
			CreatorPublicKey: pubKey,
			Owner:            owner,
			OwnerPublicKey:   ownerPub,
			MemberCount:      g.MemberCount,
			CreatedAt:        g.CreatedAt,
		})
	}
	writeOK(w, out)
}

// POST /groups/{gid}/key-packages — publish the caller's own KeyPackage.
// Applicants publish before joining, so this only requires an active group, not membership.
func (a *groupAPI) uploadKeyPackage(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupKeyPackageUploadRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	kpID := utils.TrimSpace(req.KPID)
	kpHash := utils.TrimSpace(req.KPHash)
	if userID == "" || kpID == "" || req.KPB64 == "" || kpHash == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id, kp_id, kp_b64 and kp_hash are required")
		return
	}
	// signed fields: [group_id, user_id, kp_id, kp_hash]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID, kpID, kpHash},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	if len(req.KPB64) > maxKeyPackageLen {
		writeError(w, "PAYLOAD_TOO_LARGE", "kp_b64 too large")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	if _, code, msg := loadActiveGroup(ctx, a.st, gid); code != "" {
		writeError(w, code, msg)
		return
	}

	// The server re-hashes the decoded bytes and rejects a mismatch (same code as commit/welcome).
	if !blobHashMatches(req.KPB64, kpHash) {
		writeError(w, "HASH_MISMATCH", "kp_hash does not match kp_b64")
		return
	}

	kp := &store.MLSKeyPackage{
		KPID:    kpID,
		UserID:  userID,
		GroupID: gid,
		KPB64:   req.KPB64,
		KPHash:  strings.ToLower(kpHash),
	}
	if err := a.st.CreateKeyPackage(ctx, kp); err != nil {
		if errors.Is(err, store.ErrDuplicateKeyPackage) {
			writeError(w, "DUPLICATE_KEY_PACKAGE", "kp_id already exists")
			return
		}
		log.Printf("ERROR: create key package %s: %v", kpID, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}

	LogAccess("[GROUP] key-package upload group=%s user=%s kp=%s", gid, userID, kpID)
	writeOK(w, struct {
		KPID string `json:"kp_id"`
	}{KPID: kpID})
}

// GET /groups/{gid}/key-packages?kp_id=... — fetch a KeyPackage (members only, for Add).
func (a *groupAPI) getKeyPackage(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupKeyPackageGetRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	kpID := utils.TrimSpace(req.KPID)
	if userID == "" || kpID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id and kp_id are required")
		return
	}
	// signed fields: [group_id, user_id, kp_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID, kpID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	if _, _, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID); code != "" {
		writeError(w, code, msg)
		return
	}

	kp, err := a.st.GetKeyPackage(ctx, kpID)
	if errors.Is(err, store.ErrKeyPackageNotFound) {
		writeError(w, "KEY_PACKAGE_NOT_FOUND", "KeyPackage not found")
		return
	}
	if err != nil {
		log.Printf("ERROR: get key package %s: %v", kpID, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	if kp.GroupID != gid {
		writeError(w, "KEY_PACKAGE_NOT_FOUND", "KeyPackage not found")
		return
	}
	writeOK(w, types.GroupKeyPackageResponse{
		KPID:      kp.KPID,
		UserID:    kp.UserID,
		GroupID:   kp.GroupID,
		KPB64:     kp.KPB64,
		KPHash:    kp.KPHash,
		CreatedAt: kp.CreatedAt,
	})
}

// POST /groups/{gid}/join_requests — an outsider applies to join.
func (a *groupAPI) createJoinRequest(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupJoinRequestCreate
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	requestID := utils.TrimSpace(req.RequestID)
	applicant := utils.TrimSpace(req.Applicant)
	kpID := utils.TrimSpace(req.KPID)
	kpHash := utils.TrimSpace(req.KPHash)
	if userID == "" || requestID == "" || applicant == "" || kpID == "" || kpHash == "" {
		writeError(w, "MISSING_PAYLOAD",
			"user_id, request_id, applicant, kp_id and kp_hash are required")
		return
	}
	// signed fields: [group_id, request_id, applicant, kp_id, kp_hash, text_ct, text_iv, text_tag, text_wrapped_key]
	if !verifySignedRequestFields(a.st, w, userID,
		[]string{gid, requestID, applicant, kpID, kpHash,
			req.TextCT, req.TextIV, req.TextTag, req.TextWrappedKey},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	// The signature binds user_id: an application cannot claim to be someone else.
	if applicant != userID {
		writeError(w, "APPLICANT_MISMATCH", "applicant must match the signing identity")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	if _, code, msg := loadActiveGroup(ctx, a.st, gid); code != "" {
		writeError(w, code, msg)
		return
	}
	// With a pending transfer and no owner, nobody can do the MLS Add, so reject with
	// GROUP_OWNER_UPDATING rather than park it; a plain transfer (old owner still there) is allowed.
	if _, terr := a.st.PendingOwnerTransfer(ctx, gid); terr == nil {
		hasOwner, herr := a.st.GroupHasOwner(ctx, gid)
		if herr != nil {
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		if !hasOwner {
			writeError(w, "GROUP_OWNER_UPDATING", "Group owner update in progress; joining is temporarily disabled")
			return
		}
	} else if !errors.Is(terr, store.ErrTransferNotFound) {
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	member, err := a.st.IsGroupMember(ctx, gid, applicant)
	if err != nil {
		log.Printf("ERROR: join request membership check %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	if member {
		writeError(w, "ALREADY_MEMBER", "The applicant is already a group member")
		return
	}

	kp, err := a.st.GetKeyPackage(ctx, kpID)
	if errors.Is(err, store.ErrKeyPackageNotFound) {
		writeError(w, "KEY_PACKAGE_NOT_FOUND", "KeyPackage not found")
		return
	}
	if err != nil {
		log.Printf("ERROR: join request get key package %s: %v", kpID, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	if kp.UserID != applicant || kp.GroupID != gid {
		// Do not disclose that the id exists but belongs to someone else.
		writeError(w, "KEY_PACKAGE_NOT_FOUND", "KeyPackage not found or does not belong to the applicant")
		return
	}
	// KNOWN GAP (intentional): KeyPackages are not single-use. The server never parses MLS state, so
	// it cannot mark one consumed; the ratchet tree rejects reuse as a duplicate signature key.
	if !strings.EqualFold(kp.KPHash, kpHash) {
		writeError(w, "KEY_PACKAGE_HASH_MISMATCH", "kp_hash does not match the uploaded KeyPackage")
		return
	}

	jr := &store.GroupJoinRequest{
		RequestID:      requestID,
		GroupID:        gid,
		Applicant:      applicant,
		KPID:           kpID,
		KPHash:         kpHash,
		TextCT:         req.TextCT,
		TextIV:         req.TextIV,
		TextTag:        req.TextTag,
		TextWrappedKey: req.TextWrappedKey,
	}
	if err := a.st.CreateJoinRequest(ctx, jr); err != nil {
		switch {
		case errors.Is(err, store.ErrDuplicateJoinRequest):
			writeError(w, "DUPLICATE_JOIN_REQUEST", "The applicant already has a pending join request")
		case errors.Is(err, store.ErrDuplicateRequestID):
			writeError(w, "DUPLICATE_REQUEST_ID", "request_id already exists")
		default:
			log.Printf("ERROR: create join request %s: %v", requestID, err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		}
		return
	}

	// The applicant is not a member yet, so notifyGroup would miss them: use notifyGroupRoles for owner/admin.
	notifyGroupRoles(a.st, a.sm, gid, "join_request",
		[]string{store.GroupRoleOwner, store.GroupRoleAdmin}, applicant)

	LogAccess("[GROUP] join-request group=%s applicant=%s req=%s", gid, applicant, requestID)
	writeOK(w, struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}{RequestID: requestID, Status: store.JoinRequestPending})
}

// GET /groups/{gid}/join_requests — pending applications (owner/admin only).
func (a *groupAPI) listJoinRequests(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupJoinRequestListRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, user_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	_, member, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if !hasGroupRole(member, store.GroupRoleOwner, store.GroupRoleAdmin) {
		writeError(w, "FORBIDDEN", "Only owner/admin can view join requests")
		return
	}

	reqs, err := a.st.ListPendingJoinRequests(ctx, gid)
	if err != nil {
		log.Printf("ERROR: list join requests %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	out := make([]types.GroupJoinRequestInfo, 0, len(reqs))
	for _, jr := range reqs {
		out = append(out, types.GroupJoinRequestInfo{
			RequestID:      jr.RequestID,
			GroupID:        jr.GroupID,
			Applicant:      jr.Applicant,
			KPID:           jr.KPID,
			KPHash:         jr.KPHash,
			TextCT:         jr.TextCT,
			TextIV:         jr.TextIV,
			TextTag:        jr.TextTag,
			TextWrappedKey: jr.TextWrappedKey,
			Status:         jr.Status,
			CreatedAt:      jr.CreatedAt,
		})
	}
	writeOK(w, out)
}

// POST /groups/{gid}/join_requests/{rid}/decide — owner/admin allow/deny. allow only flips the
// request status; membership begins when the Add Commit/Welcome lands (see AppendWelcome).
func (a *groupAPI) decideJoinRequest(w http.ResponseWriter, r *http.Request, gid, requestID string) {
	var req types.GroupJoinDecisionRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	decision := utils.TrimSpace(req.Decision)
	if userID == "" || requestID == "" || decision == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id, request_id and decision are required")
		return
	}
	// signed fields: [group_id, request_id, decision]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, requestID, decision},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	if decision != "allow" && decision != "deny" {
		writeError(w, "INVALID_DECISION", "decision must be allow or deny")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	_, member, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if !hasGroupRole(member, store.GroupRoleOwner, store.GroupRoleAdmin) {
		// Exception: an old owner who started a transfer keeps approval rights over requests that
		// predate it, but membership is checked first, so it only holds while they are still a member.
		ts, terr := a.st.JoinRequestCreatedAt(ctx, gid, requestID)
		allowed := false
		if terr == nil {
			if ok, berr := a.st.OwnsJoinRequestBacklog(ctx, gid, userID, ts); berr == nil && ok {
				allowed = true
			}
		}
		if !allowed {
			writeError(w, "FORBIDDEN", "Only owner/admin can decide join requests")
			return
		}
	}

	status := store.JoinRequestApproved
	if decision == "deny" {
		status = store.JoinRequestDenied
	}
	if err := a.st.DecideJoinRequest(ctx, gid, requestID, status, userID); err != nil {
		switch {
		case errors.Is(err, store.ErrJoinRequestNotFound):
			writeError(w, "JOIN_REQUEST_NOT_FOUND", "Join request not found")
		case errors.Is(err, store.ErrJoinRequestGroupMismatch):
			writeError(w, "REQUEST_GROUP_MISMATCH", "The request does not belong to this group")
		case errors.Is(err, store.ErrJoinRequestNotPending):
			writeError(w, "REQUEST_NOT_PENDING", "The request has already been handled")
		default:
			log.Printf("ERROR: decide join request %s: %v", requestID, err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		}
		return
	}

	LogAccess("[GROUP] join-request decide group=%s req=%s by=%s decision=%s",
		gid, requestID, userID, decision)
	writeOK(w, types.GroupJoinDecisionResponse{RequestID: requestID, Status: status})
}

// POST /groups/{gid}/commits — store an opaque MLS Commit and advance the epoch.
func (a *groupAPI) createCommit(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupCommitRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	dataHash := utils.TrimSpace(req.DataHash)
	if userID == "" || req.CommitB64 == "" || dataHash == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id, commit_b64 and data_hash are required")
		return
	}
	// signed fields: [group_id, epoch, parent_epoch, kind, data_hash]
	if !verifySignedRequestFields(a.st, w, userID,
		[]string{gid, strconv.FormatInt(req.Epoch, 10), strconv.FormatInt(req.ParentEpoch, 10),
			req.Kind, dataHash},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	if len(req.CommitB64) > maxMLSBlobLen {
		writeError(w, "PAYLOAD_TOO_LARGE", "commit_b64 too large")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	_, member, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if !hasGroupRole(member, store.GroupRoleOwner, store.GroupRoleAdmin) {
		writeError(w, "FORBIDDEN", "Only owner/admin can submit a Commit")
		return
	}

	// The server re-hashes the decoded bytes and rejects a mismatch (same code as commit/welcome).
	if !blobHashMatches(req.CommitB64, dataHash) {
		writeError(w, "HASH_MISMATCH", "data_hash does not match commit_b64")
		return
	}

	entry := &store.GroupMLSLogEntry{
		GroupID:  gid,
		Epoch:    req.Epoch,
		Kind:     req.Kind,
		Sender:   userID,
		DataB64:  req.CommitB64,
		DataHash: strings.ToLower(dataHash),
	}
	seq, err := a.st.AppendGroupCommit(ctx, entry, req.ParentEpoch)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrDuplicateCommitEpoch):
			writeError(w, "DUPLICATE_COMMIT_EPOCH", "A Commit already exists for this epoch (fork rejected)")
		case errors.Is(err, store.ErrEpochParentMismatch):
			writeError(w, "EPOCH_MISMATCH", "parent_epoch does not match the current epoch")
		case errors.Is(err, store.ErrEpochNotMonotonic):
			writeError(w, "EPOCH_NOT_MONOTONIC", "epoch must be greater than the current epoch")
		case errors.Is(err, store.ErrGroupNotFound):
			writeError(w, "GROUP_NOT_FOUND", "Group not found")
		default:
			log.Printf("ERROR: append commit %s: %v", gid, err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		}
		return
	}

	notifyGroup(a.st, a.sm, gid, "commit", userID)
	LogAccess("[GROUP] commit group=%s epoch=%d by=%s seq=%d", gid, req.Epoch, userID, seq)
	writeOK(w, types.GroupCommitResponse{GroupID: gid, Epoch: req.Epoch, Seq: seq})
}

// GET /groups/{gid}/commits?since_epoch=N — commits with epoch > N (members).
func (a *groupAPI) listCommits(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupMLSLogListRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, since_epoch]
	if !verifySignedRequestFields(a.st, w, userID,
		[]string{gid, strconv.FormatInt(req.SinceEpoch, 10)},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	if _, _, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID); code != "" {
		writeError(w, code, msg)
		return
	}

	entries, err := a.st.ListMLSLogSince(ctx, gid, req.SinceEpoch)
	if err != nil {
		log.Printf("ERROR: list commits %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	out := make([]types.GroupCommitInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, types.GroupCommitInfo{
			Seq:      e.Seq,
			Epoch:    e.Epoch,
			Kind:     e.Kind,
			Sender:   e.Sender,
			Target:   e.Target,
			DataB64:  e.DataB64,
			DataHash: e.DataHash,
		})
	}
	writeOK(w, out)
}

// POST /groups/{gid}/welcomes — store an opaque Welcome and create the target's membership row.
// KNOWN GAP (intentional): target_user is not checked against an allowed join request; the receiver's MLS guarantees it.
func (a *groupAPI) createWelcome(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupWelcomeCreateRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	target := utils.TrimSpace(req.TargetUser)
	dataHash := utils.TrimSpace(req.DataHash)
	if userID == "" || target == "" || req.WelcomeB64 == "" || dataHash == "" {
		writeError(w, "MISSING_PAYLOAD",
			"user_id, target_user, welcome_b64 and data_hash are required")
		return
	}
	// signed fields: [group_id, target_user, data_hash, epoch]
	if !verifySignedRequestFields(a.st, w, userID,
		[]string{gid, target, dataHash, strconv.FormatInt(req.Epoch, 10)},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	if len(req.WelcomeB64) > maxMLSBlobLen {
		writeError(w, "PAYLOAD_TOO_LARGE", "welcome_b64 too large")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	_, member, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	// Welcomes add a member, so only group administrators (owner/admin) may submit them; a plain member
	// could otherwise fill the group's member table with arbitrary/unverified targets.
	if !hasGroupRole(member, store.GroupRoleOwner, store.GroupRoleAdmin) {
		writeError(w, "FORBIDDEN", "Only owner/admin can submit a Welcome")
		return
	}

	if !blobHashMatches(req.WelcomeB64, dataHash) {
		writeError(w, "HASH_MISMATCH", "data_hash does not match welcome_b64")
		return
	}

	entry := &store.GroupMLSLogEntry{
		GroupID:  gid,
		Epoch:    req.Epoch,
		Kind:     "welcome",
		Sender:   userID,
		Target:   target,
		DataB64:  req.WelcomeB64,
		DataHash: strings.ToLower(dataHash),
	}
	seq, err := a.st.AppendWelcome(ctx, entry)
	if err != nil {
		if errors.Is(err, store.ErrGroupNotFound) {
			writeError(w, "GROUP_NOT_FOUND", "Group not found")
			return
		}
		if errors.Is(err, store.ErrGroupFull) {
			writeError(w, "GROUP_FULL",
				"Group member limit reached (1000 members)")
			return
		}
		log.Printf("ERROR: append welcome %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}

	notifyGroup(a.st, a.sm, gid, "welcome", userID)
	LogAccess("[GROUP] welcome group=%s target=%s epoch=%d by=%s seq=%d",
		gid, target, req.Epoch, userID, seq)
	writeOK(w, types.GroupWelcomeResponse{
		GroupID:    gid,
		TargetUser: target,
		Epoch:      req.Epoch,
		Seq:        seq,
	})
}

// GET /groups/{gid}/welcomes — only the Welcome entries addressed to the caller.
// KNOWN GAP (intentional): no consumed flag, so calls repeat the same rows; the client consumes once via its persisted joined state.
func (a *groupAPI) listWelcomes(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupWelcomeListRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, user_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	if _, _, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID); code != "" {
		writeError(w, code, msg)
		return
	}

	entries, err := a.st.ListWelcomesFor(ctx, gid, userID)
	if err != nil {
		log.Printf("ERROR: list welcomes %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	out := make([]types.GroupWelcomeInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, types.GroupWelcomeInfo{
			Seq:        e.Seq,
			Epoch:      e.Epoch,
			Kind:       e.Kind,
			Sender:     e.Sender,
			Target:     e.Target,
			TargetUser: e.Target,
			DataB64:    e.DataB64,
			DataHash:   e.DataHash,
		})
	}
	writeOK(w, out)
}

// POST /groups/{gid}/messages — append one ciphertext to the group queue.
func (a *groupAPI) sendMessage(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupMessageSendRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	msgID := utils.TrimSpace(req.MsgID)
	if userID == "" || msgID == "" || req.Ciphertext == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id, msg_id and ciphertext are required")
		return
	}
	// signed fields: [group_id, msg_id, epoch, ciphertext, msg_type, file_id]
	if !verifySignedRequestFields(a.st, w, userID,
		[]string{gid, msgID, strconv.FormatInt(req.Epoch, 10), req.Ciphertext, req.MsgType, req.FileID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	if len(req.Ciphertext) > maxGroupMsgLen {
		writeError(w, "PAYLOAD_TOO_LARGE", "ciphertext too large")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	g, member, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if member.JoinedEpoch > req.Epoch {
		writeError(w, "EPOCH_BEFORE_JOIN", "epoch is before the epoch the member joined the group")
		return
	}
	if req.Epoch != g.CurrentEpoch {
		writeError(w, "EPOCH_MISMATCH", "epoch does not match the group's current epoch")
		return
	}

	gm := &store.GroupMessage{
		GroupID:    gid,
		Epoch:      req.Epoch,
		Sender:     userID,
		MsgID:      msgID,
		Ciphertext: req.Ciphertext,
		MsgType:    req.MsgType,
		FileID:     req.FileID,
		Timestamp:  strconv.FormatInt(req.Timestamp, 10),
	}
	seq, err := a.st.AppendGroupMessage(ctx, gm)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateGroupMsg) {
			writeError(w, "DUPLICATE_MSG_ID", "Duplicate message (msg_id already exists)")
			return
		}
		log.Printf("ERROR: append group message %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}

	notifyGroup(a.st, a.sm, gid, "message", userID)
	LogAccess("[GROUP] message group=%s sender=%s msg=%s seq=%d", gid, userID, msgID, seq)
	writeOK(w, types.GroupMessageResponse{MsgID: msgID, Seq: seq})
}

// GET /groups/{gid}/messages?since_seq=N&limit=L — ascending page from the single queue, clamped to its lower bound (groups.min_seq).
func (a *groupAPI) listMessages(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupMessageListRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, since_seq]
	if !verifySignedRequestFields(a.st, w, userID,
		[]string{gid, strconv.FormatInt(req.SinceSeq, 10)},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	g, member, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = defaultMessagePage
	}
	if limit > maxMessagePage {
		limit = maxMessagePage
	}

	minSeq := g.MinSeq
	since := req.SinceSeq
	if since < minSeq {
		// Rows below the bound are gone, so resume from it; min_seq in the response tells the client it was truncated.
		since = minSeq
	}

	msgs, err := a.st.ListGroupMessages(ctx, gid, since, limit)
	if err != nil {
		log.Printf("ERROR: list group messages %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	out := make([]types.GroupMessageInfo, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, types.GroupMessageInfo{
			Seq:        m.Seq,
			Epoch:      m.Epoch,
			Sender:     m.Sender,
			MsgID:      m.MsgID,
			Ciphertext: m.Ciphertext,
			MsgType:    m.MsgType,
			FileID:     m.FileID,
			Timestamp:  m.Timestamp,
			CreatedAt:  m.CreatedAt,
		})
	}
	writeOK(w, types.GroupMessagesResponse{
		Messages: out,
		MinSeq:   minSeq,
		MyRole:   member.Role,
	})
}

// POST /groups/{gid}/messages/ack — advance the caller's cursor (monotonic); it deletes nothing, reclamation is a separate background pass.
func (a *groupAPI) ackMessages(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupMessageAckRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, last_seq]
	if !verifySignedRequestFields(a.st, w, userID,
		[]string{gid, strconv.FormatInt(req.LastSeq, 10)},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	if _, _, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID); code != "" {
		writeError(w, code, msg)
		return
	}
	if req.LastSeq < 0 {
		writeError(w, "INVALID_LAST_SEQ", "last_seq must not be negative")
		return
	}

	maxSeq, err := a.st.MaxGroupMessageSeq(ctx, gid)
	if err != nil {
		log.Printf("ERROR: ack max seq %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	if req.LastSeq > maxSeq {
		writeError(w, "SEQ_OUT_OF_RANGE", "last_seq exceeds the group's current maximum seq")
		return
	}

	if err := a.st.UpsertGroupCursor(ctx, userID, gid, req.LastSeq); err != nil {
		log.Printf("ERROR: ack upsert cursor %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	cur, err := a.st.GetGroupCursor(ctx, userID, gid)
	if err != nil {
		log.Printf("ERROR: ack read cursor %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	writeOK(w, types.GroupMessageAckResponse{LastSeq: cur})
}

// POST /groups/{gid}/leave — remove the caller's membership (idempotent).
func (a *groupAPI) leaveGroup(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupLeaveRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, user_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	if _, code, msg := loadActiveGroup(ctx, a.st, gid); code != "" {
		writeError(w, code, msg)
		return
	}
	// store.LeaveGroup is atomic (owner check, group_owner_transfers, membership/group_cursor
	// deletion, group_pending_removals); a leaving owner must name a successor or no one can commit.
	res, err := a.st.LeaveGroup(ctx, gid, userID, utils.TrimSpace(req.SuccessorUserID))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrSuccessorRequired):
			writeError(w, "SUCCESSOR_REQUIRED",
				"The owner must name a new owner before leaving")
		case errors.Is(err, store.ErrInvalidSuccessor):
			writeError(w, "INVALID_SUCCESSOR",
				"The designated new owner must be an existing member of this group and cannot be yourself")
		case errors.Is(err, store.ErrGroupMemberNotFound):
			writeError(w, "NOT_GROUP_MEMBER", "Not a group member")
		case errors.Is(err, store.ErrGroupNotFound):
			writeError(w, "GROUP_NOT_FOUND", "Group not found")
		default:
			log.Printf("ERROR: leave group %s: %v", gid, err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		}
		return
	}

	// Tell the rest: on sync they see the leaver still in their MLS tree but off the roster and
	// submit a Remove (openmls CannotRemoveSelf), which drops them from the tree and rotates keys.
	if !res.Dissolved {
		notifyGroup(a.st, a.sm, gid, "leave", userID)
	}
	LogAccess("[GROUP] leave group=%s user=%s successor=%s dissolved=%v pending=%v",
		gid, userID, res.Successor, res.Dissolved, res.PendingRemoval)
	writeOK(w, struct {
		GroupID        string `json:"group_id"`
		Status         string `json:"status"`
		Successor      string `json:"successor_user_id,omitempty"`
		Dissolved      bool   `json:"dissolved,omitempty"`
		PendingRemoval bool   `json:"pending_removal,omitempty"`
	}{
		GroupID:        gid,
		Status:         "left",
		Successor:      res.Successor,
		Dissolved:      res.Dissolved,
		PendingRemoval: res.PendingRemoval,
	})
}

// GET /groups/{gid}/pending-removals — owner only (not owner/admin). Work booked while the owner
// was offline: the owner client pulls it on startup/sync and pushes the Remove commit itself.
func (a *groupAPI) listPendingRemovals(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupInfoRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, user_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	ctx, cancel := bgCtx()
	defer cancel()

	if _, code, msg := loadActiveGroup(ctx, a.st, gid); code != "" {
		writeError(w, code, msg)
		return
	}
	_, actor, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if actor.Role != store.GroupRoleOwner {
		writeError(w, "NOT_OWNER", "Only the group owner can view pending removals")
		return
	}
	targets, err := a.st.PendingRemovalIDs(ctx, gid)
	if err != nil {
		log.Printf("ERROR: list pending removals %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	writeOK(w, types.GroupPendingRemovalsResponse{GroupID: gid, Targets: targets})
}

// POST /groups/{gid}/pending-removals/clear — owner only (not owner/admin). Called after the
// Remove commit lands (or nobody needs removing); stale entries are harmless, the next sync clears them.
func (a *groupAPI) clearPendingRemovals(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupPendingRemovalsClearRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	ctx, cancel := bgCtx()
	defer cancel()

	if _, code, msg := loadActiveGroup(ctx, a.st, gid); code != "" {
		writeError(w, code, msg)
		return
	}
	_, actor, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if actor.Role != store.GroupRoleOwner {
		writeError(w, "NOT_OWNER", "Only the group owner can clear pending removals")
		return
	}
	if err := a.st.ClearPendingRemovals(ctx, gid); err != nil {
		log.Printf("ERROR: clear pending removals %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	writeOK(w, map[string]string{"group_id": gid, "status": "cleared"})
}

// POST /groups/{gid}/transfer — the owner starts a hand-over.
// The old owner keeps ownership until the designee confirms, so the group keeps running (they
// still approve joins). Unlike leave, where the owner is gone and nobody can commit.
func (a *groupAPI) startOwnerTransfer(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupTransferRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	designee := utils.TrimSpace(req.Designee)
	if userID == "" || designee == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id and designee required")
		return
	}
	// signed fields: [group_id, user_id, designee]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID, designee},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	ctx, cancel := bgCtx()
	defer cancel()

	if _, _, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID); code != "" {
		writeError(w, code, msg)
		return
	}
	me, errMember := a.st.GetGroupMember(ctx, gid, userID)
	if errMember != nil || me == nil || me.Role != store.GroupRoleOwner {
		writeError(w, "NOT_OWNER", "Only the group owner can initiate a transfer")
		return
	}
	if err := a.st.CreateOwnerTransfer(ctx, gid, userID, designee); err != nil {
		switch {
		case errors.Is(err, store.ErrTransferPending):
			writeError(w, "TRANSFER_PENDING", "A transfer is already awaiting confirmation")
		case errors.Is(err, store.ErrInvalidSuccessor):
			writeError(w, "INVALID_SUCCESSOR", "The transferee must be an existing member of this group and cannot be yourself")
		default:
			log.Printf("ERROR: start transfer %s: %v", gid, err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		}
		return
	}
	notifyUser(a.sm, designee, gid, "transfer")
	LogAccess("[GROUP] transfer-start group=%s from=%s to=%s", gid, userID, designee)
	writeOK(w, map[string]any{"group_id": gid, "designee": designee, "status": "pending"})
}

// GET /groups/{gid}/transfer — the pending transfer (visible to the designee and current owner).
func (a *groupAPI) getOwnerTransfer(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupInfoRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	ctx, cancel := bgCtx()
	defer cancel()

	me, errMember := a.st.GetGroupMember(ctx, gid, userID)
	if errMember != nil && !errors.Is(errMember, store.ErrGroupMemberNotFound) {
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	t, err := a.st.PendingOwnerTransfer(ctx, gid)
	if errors.Is(err, store.ErrTransferNotFound) {
		writeOK(w, map[string]any{"group_id": gid, "transfer": nil})
		return
	}
	if err != nil {
		log.Printf("ERROR: get transfer %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	if userID != t.Designee && (me == nil || me.Role != store.GroupRoleOwner) {
		writeOK(w, map[string]any{"group_id": gid, "transfer": nil})
		return
	}
	writeOK(w, map[string]any{
		"group_id": gid,
		"transfer": types.GroupOwnerTransferInfo{
			GroupID: t.GroupID, PrevOwner: t.PrevOwner, Designee: t.Designee,
			State: t.State, CreatedAt: t.CreatedAt,
		},
	})
}

// POST /groups/{gid}/transfer/{accept|decline} — the designee decides.
func (a *groupAPI) decideOwnerTransfer(w http.ResponseWriter, r *http.Request, gid string, accept bool) {
	var req types.GroupTransferDecideRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}
	ctx, cancel := bgCtx()
	defer cancel()

	t, err := a.st.DecideOwnerTransfer(ctx, gid, userID, accept)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrTransferNotFound):
			writeError(w, "TRANSFER_NOT_FOUND", "No transfer is awaiting confirmation")
		case errors.Is(err, store.ErrNotDesignee):
			writeError(w, "NOT_DESIGNEE", "Only the designated successor can confirm this transfer")
		case errors.Is(err, store.ErrInvalidSuccessor):
			writeError(w, "INVALID_SUCCESSOR", "You are no longer in this group")
		default:
			log.Printf("ERROR: decide transfer %s: %v", gid, err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		}
		return
	}
	notifyGroup(a.st, a.sm, gid, "commit", userID)
	LogAccess("[GROUP] transfer-decide group=%s designee=%s accept=%v state=%s",
		gid, userID, accept, t.State)
	writeOK(w, map[string]any{
		"group_id": gid, "state": t.State, "designee": t.Designee,
		"prev_owner": t.PrevOwner,
	})
}

// notifyUser sends one `group_notify` to a single user (best-effort); transfers involve one person.
func notifyUser(sm *session.Manager, userID, groupID, reason string) {
	if sm == nil {
		return
	}
	sm.EnqueueMessage(userID, &types.WSEnvelope{
		Type:    "group_notify",
		Payload: types.GroupNotifyPayload{GroupID: groupID, Reason: reason},
	})
}

// POST /groups/{gid}/kick — owner/admin removes another member.
// The server only authorizes and deletes the row; the caller must already have pushed the matching
// Remove commit, which drops the member from the ratchet tree and rotates keys. This only cuts off
// their ciphertext access, so the commit must go out while the caller is still a member.
func (a *groupAPI) kickMember(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupKickMemberRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	target := utils.TrimSpace(req.TargetUser)
	if userID == "" || target == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id and target_user required")
		return
	}
	if userID == target {
		writeError(w, "INVALID_TARGET", "Cannot leave by removing a member; use /leave")
		return
	}
	// signed fields: [group_id, user_id, target_user]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID, target},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	g, code, msg := loadActiveGroup(ctx, a.st, gid)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	_, actor, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if actor.Role != store.GroupRoleOwner {
		writeError(w, "NOT_OWNER", "Only the group owner can remove members")
		return
	}
	// The owner cannot be kicked (the group would lose its only admin).
	if target == g.Creator {
		writeError(w, "NOT_OWNER", "Cannot remove the group owner")
		return
	}
	if _, _, code, _ := loadActiveGroupMember(ctx, a.st, gid, target); code != "" {
		// Target is not a member: return success idempotently so client retries do not error.
		writeOK(w, struct {
			GroupID    string `json:"group_id"`
			TargetUser string `json:"target_user"`
			Status     string `json:"status"`
		}{GroupID: gid, TargetUser: target, Status: "not_a_member"})
		return
	}
	if err := a.st.RemoveGroupMember(ctx, gid, target); err != nil {
		log.Printf("ERROR: kick member %s/%s: %v", gid, target, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	notifyGroup(a.st, a.sm, gid, "commit", userID)
	LogAccess("[GROUP] kick group=%s target=%s by=%s", gid, target, userID)
	writeOK(w, struct {
		GroupID    string `json:"group_id"`
		TargetUser string `json:"target_user"`
		Status     string `json:"status"`
	}{GroupID: gid, TargetUser: target, Status: "kicked"})
}

// DELETE /groups/{gid} — dissolve (owner only).
func (a *groupAPI) dissolveGroup(w http.ResponseWriter, r *http.Request, gid string) {
	var req types.GroupDissolveRequest
	if err := decodeGroupParams(w, r, &req); err != nil {
		writeError(w, "INVALID_JSON", "Invalid JSON body")
		return
	}
	userID := utils.TrimSpace(req.UserID)
	if userID == "" {
		writeError(w, "MISSING_PAYLOAD", "user_id required")
		return
	}
	// signed fields: [group_id, user_id]
	if !verifySignedRequestFields(a.st, w, userID, []string{gid, userID},
		req.Timestamp, req.Nonce, req.Signature) {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	_, member, code, msg := loadActiveGroupMember(ctx, a.st, gid, userID)
	if code != "" {
		writeError(w, code, msg)
		return
	}
	if member.Role != store.GroupRoleOwner {
		writeError(w, "NOT_OWNER", "Only the owner can dissolve the group")
		return
	}
	if err := a.st.DissolveGroup(ctx, gid); err != nil {
		log.Printf("ERROR: dissolve group %s: %v", gid, err)
		writeError(w, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	// Dissolving only flips groups.state and emits no event, so without this notify even online members keep a stale copy until they sync or restart.
	notifyGroup(a.st, a.sm, gid, "dissolved", userID)
	LogAccess("[GROUP] dissolve group=%s by=%s", gid, userID)
	writeOK(w, struct {
		GroupID string `json:"group_id"`
		State   string `json:"state"`
	}{GroupID: gid, State: store.GroupStateDissolved})
}

// verifySignedRequestFields wraps verifySignedRequest, writes the error response itself, and returns true on a valid signature.
func verifySignedRequestFields(st *store.Store, w http.ResponseWriter, userID string,
	fields []string, ts int64, nonce, signature string) bool {

	code, msg := verifySignedRequest(st, userID, fields, strconv.FormatInt(ts, 10), nonce, signature)
	if code != "" {
		writeError(w, code, msg)
		return false
	}
	return true
}

// decodeGroupParams decodes request parameters from a JSON body (POST/DELETE) or query string
// (GET); both are accepted for symmetry with the rest of the API, and query wins when both exist.
func decodeGroupParams(w http.ResponseWriter, r *http.Request, v interface{}) error {
	if r.Body != nil && r.ContentLength != 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
		if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return nil
	}
	rv = rv.Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		vals, ok := q[tag]
		if !ok || len(vals) == 0 {
			continue
		}
		fv := rv.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(vals[0])
		case reflect.Int, reflect.Int64:
			n, err := strconv.ParseInt(vals[0], 10, 64)
			if err != nil {
				return fmt.Errorf("parameter %q must be an integer", tag)
			}
			fv.SetInt(n)
		}
	}
	return nil
}

// loadActiveGroup loads a group and rejects missing/dissolved ones.
func loadActiveGroup(ctx context.Context, st *store.Store, groupID string) (*store.Group, string, string) {
	g, err := st.GetGroup(ctx, groupID)
	if errors.Is(err, store.ErrGroupNotFound) {
		return nil, "GROUP_NOT_FOUND", "Group not found"
	}
	if err != nil {
		log.Printf("ERROR: load group %s: %v", groupID, err)
		return nil, "DB_UNAVAILABLE", "Database unavailable"
	}
	if g.State != store.GroupStateActive {
		return nil, "GROUP_DISSOLVED", "Group dissolved"
	}
	return g, "", ""
}

// loadActiveGroupMember additionally requires the caller to be a member.
func loadActiveGroupMember(ctx context.Context, st *store.Store, groupID, userID string) (*store.Group, *store.GroupMember, string, string) {
	g, code, msg := loadActiveGroup(ctx, st, groupID)
	if code != "" {
		return nil, nil, code, msg
	}
	m, err := st.GetGroupMember(ctx, groupID, userID)
	if errors.Is(err, store.ErrGroupMemberNotFound) {
		return nil, nil, "NOT_GROUP_MEMBER", "Not a group member"
	}
	if err != nil {
		log.Printf("ERROR: load group member %s/%s: %v", groupID, userID, err)
		return nil, nil, "DB_UNAVAILABLE", "Database unavailable"
	}
	return g, m, "", ""
}

// hasGroupRole reports whether the member holds one of the given roles.
func hasGroupRole(m *store.GroupMember, roles ...string) bool {
	if m == nil {
		return false
	}
	for _, r := range roles {
		if m.Role == r {
			return true
		}
	}
	return false
}

// notifyGroupRoles is like notifyGroup but only reaches members whose role is in `roles`; used for join requests, where notifying everyone else is noise.
func notifyGroupRoles(st *store.Store, sm *session.Manager, groupID, reason string, roles []string, exclude string) {
	if sm == nil {
		return
	}
	ctx, cancel := bgCtx()
	defer cancel()

	members, err := st.GroupMemberIDs(ctx, groupID)
	if err != nil {
		log.Printf("WARN: notify roles %s: %v", groupID, err)
		return
	}
	env := &types.WSEnvelope{
		Type:    "group_notify",
		Payload: types.GroupNotifyPayload{GroupID: groupID, Reason: reason},
	}
	for _, uid := range members {
		if uid == exclude {
			continue
		}
		m, err := st.GetGroupMember(ctx, groupID, uid)
		if err != nil || m == nil {
			continue
		}
		if hasGroupRole(m, roles...) {
			sm.EnqueueMessage(uid, env)
		}
	}
}

// notifyGroup best-effort tells the other online members to pull new data; it is only a hint, REST pulls are authoritative.
func notifyGroup(st *store.Store, sm *session.Manager, groupID, reason, exclude string) {
	if sm == nil {
		return
	}
	ctx, cancel := bgCtx()
	defer cancel()

	members, err := st.GroupMemberIDs(ctx, groupID)
	if err != nil {
		log.Printf("WARN: notify group %s: %v", groupID, err)
		return
	}
	env := &types.WSEnvelope{
		Type:    "group_notify",
		Payload: types.GroupNotifyPayload{GroupID: groupID, Reason: reason},
	}
	for _, uid := range members {
		if uid == exclude {
			continue
		}
		sm.EnqueueMessage(uid, env)
	}
}

// isGroupID reports whether s is exactly 10 lowercase base36 characters; must match the client's
// GROUP_ID_LEN. Owners read IDs out to applicants, hence the short human-readable form.
func isGroupID(s string) bool {
	return len(s) == groupIDLen && isBase36Lower(s)
}

// isGroupIDPrefix reports whether s is a non-empty prefix of a group id.
func isGroupIDPrefix(s string) bool {
	return len(s) > 0 && len(s) <= groupIDLen && isBase36Lower(s)
}

func isBase36Lower(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') {
			continue
		}
		return false
	}
	return true
}

// sha256Hex returns the lowercase hex SHA-256 of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sha256HexBytes returns the lowercase hex SHA-256 of raw bytes.
func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// blobHashMatches reports whether `claimed` is the SHA-256 of the **decoded** bytes of `b64`.
// There is exactly one convention (client/src/group/service.rs hashes raw bytes for KP, commit
// and welcome alike), so hashing the Base64 string itself is rejected: tolerating two conventions
// could store a hash the client cannot verify, silently breaking tamper checks on the return path.
func blobHashMatches(b64, claimed string) bool {
	if claimed == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return false
	}
	return strings.EqualFold(sha256HexBytes(raw), claimed)
}

// encodeGroupName renders the stored name blob as Base64 ("" when absent).
func encodeGroupName(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, "METHOD_NOT_ALLOWED", "Method not allowed")
}

func notFoundGroupEndpoint(w http.ResponseWriter) {
	writeError(w, "NOT_FOUND", "Unknown group endpoint")
}
