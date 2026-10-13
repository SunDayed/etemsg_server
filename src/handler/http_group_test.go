package handler

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"e2e-msg-server/auth"
	"e2e-msg-server/config"
	"e2e-msg-server/session"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"

	"github.com/gorilla/websocket"
)

// groupEnv is a test environment sharing one RSA key across all test users (the server looks keys
// up by user_id, so this avoids a keygen per user); every request is signed with it.
type groupEnv struct {
	t     *testing.T
	st    *store.Store
	sm    *session.Manager
	priv  *rsa.PrivateKey
	nonce int64
}

type groupResp struct {
	Status  string          `json:"status"`
	Payload json.RawMessage `json:"payload"`
	Error   *types.APIError `json:"error"`
}

func (r groupResp) mustOK(t *testing.T) json.RawMessage {
	t.Helper()
	if r.Status != "ok" {
		t.Fatalf("expected ok, got status=%q err=%+v payload=%s", r.Status, r.Error, r.Payload)
	}
	return r.Payload
}

func (r groupResp) mustErr(t *testing.T, code string) {
	t.Helper()
	if r.Status != "error" || r.Error == nil || r.Error.Code != code {
		t.Fatalf("expected error %q, got status=%q err=%+v payload=%s", code, r.Status, r.Error, r.Payload)
	}
}

func newGroupEnv(t *testing.T, users ...string) *groupEnv {
	t.Helper()
	ensureTestConfig()
	st := newTestStore(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := pemOf(t, key)
	ctx := context.Background()
	for _, u := range users {
		if err := st.RegisterUser(ctx, u, pub); err != nil {
			t.Fatalf("register %s: %v", u, err)
		}
	}
	return &groupEnv{t: t, st: st, sm: session.NewManager(), priv: key}
}

// gidOf builds a valid 10-char lowercase base36 group id; %010x is lowercase hex, a legal subset of base36.
func gidOf(n int) string {
	return fmt.Sprintf("%010x", n)
}

// userPubKey returns the PEM public key registered for a test user.
func (e *groupEnv) userPubKey(t *testing.T, user string) string {
	t.Helper()
	pub, err := e.st.GetPublicKey(context.Background(), user)
	if err != nil {
		t.Fatalf("load pubkey for %s: %v", user, err)
	}
	return pub
}

func (e *groupEnv) sign(fields []string) (ts, nonce, sig string) {
	e.t.Helper()
	ts = strconv.FormatInt(time.Now().UnixMilli(), 10)
	// auth.nonceSeen is a package-global shared across tests: every request needs a fresh nonce or it is rejected as a replay.
	nonce = fmt.Sprintf("gnonce-%d-%d", time.Now().UnixNano(), atomic.AddInt64(&e.nonce, 1))
	digest := auth.MessageDigest(append(append([]string{}, fields...), ts, nonce)...)
	raw, err := rsa.SignPKCS1v15(rand.Reader, e.priv, crypto.SHA256, digest)
	if err != nil {
		e.t.Fatal(err)
	}
	return ts, nonce, base64.StdEncoding.EncodeToString(raw)
}

func (e *groupEnv) body(fields []string, extra map[string]any) map[string]any {
	e.t.Helper()
	ts, nonce, sig := e.sign(fields)
	tsMs, _ := strconv.ParseInt(ts, 10, 64)
	b := map[string]any{"timestamp": tsMs, "nonce": nonce, "signature": sig}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func (e *groupEnv) do(method, path string, body map[string]any) groupResp {
	e.t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	}
	rec := httptest.NewRecorder()
	HandleGroups(e.st, e.sm)(rec, r)

	var resp groupResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		e.t.Fatalf("decode %s %s: %v (body=%s)", method, path, err, rec.Body.String())
	}
	return resp
}

// doQuery exercises the GET query-parameter path of decodeGroupParams.
func (e *groupEnv) doQuery(path string, fields []string, params map[string]string) groupResp {
	e.t.Helper()
	ts, nonce, sig := e.sign(fields)
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	q.Set("timestamp", ts)
	q.Set("nonce", nonce)
	q.Set("signature", sig)
	r := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	HandleGroups(e.st, e.sm)(rec, r)

	var resp groupResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		e.t.Fatalf("decode GET %s: %v (body=%s)", path, err, rec.Body.String())
	}
	return resp
}

func (e *groupEnv) createGroup(user, gid string) groupResp {
	e.t.Helper()
	nameEnc := base64.StdEncoding.EncodeToString([]byte("name-" + gid))
	return e.do(http.MethodPost, "/groups", e.body(
		[]string{gid, nameEnc, user},
		map[string]any{"group_id": gid, "name_enc": nameEnc, "creator": user}))
}

func (e *groupEnv) groupInfo(user, gid string) groupResp {
	e.t.Helper()
	return e.do(http.MethodGet, "/groups/"+gid, e.body(
		[]string{gid, user}, map[string]any{"user_id": user}))
}

func (e *groupEnv) uploadKP(user, gid, kpID, kpB64, kpHash string) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/key-packages", e.body(
		[]string{gid, user, kpID, kpHash},
		map[string]any{"user_id": user, "kp_id": kpID, "kp_b64": kpB64, "kp_hash": kpHash}))
}

func (e *groupEnv) joinRequest(user, gid, requestID, kpID, kpHash string) groupResp {
	e.t.Helper()
	const ct, iv, tag, wk = "text-ct", "text-iv", "text-tag", "text-wk"
	return e.do(http.MethodPost, "/groups/"+gid+"/join_requests", e.body(
		[]string{gid, requestID, user, kpID, kpHash, ct, iv, tag, wk},
		map[string]any{
			"user_id": user, "request_id": requestID, "applicant": user,
			"kp_id": kpID, "kp_hash": kpHash,
			"text_ct": ct, "text_iv": iv, "text_tag": tag, "text_wrapped_key": wk,
		}))
}

func (e *groupEnv) decide(user, gid, requestID, decision string) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/join_requests/"+requestID+"/decide", e.body(
		[]string{gid, requestID, decision},
		map[string]any{"user_id": user, "decision": decision}))
}

// transfer starts a stand-alone owner hand-over (caller must be the owner).
func (e *groupEnv) transfer(user, gid, designee string) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/transfer", e.body(
		[]string{gid, user, designee},
		map[string]any{"user_id": user, "designee": designee}))
}

// transferDecide lets the designee accept or decline.
func (e *groupEnv) transferDecide(user, gid string, accept bool) groupResp {
	e.t.Helper()
	action := "decline"
	if accept {
		action = "accept"
	}
	return e.do(http.MethodPost, "/groups/"+gid+"/transfer/"+action,
		e.body([]string{gid, user}, map[string]any{"user_id": user}))
}

// leave calls POST /groups/{gid}/leave (signed fields [gid, user]); successor may be empty, but the server requires it for an owner with remaining members.
func (e *groupEnv) leave(user, gid, successor string) groupResp {
	e.t.Helper()
	body := map[string]any{"user_id": user}
	if successor != "" {
		body["successor_user_id"] = successor
	}
	return e.do(http.MethodPost, "/groups/"+gid+"/leave", e.body([]string{gid, user}, body))
}

// pendingRemovals calls GET /groups/{gid}/pending-removals (owner only).
func (e *groupEnv) pendingRemovals(user, gid string) groupResp {
	e.t.Helper()
	return e.doQuery("/groups/"+gid+"/pending-removals", []string{gid, user},
		map[string]string{"user_id": user})
}

// clearPendingRemovals calls POST /groups/{gid}/pending-removals/clear.
func (e *groupEnv) clearPendingRemovals(user, gid string) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/pending-removals/clear",
		e.body([]string{gid, user}, map[string]any{"user_id": user}))
}

// kick calls POST /groups/{gid}/kick. Signed fields are [gid, user, target].
func (e *groupEnv) kick(user, gid, target string) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/kick", e.body(
		[]string{gid, user, target},
		map[string]any{"user_id": user, "target_user": target}))
}

// blobHash is the client's real digest convention: SHA-256 over the **decoded** bytes
// (client/src/group/service.rs `sha256_hex(&raw_bytes)`). The server accepts only this one.
func blobHash(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("blobHash: decode %q: %v", b64, err)
	}
	return sha256HexBytes(raw)
}

// commit signs and posts a commit whose data_hash is computed from b64.
func (e *groupEnv) commit(user, gid string, epoch, parent int64, b64 string) groupResp {
	e.t.Helper()
	return e.commitHashed(user, gid, epoch, parent, "commit", b64, blobHash(e.t, b64))
}

// commitHashed posts a commit with an explicit data_hash (for hash-mismatch cases).
func (e *groupEnv) commitHashed(user, gid string, epoch, parent int64, kind, b64, hash string) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/commits", e.body(
		[]string{gid, strconv.FormatInt(epoch, 10), strconv.FormatInt(parent, 10), kind, hash},
		map[string]any{
			"user_id": user, "epoch": epoch, "parent_epoch": parent,
			"kind": kind, "commit_b64": b64, "data_hash": hash,
		}))
}

func (e *groupEnv) welcome(user, gid, target, b64 string, epoch int64) groupResp {
	e.t.Helper()
	h := blobHash(e.t, b64)
	return e.do(http.MethodPost, "/groups/"+gid+"/welcomes", e.body(
		[]string{gid, target, h, strconv.FormatInt(epoch, 10)},
		map[string]any{
			"user_id": user, "target_user": target, "welcome_b64": b64,
			"data_hash": h, "epoch": epoch,
		}))
}

func (e *groupEnv) sendMsg(user, gid, msgID string, epoch int64, ct string) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/messages", e.body(
		[]string{gid, msgID, strconv.FormatInt(epoch, 10), ct, "", ""},
		map[string]any{
			"user_id": user, "msg_id": msgID, "epoch": epoch,
			"ciphertext": ct, "msg_type": "", "file_id": "",
		}))
}

func (e *groupEnv) ack(user, gid string, lastSeq int64) groupResp {
	e.t.Helper()
	return e.do(http.MethodPost, "/groups/"+gid+"/messages/ack", e.body(
		[]string{gid, strconv.FormatInt(lastSeq, 10)},
		map[string]any{"user_id": user, "last_seq": lastSeq}))
}

func (e *groupEnv) listMsgs(user, gid string, sinceSeq, limit int64) groupResp {
	e.t.Helper()
	return e.do(http.MethodGet, "/groups/"+gid+"/messages", e.body(
		[]string{gid, strconv.FormatInt(sinceSeq, 10)},
		map[string]any{"user_id": user, "since_seq": sinceSeq, "limit": limit}))
}

func (e *groupEnv) listWelcomes(user, gid string) groupResp {
	e.t.Helper()
	return e.do(http.MethodGet, "/groups/"+gid+"/welcomes", e.body(
		[]string{gid, user}, map[string]any{"user_id": user}))
}

func (e *groupEnv) listCommits(user, gid string, sinceEpoch int64) groupResp {
	e.t.Helper()
	return e.do(http.MethodGet, "/groups/"+gid+"/commits", e.body(
		[]string{gid, strconv.FormatInt(sinceEpoch, 10)},
		map[string]any{"user_id": user, "since_epoch": sinceEpoch}))
}

func TestGroupSignedRequestRequired(t *testing.T) {
	env := newGroupEnv(t, "gsig-owner")
	gid := gidOf(101)
	nameEnc := base64.StdEncoding.EncodeToString([]byte("n"))
	tsMs := time.Now().UnixMilli()
	ts := strconv.FormatInt(tsMs, 10)

	// No signature at all → SIGNATURE_REQUIRED.
	env.do(http.MethodPost, "/groups", map[string]any{
		"group_id": gid, "name_enc": nameEnc, "creator": "gsig-owner",
		"timestamp": tsMs, "nonce": "sig-missing-" + ts, "signature": "",
	}).mustErr(t, "SIGNATURE_REQUIRED")

	env.do(http.MethodPost, "/groups", map[string]any{
		"group_id": gid, "name_enc": nameEnc, "creator": "gsig-owner",
		"timestamp": tsMs,
		"nonce":     fmt.Sprintf("sig-bad-%d-%d", time.Now().UnixNano(), atomic.AddInt64(&env.nonce, 1)),
		"signature": base64.StdEncoding.EncodeToString([]byte("not-a-signature")),
	}).mustErr(t, "SIGNATURE_INVALID")

	// Correctly signed for DIFFERENT fields than the body carries → rejected.
	tampered := env.body([]string{gid, nameEnc, "gsig-owner"},
		map[string]any{"group_id": gid, "name_enc": nameEnc, "creator": "gsig-owner"})
	tampered["name_enc"] = base64.StdEncoding.EncodeToString([]byte("other"))
	env.do(http.MethodPost, "/groups", tampered).mustErr(t, "SIGNATURE_INVALID")
}

func TestGroupCreateAndNonMemberRejected(t *testing.T) {
	env := newGroupEnv(t, "gcr-owner", "gcr-outsider")
	gid := gidOf(102)

	env.createGroup("gcr-owner", gid).mustOK(t)

	env.createGroup("gcr-owner", gid).mustErr(t, "DUPLICATE_GROUP_ID")

	// Non-member cannot read the group (which would leak the member list).
	env.groupInfo("gcr-outsider", gid).mustErr(t, "NOT_GROUP_MEMBER")

	payload := env.groupInfo("gcr-owner", gid).mustOK(t)
	var info types.GroupInfoResponse
	if err := json.Unmarshal(payload, &info); err != nil {
		t.Fatal(err)
	}
	if info.GroupID != gid || info.Creator != "gcr-owner" || info.State != "active" {
		t.Fatalf("unexpected group info: %+v", info)
	}
	if len(info.Members) != 1 || info.Members[0].UserID != "gcr-owner" || info.Members[0].Role != "owner" {
		t.Fatalf("unexpected members: %+v", info.Members)
	}
}

func TestGroupSearchRejectsNameSearch(t *testing.T) {
	env := newGroupEnv(t, "gsr-user")
	gid := gidOf(103)
	env.createGroup("gsr-user", gid).mustOK(t)

	// by=name must fail loudly, never silently degrade to an empty list.
	env.doQuery("/groups/search",
		[]string{"gsr-user", "name", "some name"},
		map[string]string{"user_id": "gsr-user", "by": "name", "q": "some name"},
	).mustErr(t, "UNSUPPORTED_SEARCH_BY")

	payload := env.doQuery("/groups/search",
		[]string{"gsr-user", "id", gid},
		map[string]string{"user_id": "gsr-user", "by": "id", "q": gid},
	).mustOK(t)

	var results []map[string]any
	if err := json.Unmarshal(payload, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0]["group_id"] != gid {
		t.Fatalf("unexpected search results: %s", payload)
	}
	if _, hasMembers := results[0]["members"]; hasMembers {
		t.Fatalf("search must not return a member list: %s", payload)
	}
	if results[0]["member_count"].(float64) != 1 {
		t.Fatalf("member_count = %v, want 1", results[0]["member_count"])
	}
	if ck, _ := results[0]["creator_public_key"].(string); ck == "" {
		t.Fatalf("search must return the creator public key: %s", payload)
	}
}

// The applicant must be able to verify the returned creator key really belongs to that creator id.
func TestGroupSearchReturnsVerifiableCreatorPublicKey(t *testing.T) {
	ensureTestConfig()
	st := newTestStore(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := pemOf(t, key)
	creatorID, err := utils.PublicKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RegisterUser(context.Background(), creatorID, pub); err != nil {
		t.Fatal(err)
	}
	env := &groupEnv{t: t, st: st, sm: session.NewManager(), priv: key}
	gid := gidOf(113)
	env.createGroup(creatorID, gid).mustOK(t)

	payload := env.doQuery("/groups/search",
		[]string{creatorID, "id", gid},
		map[string]string{"user_id": creatorID, "by": "id", "q": gid},
	).mustOK(t)

	var results []types.GroupSearchResult
	if err := json.Unmarshal(payload, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected search results: %s", payload)
	}
	if results[0].CreatorPublicKey == "" {
		t.Fatalf("creator_public_key missing: %s", payload)
	}
	derived, err := utils.PublicKeyID(results[0].CreatorPublicKey)
	if err != nil {
		t.Fatalf("returned creator_public_key is not a valid PEM: %v", err)
	}
	if derived != results[0].Creator {
		t.Fatalf("public_key_id(creator_public_key)=%s != creator=%s", derived, results[0].Creator)
	}
	if derived != creatorID {
		t.Fatalf("derived id %s != registered creator id %s", derived, creatorID)
	}
}

func TestGroupJoinRequestDuplicatePending(t *testing.T) {
	env := newGroupEnv(t, "gjr-owner", "gjr-applicant")
	gid := gidOf(104)
	env.createGroup("gjr-owner", gid).mustOK(t)

	kpB64 := base64.StdEncoding.EncodeToString([]byte("kp-bytes-104"))
	kpHash := blobHash(t, kpB64)
	env.uploadKP("gjr-applicant", gid, "kp-104", kpB64, kpHash).mustOK(t)

	// The digest is over the DECODED bytes (the client's convention).
	kpBytes2 := []byte("kp-bytes-104-bytehash")
	kpB64b := base64.StdEncoding.EncodeToString(kpBytes2)
	env.uploadKP("gjr-applicant", gid, "kp-104-bytehash", kpB64b, sha256HexBytes(kpBytes2)).mustOK(t)

	// Hashing the base64 string must be rejected: tolerating two conventions would store a data_hash the client cannot verify.
	env.uploadKP("gjr-applicant", gid, "kp-104-strhash", kpB64b, sha256Hex(kpB64b)).
		mustErr(t, "HASH_MISMATCH")

	env.uploadKP("gjr-applicant", gid, "kp-104-bad", kpB64, "deadbeef").mustErr(t, "HASH_MISMATCH")

	env.joinRequest("gjr-applicant", gid, "req-104-a", "kp-104", kpHash).mustOK(t)
	// Same (group, applicant) with a new request id is still one pending request.
	env.joinRequest("gjr-applicant", gid, "req-104-b", "kp-104", kpHash).mustErr(t, "DUPLICATE_JOIN_REQUEST")

	env.joinRequest("gjr-owner", gid, "req-104-c", "kp-104", kpHash).mustErr(t, "ALREADY_MEMBER")
}

func TestGroupDecideRequiresAdminAndDoesNotAddMember(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "gdec-owner", "gdec-admin", "gdec-member", "gdec-applicant")
	gid := gidOf(105)
	env.createGroup("gdec-owner", gid).mustOK(t)

	if err := env.st.AddGroupMember(ctx, gid, "gdec-admin", store.GroupRoleAdmin, 0); err != nil {
		t.Fatal(err)
	}
	if err := env.st.AddGroupMember(ctx, gid, "gdec-member", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}

	kpB64 := base64.StdEncoding.EncodeToString([]byte("kp-bytes-105"))
	kpHash := blobHash(t, kpB64)
	env.uploadKP("gdec-applicant", gid, "kp-105", kpB64, kpHash).mustOK(t)
	env.joinRequest("gdec-applicant", gid, "req-105", "kp-105", kpHash).mustOK(t)

	env.decide("gdec-member", gid, "req-105", "allow").mustErr(t, "FORBIDDEN")
	env.decide("gdec-applicant", gid, "req-105", "allow").mustErr(t, "NOT_GROUP_MEMBER")
	env.decide("gdec-owner", gid, "req-105", "maybe").mustErr(t, "INVALID_DECISION")

	// The admin may decide (owner/admin are both allowed).
	env.decide("gdec-admin", gid, "req-105", "allow").mustOK(t)

	// KEY ASSERTION: approving does not create membership; that waits for the Welcome to be stored.
	isMember, err := env.st.IsGroupMember(ctx, gid, "gdec-applicant")
	if err != nil {
		t.Fatal(err)
	}
	if isMember {
		t.Fatal("allow must not add the applicant before the MLS Commit/Welcome is stored")
	}

	env.decide("gdec-owner", gid, "req-105", "allow").mustErr(t, "REQUEST_NOT_PENDING")
}

func TestGroupCommitValidation(t *testing.T) {
	env := newGroupEnv(t, "gcm-owner", "gcm-member")
	gid := gidOf(106)
	env.createGroup("gcm-owner", gid).mustOK(t)
	if err := env.st.AddGroupMember(context.Background(), gid, "gcm-member", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}

	b1 := base64.StdEncoding.EncodeToString([]byte("commit-106-1"))

	env.commit("gcm-owner", gid, 1, 5, b1).mustErr(t, "EPOCH_MISMATCH")
	env.commit("gcm-owner", gid, 0, 0, b1).mustErr(t, "EPOCH_NOT_MONOTONIC")
	env.commit("gcm-member", gid, 1, 0, b1).mustErr(t, "FORBIDDEN")
	env.commitHashed("gcm-owner", gid, 1, 0, "commit", b1, "deadbeef").mustErr(t, "HASH_MISMATCH")

	env.commit("gcm-owner", gid, 1, 0, b1).mustOK(t)
	// Same (group, epoch) again → fork rejected.
	b2 := base64.StdEncoding.EncodeToString([]byte("commit-106-fork"))
	env.commit("gcm-owner", gid, 1, 0, b2).mustErr(t, "DUPLICATE_COMMIT_EPOCH")

	g, err := env.st.GetGroup(context.Background(), gid)
	if err != nil {
		t.Fatal(err)
	}
	if g.CurrentEpoch != 1 {
		t.Fatalf("current_epoch = %d, want 1", g.CurrentEpoch)
	}

	// Failing commits must not have mutated anything else.
	payload := env.listCommits("gcm-owner", gid, 0).mustOK(t)
	var commits []types.GroupCommitInfo
	if err := json.Unmarshal(payload, &commits); err != nil {
		t.Fatal(err)
	}
	if len(commits) != 1 || commits[0].Epoch != 1 || commits[0].DataB64 != b1 {
		t.Fatalf("unexpected commits: %s", payload)
	}
}

func TestGroupWelcomeMakesMemberEffective(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "gwel-owner", "gwel-applicant")
	gid := gidOf(107)
	env.createGroup("gwel-owner", gid).mustOK(t)

	w0 := base64.StdEncoding.EncodeToString([]byte("welcome-107-x"))
	env.welcome("gwel-applicant", gid, "gwel-applicant", w0, 1).mustErr(t, "NOT_GROUP_MEMBER")

	w := base64.StdEncoding.EncodeToString([]byte("welcome-107"))
	env.welcome("gwel-owner", gid, "gwel-applicant", w, 1).mustOK(t)

	// KEY ASSERTION: membership only exists after the Welcome is stored.
	m, err := env.st.GetGroupMember(ctx, gid, "gwel-applicant")
	if err != nil {
		t.Fatalf("applicant should be a member after the welcome: %v", err)
	}
	if m.Role != store.GroupRoleMember || m.JoinedEpoch != 1 {
		t.Fatalf("unexpected member row: %+v", m)
	}

	// GET welcomes only returns entries addressed to the caller.
	payload := env.listWelcomes("gwel-applicant", gid).mustOK(t)
	var mine []types.GroupWelcomeInfo
	if err := json.Unmarshal(payload, &mine); err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 || mine[0].TargetUser != "gwel-applicant" || mine[0].DataB64 != w {
		t.Fatalf("unexpected welcomes for applicant: %s", payload)
	}
	own := env.listWelcomes("gwel-owner", gid).mustOK(t)
	var ownerWelcomes []types.GroupWelcomeInfo
	if err := json.Unmarshal(own, &ownerWelcomes); err != nil {
		t.Fatal(err)
	}
	if len(ownerWelcomes) != 0 {
		t.Fatalf("owner must not see the applicant's welcome: %s", own)
	}
}

func TestGroupWelcomeRequiresAdminRole(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "gwel2-owner", "gwel2-admin", "gwel2-member", "gwel2-applicant")
	gid := gidOf(1070)
	env.createGroup("gwel2-owner", gid).mustOK(t)

	if err := env.st.AddGroupMember(ctx, gid, "gwel2-admin", store.GroupRoleAdmin, 0); err != nil {
		t.Fatal(err)
	}
	if err := env.st.AddGroupMember(ctx, gid, "gwel2-member", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}

	w := base64.StdEncoding.EncodeToString([]byte("welcome-role-check"))
	// Plain members must not be able to add arbitrary members.
	env.welcome("gwel2-member", gid, "gwel2-applicant", w, 1).mustErr(t, "FORBIDDEN")
	// Owner/admin remain allowed (owner is the only role currently granted by the lifecycle, admin is the explicit privileged role).
	env.welcome("gwel2-admin", gid, "gwel2-applicant", w, 1).mustOK(t)
}

func TestGroupMessagesEpochDedupAndSeq(t *testing.T) {
	env := newGroupEnv(t, "gmsg-owner")
	gid := gidOf(108)
	env.createGroup("gmsg-owner", gid).mustOK(t)

	env.sendMsg("gmsg-owner", gid, "msg-108-1", 1, "ct-1").mustErr(t, "EPOCH_MISMATCH")

	env.commit("gmsg-owner", gid, 1, 0, base64.StdEncoding.EncodeToString([]byte("c-108"))).mustOK(t)

	p1 := env.sendMsg("gmsg-owner", gid, "msg-108-1", 1, "ct-1").mustOK(t)
	var ack1 types.GroupMessageResponse
	if err := json.Unmarshal(p1, &ack1); err != nil {
		t.Fatal(err)
	}
	if ack1.Seq != 1 {
		t.Fatalf("first seq = %d, want 1", ack1.Seq)
	}

	// Replaying the same msg_id is rejected.
	env.sendMsg("gmsg-owner", gid, "msg-108-1", 1, "ct-1-replay").mustErr(t, "DUPLICATE_MSG_ID")

	p2 := env.sendMsg("gmsg-owner", gid, "msg-108-2", 1, "ct-2").mustOK(t)
	var ack2 types.GroupMessageResponse
	if err := json.Unmarshal(p2, &ack2); err != nil {
		t.Fatal(err)
	}
	if ack2.Seq != 2 {
		t.Fatalf("second seq = %d, want 2 (monotonic)", ack2.Seq)
	}

	payload := env.listMsgs("gmsg-owner", gid, 0, 0).mustOK(t)
	var page types.GroupMessagesResponse
	if err := json.Unmarshal(payload, &page); err != nil {
		t.Fatal(err)
	}
	if page.MinSeq != 0 {
		t.Fatalf("min_seq = %d, want 0", page.MinSeq)
	}
	if len(page.Messages) != 2 || page.Messages[0].Seq != 1 || page.Messages[1].Seq != 2 {
		t.Fatalf("unexpected message page: %s", payload)
	}
}

func TestGroupAckCursorIsMonotonic(t *testing.T) {
	env := newGroupEnv(t, "gack-owner")
	gid := gidOf(109)
	env.createGroup("gack-owner", gid).mustOK(t)
	env.commit("gack-owner", gid, 1, 0, base64.StdEncoding.EncodeToString([]byte("c-109"))).mustOK(t)
	env.sendMsg("gack-owner", gid, "msg-109-1", 1, "ct-1").mustOK(t)
	env.sendMsg("gack-owner", gid, "msg-109-2", 1, "ct-2").mustOK(t)

	var ack types.GroupMessageAckResponse
	if err := json.Unmarshal(env.ack("gack-owner", gid, 2).mustOK(t), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.LastSeq != 2 {
		t.Fatalf("last_seq = %d, want 2", ack.LastSeq)
	}
	// An older ack must not move the cursor backwards.
	if err := json.Unmarshal(env.ack("gack-owner", gid, 1).mustOK(t), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.LastSeq != 2 {
		t.Fatalf("cursor moved backwards: %d", ack.LastSeq)
	}
	env.ack("gack-owner", gid, 5).mustErr(t, "SEQ_OUT_OF_RANGE")
	// Ack never deletes rows.
	if max, err := env.st.MaxGroupMessageSeq(context.Background(), gid); err != nil || max != 2 {
		t.Fatalf("ack must not delete messages: max=%d err=%v", max, err)
	}
}

func TestGroupQueueReclaimMinSeq(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "grc-owner", "grc-b")
	gid := gidOf(110)
	env.createGroup("grc-owner", gid).mustOK(t)
	if err := env.st.AddGroupMember(ctx, gid, "grc-b", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 10; i++ {
		if _, err := env.st.AppendGroupMessage(ctx, &store.GroupMessage{
			GroupID: gid, Epoch: 0, Sender: "grc-owner",
			MsgID: fmt.Sprintf("rmsg-%d", i), Ciphertext: fmt.Sprintf("ct-%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Cursors: owner 5, b 3 → MIN = 3.
	if err := env.st.UpsertGroupCursor(ctx, "grc-owner", gid, 5); err != nil {
		t.Fatal(err)
	}
	if err := env.st.UpsertGroupCursor(ctx, "grc-b", gid, 3); err != nil {
		t.Fatal(err)
	}

	res, err := env.st.ReclaimGroupMessages(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedByCursor != 3 {
		t.Fatalf("deleted_by_cursor = %d, want 3 (MIN semantics)", res.DeletedByCursor)
	}
	msgs, err := env.st.ListGroupMessages(ctx, gid, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 7 || msgs[0].Seq != 4 {
		t.Fatalf("expected seq 4..10, got %d rows starting at %d", len(msgs), msgs[0].Seq)
	}
	g, err := env.st.GetGroup(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if g.MinSeq != 3 {
		t.Fatalf("min_seq = %d, want 3", g.MinSeq)
	}

	// A member without any cursor row blocks cursor-based reclaim (safe_seq = 0).
	if err := env.st.AddGroupMember(ctx, gid, "grc-c", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}
	res, err = env.st.ReclaimGroupMessages(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedByCursor != 0 {
		t.Fatalf("an un-acked member must block reclaim, deleted=%d", res.DeletedByCursor)
	}
}

func TestGroupQueueReclaimCapRaisesMinSeq(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "gcap-owner")
	gid := gidOf(111)
	env.createGroup("gcap-owner", gid).mustOK(t)

	// Bulk-insert well over the retention cap directly (fast, one transaction).
	const total = store.GroupQueueMaxMessages + 5
	tx, err := env.st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO group_messages
		   (group_id, seq, epoch, sender, msg_id, ciphertext, msg_type, file_id, timestamp, created_at)
		 VALUES (?, ?, 0, 'gcap-owner', ?, 'ct', '', '', '', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= total; i++ {
		if _, err := stmt.ExecContext(ctx, gid, i, fmt.Sprintf("capmsg-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	res, err := env.st.ReclaimGroupMessages(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedByCap != 5 {
		t.Fatalf("deleted_by_cap = %d, want 5", res.DeletedByCap)
	}
	if res.MinSeq != 5 {
		t.Fatalf("min_seq = %d, want 5", res.MinSeq)
	}

	var count int64
	if err := env.st.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM group_messages WHERE group_id = ?", gid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != store.GroupQueueMaxMessages {
		t.Fatalf("queue count = %d, want %d", count, store.GroupQueueMaxMessages)
	}

	// The listing endpoint clamps since_seq to min_seq and reports it.
	payload := env.listMsgs("gcap-owner", gid, 0, 1).mustOK(t)
	var page types.GroupMessagesResponse
	if err := json.Unmarshal(payload, &page); err != nil {
		t.Fatal(err)
	}
	if page.MinSeq != 5 {
		t.Fatalf("response min_seq = %d, want 5", page.MinSeq)
	}
	if len(page.Messages) != 1 || page.Messages[0].Seq != 6 {
		t.Fatalf("expected the page to resume at min_seq+1=6, got %s", payload)
	}
}

// TestWSGroupMessageFanout drives the WS "group_message" branch end to end: the sender gets a
// {status:ok, payload:{msg_id, seq}} ack and another online member receives group_new_message with the same seq.
func TestWSGroupMessageFanout(t *testing.T) {
	ensureTestConfig()
	config.Cfg.WSReadTimeout = 10
	config.Cfg.WSPingInterval = 60

	ctx := context.Background()
	st := newTestStore(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := pemOf(t, key)
	for _, u := range []string{"gws_owner", "gws_peer"} {
		if err := st.RegisterUser(ctx, u, pub); err != nil {
			t.Fatal(err)
		}
		if err := st.StoreToken(ctx, u, "tok-"+u, time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	gid := gidOf(112)
	if err := st.CreateGroup(ctx, &store.Group{GroupID: gid, NameEnc: []byte("n"), Creator: "gws_owner"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddGroupMember(ctx, gid, "gws_peer", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}

	sm := session.NewManager()
	wsHandler := NewWSHandler(st, sm)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsHandler.ServeWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	dial := func(user string) *websocket.Conn {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial %s: %v", user, err)
		}
		if err := conn.WriteJSON(types.WSEnvelope{
			Type:    "connect",
			Payload: map[string]string{"user_id": user, "token": "tok-" + user},
		}); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var ack types.WSEnvelope
		if err := conn.ReadJSON(&ack); err != nil {
			t.Fatalf("read connect ack %s: %v", user, err)
		}
		if ack.Type != "connect" || ack.Error != nil {
			t.Fatalf("connect %s failed: %#v err=%+v", user, ack, ack.Error)
		}
		return conn
	}

	owner := dial("gws_owner")
	defer owner.Close()
	peer := dial("gws_peer")
	defer peer.Close()

	const msgID = "gws-msg-1"
	const ct = "opaque-ciphertext"
	digest := auth.MessageDigest(gid, "0", msgID, ct, "", "", "gws_owner")
	raw, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.WriteJSON(types.WSEnvelope{
		Type: "group_message",
		Payload: types.GroupMessagePayload{
			GroupID:    gid,
			Epoch:      0,
			Ciphertext: ct,
			MsgID:      msgID,
			Signature:  base64.StdEncoding.EncodeToString(raw),
		},
	}); err != nil {
		t.Fatal(err)
	}

	owner.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ack types.WSEnvelope
	if err := owner.ReadJSON(&ack); err != nil {
		t.Fatalf("read group_message ack: %v", err)
	}
	if ack.Type != "group_message" || ack.Status != "ok" || ack.Error != nil {
		t.Fatalf("unexpected group_message ack: %#v", ack)
	}

	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var push types.WSEnvelope
	if err := peer.ReadJSON(&push); err != nil {
		t.Fatalf("peer did not receive group_new_message: %v", err)
	}
	if push.Type != "group_new_message" {
		t.Fatalf("expected group_new_message, got %#v", push)
	}
	rawPush, _ := json.Marshal(push.Payload)
	var newMsg types.GroupNewMessagePayload
	if err := json.Unmarshal(rawPush, &newMsg); err != nil {
		t.Fatal(err)
	}
	if newMsg.Sender != "gws_owner" || newMsg.MsgID != msgID || newMsg.Ciphertext != ct || newMsg.Seq != 1 {
		t.Fatalf("unexpected pushed message: %+v", newMsg)
	}
}

// TestGroupIDFormat pins the group-id shape: exactly 10 lowercase base36 chars. Owners read IDs out
// to applicants, so it must stay short and readable; it also guards that old shapes are rejected.
func TestGroupIDFormat(t *testing.T) {
	env := newGroupEnv(t, "gidfmt-owner")

	valid := []string{"a1b2c3d4e5", "0000000000", "zzzzzzzzzz", "0123456789"}
	for _, gid := range valid {
		env.createGroup("gidfmt-owner", gid).mustOK(t)
	}

	invalid := map[string]string{
		"too short":          "abc",
		"too long":           "a1b2c3d4e5f",
		"legacy 48-char hex": "0123456789abcdef0123456789abcdef0123456789abcdef",
		"uppercase":          "A1B2C3D4E5",
		"hyphen":             "a1b2c3d4e-",
		"underscore":         "a1b2c3d4e_",
		"non-ASCII":          "a1b2c3d4eé",
	}
	for name, gid := range invalid {
		t.Run(name, func(t *testing.T) {
			env.createGroup("gidfmt-owner", gid).mustErr(t, "INVALID_GROUP_ID")
		})
	}
}

// TestGroupKickMember covers the owner-only removal endpoint: it authorizes and deletes the row
// only; the MLS Remove commit is pushed by the client (a client can never remove itself — openmls CannotRemoveSelf).
func TestGroupKickMember(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "gk-owner", "gk-admin", "gk-member", "gk-out", "gk-stranger")
	gid := gidOf(130)
	env.createGroup("gk-owner", gid).mustOK(t)

	// AddGroupMember is INSERT OR IGNORE, so a repeat add never changes the role: gk-admin must be added with the admin role the first time.
	for _, u := range []string{"gk-member", "gk-out"} {
		if err := env.st.AddGroupMember(ctx, gid, u, store.GroupRoleMember, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.st.AddGroupMember(ctx, gid, "gk-admin", store.GroupRoleAdmin, 0); err != nil {
		t.Fatal(err)
	}

	env.kick("gk-member", gid, "gk-out").mustErr(t, "NOT_OWNER")
	env.kick("gk-stranger", gid, "gk-out").mustErr(t, "NOT_GROUP_MEMBER")
	// **Admins cannot kick either** — kicking is owner-only.
	env.kick("gk-admin", gid, "gk-out").mustErr(t, "NOT_OWNER")
	env.kick("gk-owner", gid, "gk-owner").mustErr(t, "INVALID_TARGET")

	env.kick("gk-owner", gid, "gk-out").mustOK(t)
	isMember, err := env.st.IsGroupMember(ctx, gid, "gk-out")
	if err != nil {
		t.Fatal(err)
	}
	if isMember {
		t.Fatal("kicked member must no longer be a member")
	}
	// Idempotent: kicking again does not error.
	env.kick("gk-owner", gid, "gk-out").mustOK(t)
	isMember, err = env.st.IsGroupMember(ctx, gid, "gk-member")
	if err != nil {
		t.Fatal(err)
	}
	if !isMember {
		t.Fatal("kicking one member must not affect others")
	}
}

// TestRemoveGroupMemberClearsCursor: a leftover ack cursor would revive on rejoin and pin the group's queue reclamation until the next ack, so it must be deleted with the membership row.
func TestRemoveGroupMemberClearsCursor(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "gcur-owner", "gcur-out")
	gid := gidOf(131)
	env.createGroup("gcur-owner", gid).mustOK(t)
	if err := env.st.AddGroupMember(ctx, gid, "gcur-out", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}
	if err := env.st.UpsertGroupCursor(ctx, "gcur-out", gid, 7); err != nil {
		t.Fatal(err)
	}
	if err := env.st.RemoveGroupMember(ctx, gid, "gcur-out"); err != nil {
		t.Fatal(err)
	}
	cur, err := env.st.GetGroupCursor(ctx, "gcur-out", gid)
	if err != nil {
		t.Fatal(err)
	}
	if cur != 0 {
		t.Fatalf("cursor row must be removed with the membership, got %d", cur)
	}
}

// TestLeaveGroupOwnerMustNameSuccessor: a leaving owner must name a successor, else nobody can commit again (no rename/kick/add or removal reconciliation).
func TestLeaveGroupOwnerMustNameSuccessor(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "lv-owner", "lv-a", "lv-b", "lv-stranger")
	gid := gidOf(140)
	env.createGroup("lv-owner", gid).mustOK(t)
	for _, u := range []string{"lv-a", "lv-b"} {
		if err := env.st.AddGroupMember(ctx, gid, u, store.GroupRoleMember, 0); err != nil {
			t.Fatal(err)
		}
	}

	env.leave("lv-owner", gid, "").mustErr(t, "SUCCESSOR_REQUIRED")
	env.leave("lv-owner", gid, "lv-stranger").mustErr(t, "INVALID_SUCCESSOR")
	env.leave("lv-owner", gid, "lv-owner").mustErr(t, "INVALID_SUCCESSOR")
	// None of the failures above may change any state.
	isMember, err := env.st.IsGroupMember(ctx, gid, "lv-owner")
	if err != nil {
		t.Fatal(err)
	}
	if !isMember {
		t.Fatal("a rejected leave must not remove the owner")
	}

	// A valid successor: the owner leaves at once but is **not promoted immediately** — the group has no owner until the designee confirms.
	env.leave("lv-owner", gid, "lv-a").mustOK(t)
	stillMember, err := env.st.IsGroupMember(ctx, gid, "lv-owner")
	if err != nil {
		t.Fatal(err)
	}
	if stillMember {
		t.Fatal("owner should have left")
	}
	m, err := env.st.GetGroupMember(ctx, gid, "lv-a")
	if err != nil {
		t.Fatal(err)
	}
	if m.Role == store.GroupRoleOwner {
		t.Fatal("successor must NOT become owner before confirming")
	}
	hasOwner, err := env.st.GroupHasOwner(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if hasOwner {
		t.Fatal("group should have no owner while the transfer is unconfirmed")
	}
	pend, err := env.st.PendingOwnerTransfer(ctx, gid)
	if err != nil {
		t.Fatalf("a pending transfer should exist: %v", err)
	}
	if pend.Designee != "lv-a" || pend.PrevOwner != "lv-owner" {
		t.Fatalf("unexpected pending transfer: %+v", pend)
	}
	if _, err := env.st.DecideOwnerTransfer(ctx, gid, "lv-a", true); err != nil {
		t.Fatalf("designee should be able to accept: %v", err)
	}
	m, err = env.st.GetGroupMember(ctx, gid, "lv-a")
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != store.GroupRoleOwner {
		t.Fatalf("successor should own the group after accepting, got role=%q", m.Role)
	}
	// The leaver is booked as a pending removal for the new owner to clear with an MLS Remove commit.
	targets, err := env.st.PendingRemovalIDs(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "lv-owner" {
		t.Fatalf("expected a pending removal for lv-owner, got %v", targets)
	}
}

// TestLeaveGroupLastMemberDissolves: an owner who is the last member cannot name a successor, so the group dissolves instead of lingering ownerless.
func TestLeaveGroupLastMemberDissolves(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "lv-solo")
	gid := gidOf(141)
	env.createGroup("lv-solo", gid).mustOK(t)

	env.leave("lv-solo", gid, "").mustOK(t)
	g, err := env.st.GetGroup(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if g.State != store.GroupStateDissolved {
		t.Fatalf("sole owner leaving should dissolve the group, got state=%q", g.State)
	}
}

// TestLeaveGroupMemberRecordsPendingRemoval: a plain member loses access immediately and leaves the owner a pending removal from the MLS tree.
func TestLeaveGroupMemberRecordsPendingRemoval(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "lv2-owner", "lv2-member")
	gid := gidOf(142)
	env.createGroup("lv2-owner", gid).mustOK(t)
	if err := env.st.AddGroupMember(ctx, gid, "lv2-member", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}
	if err := env.st.UpsertGroupCursor(ctx, "lv2-member", gid, 3); err != nil {
		t.Fatal(err)
	}

	env.leave("lv2-member", gid, "").mustOK(t)

	// Loses membership immediately (so every group endpoint and push rejects them).
	isMember, err := env.st.IsGroupMember(ctx, gid, "lv2-member")
	if err != nil {
		t.Fatal(err)
	}
	if isMember {
		t.Fatal("leaver must no longer be a member")
	}
	// The cursor is cleared with the membership row so a stale one cannot pin reclamation after rejoin.
	cur, err := env.st.GetGroupCursor(ctx, "lv2-member", gid)
	if err != nil {
		t.Fatal(err)
	}
	if cur != 0 {
		t.Fatalf("cursor must be cleared with the membership, got %d", cur)
	}
	targets, err := env.st.PendingRemovalIDs(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "lv2-member" {
		t.Fatalf("expected pending removal for lv2-member, got %v", targets)
	}

	env.pendingRemovals("lv2-member", gid).mustErr(t, "NOT_GROUP_MEMBER")
	env.pendingRemovals("lv2-owner", gid).mustOK(t)
	env.clearPendingRemovals("lv2-owner", gid).mustOK(t)
	targets, err = env.st.PendingRemovalIDs(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("pending removals should be cleared, got %v", targets)
	}
	// Idempotent: leaving again neither errors nor books a duplicate removal.
	env.leave("lv2-member", gid, "").mustOK(t)
}

// TestOwnerTransferNeedsDesigneeConsent: the owner keeps the group (and keeps approving) until the designee confirms.
func TestOwnerTransferNeedsDesigneeConsent(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "tr-owner", "tr-designee", "tr-other")
	gid := gidOf(150)
	env.createGroup("tr-owner", gid).mustOK(t)
	for _, u := range []string{"tr-designee", "tr-other"} {
		if err := env.st.AddGroupMember(ctx, gid, u, store.GroupRoleMember, 0); err != nil {
			t.Fatal(err)
		}
	}

	env.transfer("tr-designee", gid, "tr-other").mustErr(t, "NOT_OWNER")
	env.transfer("tr-owner", gid, "tr-nobody").mustErr(t, "INVALID_SUCCESSOR")

	env.transfer("tr-owner", gid, "tr-designee").mustOK(t)
	// A second transfer is rejected.
	env.transfer("tr-owner", gid, "tr-other").mustErr(t, "TRANSFER_PENDING")

	// Before confirmation tr-owner **is still** the owner.
	m, err := env.st.GetGroupMember(ctx, gid, "tr-owner")
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != store.GroupRoleOwner {
		t.Fatalf("owner must keep the group until the designee confirms, got %q", m.Role)
	}

	// Nobody else can confirm on their behalf.
	env.transferDecide("tr-other", gid, true).mustErr(t, "NOT_DESIGNEE")

	// On confirmation the role moves and there is exactly **one owner**.
	env.transferDecide("tr-designee", gid, true).mustOK(t)
	m, err = env.st.GetGroupMember(ctx, gid, "tr-designee")
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != store.GroupRoleOwner {
		t.Fatalf("designee should own the group after accepting, got %q", m.Role)
	}
	m, err = env.st.GetGroupMember(ctx, gid, "tr-owner")
	if err != nil {
		t.Fatal(err)
	}
	if m.Role == store.GroupRoleOwner {
		t.Fatal("previous owner must be demoted, not left as a second owner")
	}
}

// TestJoinBlockedWhileOwnerVacant: with the owner gone and the successor unconfirmed nobody can
// push an MLS Add, so joining must be refused with an explicit GROUP_OWNER_UPDATING, not silently queued.
func TestJoinBlockedWhileOwnerVacant(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "vac-owner", "vac-designee", "vac-applicant")
	gid := gidOf(151)
	env.createGroup("vac-owner", gid).mustOK(t)
	if err := env.st.AddGroupMember(ctx, gid, "vac-designee", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}

	kpB64 := base64.StdEncoding.EncodeToString([]byte("kp-bytes-151"))
	kpHash := blobHash(t, kpB64)
	env.uploadKP("vac-applicant", gid, "kp-151", kpB64, kpHash).mustOK(t)

	// Owner leaves with a successor: the group has no owner.
	env.leave("vac-owner", gid, "vac-designee").mustOK(t)
	env.joinRequest("vac-applicant", gid, "req-151", "kp-151", kpHash).
		mustErr(t, "GROUP_OWNER_UPDATING")

	env.transferDecide("vac-designee", gid, true).mustOK(t)
	env.joinRequest("vac-applicant", gid, "req-151", "kp-151", kpHash).mustOK(t)
}

// TestGroupSearchExposesCurrentOwner guards a real bug fix: join justifications are encrypted to the
// **approver** = current owner, not creator; before the fix a new owner after a transfer could not decrypt them.
func TestGroupSearchExposesCurrentOwner(t *testing.T) {
	ctx := context.Background()
	env := newGroupEnv(t, "so-owner", "so-next")
	gid := gidOf(160)
	env.createGroup("so-owner", gid).mustOK(t)
	if err := env.st.AddGroupMember(ctx, gid, "so-next", store.GroupRoleMember, 0); err != nil {
		t.Fatal(err)
	}

	search := func() map[string]any {
		t.Helper()
		raw := env.doQuery("/groups/search",
			[]string{"so-owner", "id", gid},
			map[string]string{"user_id": "so-owner", "by": "id", "q": gid},
		).mustOK(t)
		var hits []map[string]any
		if err := json.Unmarshal(raw, &hits); err != nil {
			t.Fatal(err)
		}
		if len(hits) != 1 {
			t.Fatalf("expected exactly one hit, got %s", raw)
		}
		return hits[0]
	}

	hit := search()
	if hit["creator"] != "so-owner" {
		t.Fatalf("creator should be unchanged, got %v", hit["creator"])
	}
	if hit["owner"] != "so-owner" {
		t.Fatalf("owner should be the creator while they own the group, got %v", hit["owner"])
	}
	if hit["owner_public_key"] == "" || hit["owner_public_key"] == nil {
		t.Fatal("owner_public_key must be present so the applicant can verify it")
	}
	// The public key must be bound to the owner id (clients verify this locally).
	if want := env.userPubKey(t, "so-owner"); hit["owner_public_key"] != want {
		t.Fatalf("owner_public_key mismatch:\n got %v\nwant %v", hit["owner_public_key"], want)
	}

	// After a confirmed transfer the owner field must follow, with the new owner's public key.
	env.transfer("so-owner", gid, "so-next").mustOK(t)
	env.transferDecide("so-next", gid, true).mustOK(t)

	hit = search()
	if hit["owner"] != "so-next" {
		t.Fatalf("owner must follow the hand-over, got %v", hit["owner"])
	}
	if hit["creator"] != "so-owner" {
		t.Fatalf("creator must NOT change on hand-over, got %v", hit["creator"])
	}
	if want := env.userPubKey(t, "so-next"); hit["owner_public_key"] != want {
		t.Fatalf("owner_public_key must be the new owner's key:\n got %v\nwant %v",
			hit["owner_public_key"], want)
	}
}
