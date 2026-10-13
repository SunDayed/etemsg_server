package types

// All MLS objects (KeyPackage / Commit / Welcome) are opaque Base64: the server never parses them or touches group keys.

// GroupCreateRequest is the JSON body for POST /groups.
type GroupCreateRequest struct {
	GroupID   string `json:"group_id"`
	NameEnc   string `json:"name_enc"` // Base64 of the encrypted group name
	Creator   string `json:"creator"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupCreateResponse is returned after a group is created.
type GroupCreateResponse struct {
	GroupID string `json:"group_id"`
}

// GroupListRequest is the JSON body for GET /groups.
type GroupListRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupSummary describes one group the caller belongs to.
type GroupSummary struct {
	GroupID      string `json:"group_id"`
	NameEnc      string `json:"name_enc"`
	MyRole       string `json:"my_role"`
	CurrentEpoch int64  `json:"current_epoch"`
	MinSeq       int64  `json:"min_seq"`
}

// GroupInfoRequest is the parameter set for GET /groups/{gid}.
type GroupInfoRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupMemberInfo is one entry of a group's member list. JoinedEpoch is when the member was Add-ed and the earliest epoch it can decrypt; earlier-epoch messages are rejected.
type GroupMemberInfo struct {
	UserID      string `json:"user_id"`
	Role        string `json:"role"`
	JoinedEpoch int64  `json:"joined_epoch"`
}

// GroupInfoResponse is returned by GET /groups/{gid}.
type GroupInfoResponse struct {
	GroupID      string            `json:"group_id"`
	NameEnc      string            `json:"name_enc"`
	Creator      string            `json:"creator"`
	CurrentEpoch int64             `json:"current_epoch"`
	State        string            `json:"state"`
	MinSeq       int64             `json:"min_seq"`
	Members      []GroupMemberInfo `json:"members"`
}

// GroupSearchRequest is the parameter set for GET /groups/search.
type GroupSearchRequest struct {
	UserID    string `json:"user_id"`
	By        string `json:"by"`
	Q         string `json:"q"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupSearchResult is returned by GET /groups/search; it omits the member list (anti-enumeration) and carries CreatorPublicKey so applicants can bind the creator key before encrypting.
type GroupSearchResult struct {
	GroupID          string `json:"group_id"`
	NameEnc          string `json:"name_enc"`
	Creator          string `json:"creator"`
	CreatorPublicKey string `json:"creator_public_key"`
	// Owner/OwnerPublicKey are the current owner — the one who can approve joins. After a transfer owner != creator, so justifications must use owner_public_key.
	Owner          string `json:"owner"`
	OwnerPublicKey string `json:"owner_public_key"`
	MemberCount    int64  `json:"member_count"`
	CreatedAt      int64  `json:"created_at"`
}

// GroupKeyPackageUploadRequest is the JSON body for POST /groups/{gid}/key-packages.
type GroupKeyPackageUploadRequest struct {
	UserID    string `json:"user_id"`
	KPID      string `json:"kp_id"`
	KPB64     string `json:"kp_b64"`
	KPHash    string `json:"kp_hash"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupKeyPackageGetRequest is the parameter set for GET /groups/{gid}/key-packages.
type GroupKeyPackageGetRequest struct {
	UserID    string `json:"user_id"`
	KPID      string `json:"kp_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupKeyPackageResponse returns one opaque KeyPackage.
type GroupKeyPackageResponse struct {
	KPID      string `json:"kp_id"`
	UserID    string `json:"user_id"`
	GroupID   string `json:"group_id"`
	KPB64     string `json:"kp_b64"`
	KPHash    string `json:"kp_hash"`
	CreatedAt int64  `json:"created_at"`
}

// GroupJoinRequestCreate is the JSON body for POST /groups/{gid}/join_requests; text_* is the applicant's encrypted self-introduction.
type GroupJoinRequestCreate struct {
	UserID         string `json:"user_id"`
	RequestID      string `json:"request_id"`
	Applicant      string `json:"applicant"`
	KPID           string `json:"kp_id"`
	KPHash         string `json:"kp_hash"`
	TextCT         string `json:"text_ct"`
	TextIV         string `json:"text_iv"`
	TextTag        string `json:"text_tag"`
	TextWrappedKey string `json:"text_wrapped_key"`
	Timestamp      int64  `json:"timestamp,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	Signature      string `json:"signature,omitempty"`
}

// GroupJoinRequestListRequest is the parameter set for GET /groups/{gid}/join_requests.
type GroupJoinRequestListRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupJoinRequestInfo is one pending join request.
type GroupJoinRequestInfo struct {
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
	CreatedAt      int64  `json:"created_at"`
}

// GroupJoinDecisionRequest is the JSON body for POST /groups/{gid}/join_requests/{rid}/decide.
type GroupJoinDecisionRequest struct {
	UserID    string `json:"user_id"`
	Decision  string `json:"decision"` // "allow" | "deny"
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupJoinDecisionResponse reports the resulting status.
type GroupJoinDecisionResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// GroupCommitRequest is the JSON body for POST /groups/{gid}/commits.
type GroupCommitRequest struct {
	UserID      string `json:"user_id"`
	Epoch       int64  `json:"epoch"`
	ParentEpoch int64  `json:"parent_epoch"`
	Kind        string `json:"kind"`
	CommitB64   string `json:"commit_b64"`
	DataHash    string `json:"data_hash"`
	Timestamp   int64  `json:"timestamp,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

// GroupCommitResponse is returned after a Commit is stored.
type GroupCommitResponse struct {
	GroupID string `json:"group_id"`
	Epoch   int64  `json:"epoch"`
	Seq     int64  `json:"seq"`
}

// GroupMLSLogListRequest is the parameter set for GET /groups/{gid}/commits.
type GroupMLSLogListRequest struct {
	UserID     string `json:"user_id"`
	SinceEpoch int64  `json:"since_epoch"`
	Timestamp  int64  `json:"timestamp,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Signature  string `json:"signature,omitempty"`
}

// GroupCommitInfo is one Commit entry; Seq/Target follow the generic MLS log record shape clients read.
type GroupCommitInfo struct {
	Seq      int64  `json:"seq"`
	Epoch    int64  `json:"epoch"`
	Kind     string `json:"kind"`
	Sender   string `json:"sender"`
	Target   string `json:"target"`
	DataB64  string `json:"data_b64"`
	DataHash string `json:"data_hash"`
}

// GroupWelcomeCreateRequest is the JSON body for POST /groups/{gid}/welcomes.
type GroupWelcomeCreateRequest struct {
	UserID     string `json:"user_id"`
	TargetUser string `json:"target_user"`
	WelcomeB64 string `json:"welcome_b64"`
	DataHash   string `json:"data_hash"`
	Epoch      int64  `json:"epoch"`
	Timestamp  int64  `json:"timestamp,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Signature  string `json:"signature,omitempty"`
}

// GroupWelcomeResponse is returned after a Welcome is stored.
type GroupWelcomeResponse struct {
	GroupID    string `json:"group_id"`
	TargetUser string `json:"target_user"`
	Epoch      int64  `json:"epoch"`
	Seq        int64  `json:"seq"`
}

// GroupWelcomeListRequest is the parameter set for GET /groups/{gid}/welcomes.
type GroupWelcomeListRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupWelcomeInfo is one Welcome addressed to the caller; Target and TargetUser hold the same value, following the generic MLS log shape.
type GroupWelcomeInfo struct {
	Seq        int64  `json:"seq"`
	Epoch      int64  `json:"epoch"`
	Kind       string `json:"kind"`
	Sender     string `json:"sender"`
	Target     string `json:"target"`
	TargetUser string `json:"target_user"`
	DataB64    string `json:"data_b64"`
	DataHash   string `json:"data_hash"`
}

// GroupMessageSendRequest is the JSON body for POST /groups/{gid}/messages.
type GroupMessageSendRequest struct {
	UserID     string `json:"user_id"`
	MsgID      string `json:"msg_id"`
	Epoch      int64  `json:"epoch"`
	Ciphertext string `json:"ciphertext"`
	MsgType    string `json:"msg_type"`
	FileID     string `json:"file_id"`
	Timestamp  int64  `json:"timestamp,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Signature  string `json:"signature,omitempty"`
}

// GroupMessageResponse acknowledges a stored group message.
type GroupMessageResponse struct {
	MsgID string `json:"msg_id"`
	Seq   int64  `json:"seq"`
}

// GroupMessageListRequest is the parameter set for GET /groups/{gid}/messages.
type GroupMessageListRequest struct {
	UserID    string `json:"user_id"`
	SinceSeq  int64  `json:"since_seq"`
	Limit     int64  `json:"limit"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupMessageInfo is one queued group message.
type GroupMessageInfo struct {
	Seq        int64  `json:"seq"`
	Epoch      int64  `json:"epoch"`
	Sender     string `json:"sender"`
	MsgID      string `json:"msg_id"`
	Ciphertext string `json:"ciphertext"`
	MsgType    string `json:"msg_type,omitempty"`
	FileID     string `json:"file_id,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
	CreatedAt  int64  `json:"created_at"`
}

// GroupMessagesResponse is returned by GET /groups/{gid}/messages. MinSeq is the queue floor: clients below it lost rows, must jump to MinSeq+1 and report the truncation.
type GroupMessagesResponse struct {
	Messages []GroupMessageInfo `json:"messages"`
	MinSeq   int64              `json:"min_seq"`
	// MyRole rides along so a successor promoted while offline learns of it before pushing a Remove.
	MyRole string `json:"my_role,omitempty"`
}

// GroupMessageAckRequest is the JSON body for POST /groups/{gid}/messages/ack.
type GroupMessageAckRequest struct {
	UserID    string `json:"user_id"`
	LastSeq   int64  `json:"last_seq"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupMessageAckResponse reports the (monotonic) cursor after an ack.
type GroupMessageAckResponse struct {
	LastSeq int64 `json:"last_seq"`
}

// GroupKickMemberRequest is the body of POST /groups/{gid}/kick; the caller must be owner/admin and the signature covers [group_id, user_id, target_user].
type GroupKickMemberRequest struct {
	UserID     string `json:"user_id"`
	TargetUser string `json:"target_user"`
	Timestamp  int64  `json:"timestamp,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Signature  string `json:"signature,omitempty"`
}

// GroupLeaveRequest is the JSON body for POST /groups/{gid}/leave. An owner leaving with members
// remaining must pass SuccessorUserID or nobody can commit; the last member needs none — the group dissolves.
type GroupLeaveRequest struct {
	UserID          string `json:"user_id"`
	SuccessorUserID string `json:"successor_user_id,omitempty"`
	Timestamp       int64  `json:"timestamp,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
	Signature       string `json:"signature,omitempty"`
}

// GroupDissolveRequest is the JSON body for DELETE /groups/{gid}.
type GroupDissolveRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}


// GroupMessagePayload is the C→S "group_message" payload; the signature covers group_id, epoch, msg_id, ciphertext, msg_type, file_id and the connection's `from`.
type GroupMessagePayload struct {
	GroupID    string `json:"group_id"`
	Epoch      int64  `json:"epoch"`
	Ciphertext string `json:"ciphertext"`
	MsgID      string `json:"msg_id"`
	MsgType    string `json:"msg_type,omitempty"`
	FileID     string `json:"file_id,omitempty"`
	Signature  string `json:"signature"`
}

// GroupNewMessagePayload is pushed to the other online group members.
type GroupNewMessagePayload struct {
	GroupID    string `json:"group_id"`
	Seq        int64  `json:"seq"`
	Epoch      int64  `json:"epoch"`
	Sender     string `json:"sender"`
	MsgID      string `json:"msg_id"`
	Ciphertext string `json:"ciphertext"`
	MsgType    string `json:"msg_type,omitempty"`
	FileID     string `json:"file_id,omitempty"`
}

// GroupNotifyPayload is an S→C hint that a group has new data to pull; best-effort, REST pulls are authoritative.
type GroupNotifyPayload struct {
	GroupID string `json:"group_id"`
	Reason  string `json:"reason"`
}

// GroupPendingRemovalsResponse is the payload of GET /groups/{gid}/pending-removals: these users already lost access; the missing step is the MLS Remove commit that ejects them and rotates keys.
type GroupPendingRemovalsResponse struct {
	GroupID string   `json:"group_id"`
	Targets []string `json:"targets"`
}

// GroupPendingRemovalsClearRequest is the body of POST /groups/{gid}/pending-removals/clear.
type GroupPendingRemovalsClearRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupTransferRequest is the JSON body for POST /groups/{gid}/transfer; the caller must be the current owner, and the role moves only once the designee confirms.
type GroupTransferRequest struct {
	UserID    string `json:"user_id"`
	Designee  string `json:"designee"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupTransferDecideRequest is the body of POST /groups/{gid}/transfer/{accept|decline}; only the designee may call it.
type GroupTransferDecideRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// GroupOwnerTransferInfo is the pending-transfer view from GET /groups/{gid}/transfer (owner and designee only).
type GroupOwnerTransferInfo struct {
	GroupID   string `json:"group_id"`
	PrevOwner string `json:"prev_owner"`
	Designee  string `json:"designee"`
	State     string `json:"state"`
	CreatedAt int64  `json:"created_at"`
}
