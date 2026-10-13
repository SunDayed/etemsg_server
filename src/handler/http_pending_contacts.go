package handler

import (
	"log"
	"net/http"
	"strconv"

	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandlePendingContacts handles POST /contacts/pending_incoming — users who added me but whom I have
// not added back. Adding is one-sided (the other side gets no signal) while messaging needs a mutual
// relationship, so the notification centre shows this as its "friend requests" list.
func HandlePendingContacts(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.PendingContactsRequest
		if err := decodeBody(w, r, &req); err != nil {
			writeError(w, "INVALID_JSON", "Invalid JSON body")
			return
		}
		userID := utils.TrimSpace(req.UserID)
		if userID == "" {
			writeError(w, "MISSING_PAYLOAD", "user_id required")
			return
		}
		if code, msg := verifySignedRequest(st, userID, []string{userID},
			strconv.FormatInt(req.Timestamp, 10), req.Nonce, req.Signature); code != "" {
			writeError(w, code, msg)
			return
		}
		ctx, cancel := bgCtx()
		defer cancel()

		ids, err := st.PendingIncomingContacts(ctx, userID)
		if err != nil {
			log.Printf("ERROR: pending contacts %s: %v", userID, err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		out := make([]types.PendingContactInfo, 0, len(ids))
		for _, id := range ids {
			out = append(out, types.PendingContactInfo{UserID: id})
		}
		writeOK(w, out)
	}
}
