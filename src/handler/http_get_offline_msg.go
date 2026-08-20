package handler

import (
	"log"
	"net/http"
	"strconv"

	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleGetOfflineMsg handles POST /get_offline_msg — fetches and clears offline messages.
func HandleGetOfflineMsg(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.GetOfflineMsgRequest
		if err := decodeBody(w, r, &req); err != nil {
			writeError(w, "INVALID_JSON", "Invalid JSON body")
			return
		}

		userID := utils.TrimSpace(req.UserID)
		if len(userID) == 0 {
			writeError(w, "MISSING_PAYLOAD", "user_id required")
			return
		}

		if code, msg := verifySignedRequest(
			st, userID, []string{userID},
			strconv.FormatInt(req.Timestamp, 10), req.Nonce, req.Signature,
		); code != "" {
			writeError(w, code, msg)
			return
		}

		ctx, cancel := bgCtx()
		defer cancel()

		msgs, err := st.FetchAndClearOfflineMsgs(ctx, userID)
		if err != nil {
			log.Printf("ERROR: get_offline_msg: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to fetch messages")
			return
		}

		// Ensure empty array instead of null in JSON
		if msgs == nil {
			msgs = []types.OfflineMessage{}
		}

		log.Printf("INFO: HTTP get_offline_msg: %s count=%d", userID, len(msgs))
		writeOK(w, types.GetOfflineMsgResponse{Messages: msgs})
	}
}
