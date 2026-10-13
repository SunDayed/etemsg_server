package handler

import (
	"log"
	"net/http"
	"strconv"

	"e2e-msg-server/session"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleContactsOnline handles POST /contacts/online — returns which of the caller's contacts are online.
//	POST /contacts/online {user_id, contacts:[id...], timestamp, nonce, signature} → {status:"ok", payload:{online:[id...]}}
// The signature covers [user_id] + contacts + timestamp + nonce (same as /get_offline_msg). The server
// answers only for ids the caller explicitly added, so it cannot be used to probe arbitrary ids.
func HandleContactsOnline(st *store.Store, sm *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.ContactsOnlineRequest
		if err := decodeBody(w, r, &req); err != nil {
			writeError(w, "INVALID_JSON", "Invalid JSON body")
			return
		}

		userID := utils.TrimSpace(req.UserID)
		if userID == "" {
			writeError(w, "MISSING_PAYLOAD", "user_id required")
			return
		}
		// Cap prevents one request from being used for bulk probing.
		const maxContacts = 2000
		if len(req.Contacts) > maxContacts {
			writeError(w, "TOO_MANY_CONTACTS",
				"too many contacts in one request (max "+strconv.Itoa(maxContacts)+")")
			return
		}

		// The signed field order must match the client's: [user_id] + contacts + ts + nonce.
		fields := append([]string{userID}, req.Contacts...)
		if code, msg := verifySignedRequest(
			st, userID, fields,
			strconv.FormatInt(req.Timestamp, 10), req.Nonce, req.Signature,
		); code != "" {
			writeError(w, code, msg)
			return
		}

		ctx, cancel := bgCtx()
		defer cancel()

		// Answer only for ids that really added me (and are registered); ignore the rest to prevent probing.
		allowed, err := st.GetContacts(ctx, userID)
		if err != nil {
			log.Printf("ERROR: contacts/online get contacts: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		allowedSet := make(map[string]bool, len(allowed))
		for _, c := range allowed {
			allowedSet[c] = true
		}

		candidates := make([]string, 0, len(req.Contacts))
		for _, c := range req.Contacts {
			if allowedSet[c] {
				candidates = append(candidates, c)
			}
		}

		// Same condition as "can they message": presence is shared only between **mutual** contacts, so
		// one-way adds never count — consistent with the periodic snapshot (see filterMutualContacts).
		candidates = filterMutualContacts(ctx, st, userID, candidates)

		onlineSet := sm.OnlineIDs(candidates)
		online := make([]string, 0, len(onlineSet))
		for _, c := range candidates {
			if onlineSet[c] {
				online = append(online, c)
			}
		}

		LogAccess("[PRESENCE] query user=%s asked=%d allowed=%d online=%d",
			userID, len(req.Contacts), len(candidates), len(online))
		writeOK(w, types.ContactsOnlineResponse{Online: online})
	}
}
