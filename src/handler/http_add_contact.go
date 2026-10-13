package handler

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"e2e-msg-server/session"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleAddContact handles POST /add_contact — adds a bidirectional contact relationship.
func HandleAddContact(st *store.Store, sm *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.AddContactRequest
		if err := decodeBody(w, r, &req); err != nil {
			writeError(w, "INVALID_JSON", "Invalid JSON body")
			return
		}

		userID := utils.TrimSpace(req.UserID)
		contactID := utils.TrimSpace(req.ContactUserID)

		if len(userID) == 0 || len(contactID) == 0 {
			writeError(w, "MISSING_PAYLOAD", "user_id and contact_user_id required")
			return
		}

		if userID == contactID {
			writeError(w, "SELF_CONTACT", "Cannot add yourself")
			return
		}

		if code, msg := verifySignedRequest(
			st, userID, []string{userID, contactID},
			strconv.FormatInt(req.Timestamp, 10), req.Nonce, req.Signature,
		); code != "" {
			writeError(w, code, msg)
			return
		}

		ctx, cancel := bgCtx()
		defer cancel()

		exists, err := st.ContactExists(ctx, contactID)
		if err != nil {
			log.Printf("ERROR: add_contact check: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		if !exists {
			writeError(w, "USER_NOT_FOUND", "Contact not registered")
			return
		}

		pubKey, err := st.GetPublicKey(ctx, contactID)
		if err != nil {
			log.Printf("ERROR: add_contact get pubkey: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to get contact public key")
			return
		}
		pubID, err := utils.PublicKeyID(pubKey)
		if err != nil || pubID != strings.ToLower(contactID) {
			log.Printf("INFO: add_contact rejected public key/ID mismatch: %s", contactID)
			writeError(w, "CONTACT_ID_MISMATCH", "Public key does not match the ID; a man-in-the-middle is possible")
			return
		}

		if _, err := st.AddContact(ctx, userID, contactID); err != nil {
			log.Printf("ERROR: add_contact persist: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to process")
			return
		}

		// A one-way add gives the other side no signal, and messaging needs a mutual relationship, so
		// push a `contact_notify` telling them "someone added you" and letting them add back from the
		// notification centre. Best-effort: POST /contacts/pending_incoming covers an offline peer.
		if sm != nil {
			sm.EnqueueMessage(contactID, &types.WSEnvelope{
				Type: "contact_notify",
				Payload: types.ContactNotifyPayload{
					From:   userID,
					Reason: "friend_request",
				},
			})
		}
		log.Printf("INFO: HTTP add_contact: %s <-> %s", userID, contactID)
		writeOK(w, types.AddContactResponse{
			ContactUserID: contactID,
			PublicKey:     pubKey,
		})
	}
}
