package handler

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleAddContact handles POST /add_contact — adds a bidirectional contact relationship.
func HandleAddContact(st *store.Store) http.HandlerFunc {
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
			writeError(w, "CONTACT_ID_MISMATCH", "公钥与ID不匹配，可能存在中间人")
			return
		}

		if _, err := st.AddContact(ctx, userID, contactID); err != nil {
			log.Printf("ERROR: add_contact persist: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to process")
			return
		}

		log.Printf("INFO: HTTP add_contact: %s <-> %s", userID, contactID)
		writeOK(w, types.AddContactResponse{
			ContactUserID: contactID,
			PublicKey:     pubKey,
		})
	}
}
