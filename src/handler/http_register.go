package handler

import (
	"log"
	"net/http"

	"e2e-msg-server/auth"

	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleRegister handles POST /register — creates a new user with their public key.
func HandleRegister(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.RegisterRequest
		if err := decodeBody(w, r, &req); err != nil {
			writeError(w, "INVALID_JSON", "Invalid JSON body")
			return
		}

		userID := utils.TrimSpace(req.UserID)
		publicKey := utils.TrimSpace(req.PublicKey)

		if !utils.IsValidUserID(userID) {
			writeError(w, "INVALID_USER_ID", "3-32 chars, alphanumeric + underscore")
			return
		}

		if !utils.IsPEM(publicKey) {
			writeError(w, "INVALID_PUBLIC_KEY", "Must be PEM format")
			return
		}

		if _, err := auth.ParsePublicKey(publicKey); err != nil {
			log.Printf("INFO: register rejected invalid public key for %s: %v", userID, err)
			writeError(w, "INVALID_PUBLIC_KEY", "Must be a valid PEM public key")
			return
		}

		pubID, err := utils.PublicKeyID(publicKey)
		if err != nil || pubID != userID {
			log.Printf("INFO: register rejected public key/ID mismatch: %s", userID)
			writeError(w, "PUBKEY_ID_MISMATCH", "user_id must equal public key ID (SHA512/SPKI first 10 hex)")
			return
		}

		ctx, cancel := bgCtx()
		defer cancel()

		exists, err := st.UserExists(ctx, userID)
		if err != nil {
			log.Printf("ERROR: register check exists: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		if exists {
			writeError(w, "USER_EXISTS", "User already registered")
			return
		}

		if err := st.RegisterUser(ctx, userID, publicKey); err != nil {
			log.Printf("ERROR: register persist: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to persist")
			return
		}

		log.Printf("INFO: HTTP register: %s", userID)
		writeOK(w, map[string]string{"user_id": userID})
	}
}
