package handler

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"e2e-msg-server/auth"
	"e2e-msg-server/config"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleLoginChallenge handles POST /login/challenge — generates a random challenge
// for the client to sign with their private key, proving ownership.
func HandleLoginChallenge(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.LoginChallengeRequest
		if err := decodeBody(w, r, &req); err != nil {
			writeError(w, "INVALID_JSON", "Invalid JSON body")
			return
		}

		userID := utils.TrimSpace(req.UserID)
		if len(userID) == 0 {
			writeError(w, "MISSING_PAYLOAD", "user_id required")
			return
		}

		ctx, cancel := bgCtx()
		defer cancel()

		exists, err := st.UserExists(ctx, userID)
		if err != nil {
			log.Printf("ERROR: login challenge check: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		if !exists {
			writeError(w, "USER_NOT_FOUND", "User not registered")
			return
		}

		challenge, err := auth.GenerateChallenge()
		if err != nil {
			log.Printf("ERROR: generate challenge: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to generate challenge")
			return
		}

		if err := st.StoreLoginChallenge(ctx, userID, challenge); err != nil {
			log.Printf("ERROR: store challenge: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to store challenge")
			return
		}

		log.Printf("INFO: Login challenge issued for: %s", userID)
		writeOK(w, types.LoginChallengeResponse{
			UserID:    userID,
			Challenge: challenge,
		})
	}
}

// HandleLogin handles POST /login — verifies the signed challenge and returns user info.
func HandleLogin(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.LoginVerifyRequest
		if err := decodeBody(w, r, &req); err != nil {
			writeError(w, "INVALID_JSON", "Invalid JSON body")
			return
		}

		userID := utils.TrimSpace(req.UserID)
		signature := utils.TrimSpace(req.Signature)

		if len(userID) == 0 || len(signature) == 0 {
			writeError(w, "MISSING_PAYLOAD", "user_id and signature required")
			return
		}

		ctx, cancel := bgCtx()
		defer cancel()

		// Fetch public key and contacts first so we don't consume the challenge
		// when the user does not exist or the database is unavailable.
		pubKey, contacts, err := st.GetUserInfo(ctx, userID)
		if err != nil {
			log.Printf("ERROR: login get user info: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}

		if pubKey == "" {
			writeError(w, "USER_NOT_FOUND", "User not registered")
			return
		}

		// Retrieve the stored challenge without consuming it yet.
		challenge, err := st.PeekLoginChallenge(ctx, userID)
		if err != nil {
			writeError(w, "CHALLENGE_EXPIRED", "No active challenge; request a new one via /login/challenge")
			return
		}

		// Verify signature
		if err := auth.VerifySignature(pubKey, challenge, signature); err != nil {
			log.Printf("INFO: Login signature verification failed for %s: %v", userID, err)
			writeError(w, "SIGNATURE_INVALID", "Signature verification failed — request a new challenge")
			return
		}

		log.Printf("INFO: HTTP login verified: %s", userID)

		token, err := generateToken()
		if err != nil {
			log.Printf("ERROR: generate token: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to generate session token")
			return
		}
		if err := st.StoreToken(ctx, userID, token, time.Now().Add(config.Cfg.TokenTTL()).Unix()); err != nil {
			log.Printf("ERROR: store token: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to store session token")
			return
		}

		// Consume the challenge only after the login has fully succeeded.
		if err := st.DeleteLoginChallenge(ctx, userID); err != nil {
			log.Printf("WARN: login delete challenge: %v", err)
		}

		writeOK(w, types.LoginResponse{
			UserID:    userID,
			PublicKey: pubKey,
			Contacts:  contacts,
			Token:     token,
		})
	}
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
