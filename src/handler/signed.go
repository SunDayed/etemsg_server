package handler

import (
	"errors"
	"log"

	"e2e-msg-server/auth"
	"e2e-msg-server/store"
)

func verifySignedRequest(st *store.Store, userID string, fields []string,
	timestamp, nonce, signature string) (string, string) {

	if signature == "" {
		return "SIGNATURE_REQUIRED", "请求必须携带签名（请升级客户端）"
	}

	ctx, cancel := bgCtx()
	defer cancel()

	pubKey, err := st.GetPublicKey(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return "USER_NOT_FOUND", "User not registered"
		}
		log.Printf("ERROR: signed request get pubkey: %v", err)
		return "INTERNAL_ERROR", "Failed to verify signature"
	}
	if err := auth.VerifySignedRequest(pubKey, fields, timestamp, nonce, signature); err != nil {
		log.Printf("INFO: signed request rejected: %s: %v", userID, err)
		return "SIGNATURE_INVALID", "请求签名无效或已过期"
	}
	if auth.CheckNonce(userID, nonce) {
		log.Printf("INFO: signed request rejected (nonce replay): %s", userID)
		return "DUPLICATE_REQUEST", "重复请求（nonce 已使用）"
	}
	return "", ""
}
