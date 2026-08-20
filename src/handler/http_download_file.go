package handler

import (
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"e2e-msg-server/store"
	"e2e-msg-server/utils"
)

// HandleDownloadFile handles GET /download_file/{file_id} — streams the
// encrypted file back to the authorized recipient.
//	GET /download_file/{file_id}?user_id=<recipient>
//	Response: raw ciphertext bytes with Content-Length (streamed)
// Only the recipient (owner) may download. The server never decrypts.
func HandleDownloadFile(st *store.Store, fileDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileID := strings.TrimPrefix(r.URL.Path, "/download_file/")
		fileID = strings.TrimSuffix(fileID, "/")
		userID := utils.TrimSpace(r.URL.Query().Get("user_id"))

		if !utils.IsValidFileID(fileID) {
			writeError(w, "INVALID_PARAMS", "invalid file_id (UUID required)")
			return
		}
		if userID == "" {
			writeError(w, "MISSING_PAYLOAD", "user_id required")
			return
		}

		q := r.URL.Query()
		if code, msg := verifySignedRequest(
			st, userID, []string{userID, fileID},
			q.Get("timestamp"), q.Get("nonce"), q.Get("signature"),
		); code != "" {
			writeError(w, code, msg)
			return
		}

		ctx, cancel := bgCtx()
		defer cancel()

		meta, err := st.GetFileMeta(ctx, fileID)
		if err != nil {
			if errors.Is(err, store.ErrFileNotFound) {
				writeError(w, "FILE_NOT_FOUND", "File not found")
				return
			}
			log.Printf("ERROR: download get meta: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}

		// Authorization: only the recipient may download.
		if meta.Owner != userID {
			writeError(w, "FORBIDDEN", "Not the file recipient")
			return
		}

		filePath := filepath.Join(fileDir, fileID+".enc")
		f, err := os.Open(filePath)
		if err != nil {
			log.Printf("ERROR: download open file: %v", err)
			writeError(w, "FILE_NOT_FOUND", "File missing on disk")
			return
		}
		defer f.Close()

		// Stream ciphertext back (io.Copy: constant memory, 64KB chunks).
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("ERROR: download stream: %v", err)
			return
		}

		if err := os.Remove(filePath); err != nil {
			log.Printf("WARN: download cleanup file %s: %v", fileID, err)
		}
		delCtx, cancel := bgCtx()
		defer cancel()
		if err := st.DeleteFileMeta(delCtx, fileID); err != nil {
			log.Printf("WARN: download cleanup meta %s: %v", fileID, err)
		}
		LogAccess("[DOWNLOAD] user=%s file_id=%s size=%d delivered=true", userID, fileID, meta.Size)
	}
}
