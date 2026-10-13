package handler

import (
	"errors"
	"fmt"
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

// HandleDownloadFile handles GET /download_file/{file_id} — streams the ciphertext back to the authorized recipient.
//	GET /download_file/{file_id}?user_id=<recipient>
//	Optional Range: bytes=<start>- (206 + Content-Range on a hit); the response is raw ciphertext + Content-Length.
// Only the recipient (owner) may download and the server never decrypts. File and metadata are deleted
// **only after the response body is fully written**, so an interrupted transfer keeps them for resume.
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

		start := int64(0)
		if rh := r.Header.Get("Range"); rh != "" {
			s, ok := parseRangeStart(rh, meta.Size)
			if !ok {
				w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(meta.Size, 10))
				http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			start = s
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Accept-Ranges", "bytes")
		if start > 0 {
			if _, err := f.Seek(start, io.SeekStart); err != nil {
				log.Printf("ERROR: download seek %s: %v", fileID, err)
				writeError(w, "INTERNAL_ERROR", "Cannot seek file")
				return
			}
			remain := meta.Size - start
			w.Header().Set("Content-Range",
				fmt.Sprintf("bytes %d-%d/%d", start, meta.Size-1, meta.Size))
			w.Header().Set("Content-Length", strconv.FormatInt(remain, 10))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
			w.WriteHeader(http.StatusOK)
		}

		written, copyErr := io.Copy(w, f)
		if copyErr != nil || start+written != meta.Size {
			// Not fully delivered: **keep the ciphertext and metadata** so the client can resume with a Range.
			log.Printf("WARN: download interrupted file_id=%s sent=%d/%d err=%v",
				fileID, start+written, meta.Size, copyErr)
			LogAccess("[DOWNLOAD] user=%s file_id=%s sent=%d/%d delivered=false",
				userID, fileID, start+written, meta.Size)
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

// parseRangeStart parses `Range: bytes=<start>-`, supporting only the single open-ended form (all the
// client needs for resume); ok=false means the Range cannot be satisfied and the caller should return 416.
func parseRangeStart(header string, size int64) (int64, bool) {
	h := strings.TrimSpace(header)
	const p = "bytes="
	if !strings.HasPrefix(h, p) {
		return 0, false
	}
	h = strings.TrimPrefix(h, p)
	if strings.Contains(h, ",") {
		return 0, false // multi-range requests are not supported
	}
	dash := strings.IndexByte(h, '-')
	if dash < 0 {
		return 0, false
	}
	startStr := strings.TrimSpace(h[:dash])
	if startStr == "" {
		return 0, false // "bytes=-N" (trailing N bytes) is not supported
	}
	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, false
	}
	return start, true
}
