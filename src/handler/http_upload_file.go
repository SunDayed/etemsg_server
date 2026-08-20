package handler

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"e2e-msg-server/config"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"
)

// HandleUploadFile handles POST /upload_file — streams the encrypted file
// body to disk and records its metadata in SQLite.
//	POST /upload_file?user_id=<sender>&file_id=<uuid4>&to=<recipient>&filename=<name>&size=<bytes>&sha256=<hex>
//	Body: raw ciphertext bytes (streamed, never buffered in memory)
// The upload happens BEFORE the sender broadcasts the file_meta over
// WebSocket, so a received meta always implies the file is ready on disk.
func HandleUploadFile(st *store.Store, fileDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		userID := utils.TrimSpace(q.Get("user_id"))
		fileID := utils.TrimSpace(q.Get("file_id"))
		owner := utils.TrimSpace(q.Get("to"))
		filename := q.Get("filename")
		sha256 := q.Get("sha256")

		// ── Parameter validation ────────────────────────────────
		if userID == "" || owner == "" || !utils.IsValidFileID(fileID) {
			writeError(w, "INVALID_PARAMS", "user_id, file_id (UUID) and to are required")
			return
		}
		size, err := strconv.ParseInt(q.Get("size"), 10, 64)
		if err != nil || size <= 0 || size > config.Cfg.MaxFileSize {
			writeError(w, "INVALID_SIZE", "size must be 1..MaxFileSize")
			return
		}
		if filename == "" || len(filename) > config.Cfg.FileNameMax {
			writeError(w, "INVALID_FILENAME", fmt.Sprintf("filename is required and must be <= %d chars", config.Cfg.FileNameMax))
			return
		}

		// ── Uploader must be a registered user ──────────────────
		ctx, cancel := bgCtx()
		defer cancel()

		exists, err := st.UserExists(ctx, userID)
		if err != nil {
			log.Printf("ERROR: upload check user: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		if !exists {
			writeError(w, "USER_NOT_FOUND", "Uploader not registered")
			return
		}

		signature := utils.TrimSpace(q.Get("signature"))
		tsStr := utils.TrimSpace(q.Get("timestamp"))
		nonce := utils.TrimSpace(q.Get("nonce"))
		if signature == "" || nonce == "" {
			writeError(w, "SIGNATURE_REQUIRED", "请求必须携带签名和 nonce（请升级客户端）")
			return
		}
		if code, msg := verifySignedRequest(
			st, userID,
			[]string{userID, fileID, owner, filename, strconv.FormatInt(size, 10), sha256},
			tsStr, nonce, signature,
		); code != "" {
			log.Printf("INFO: upload rejected (bad signature): %s -> %s", userID, owner)
			LogAccess("[UPLOAD] %s->%s rejected %s", userID, owner, code)
			writeError(w, code, msg)
			return
		}

		mutual, err := st.IsMutualContact(ctx, userID, owner)
		if err != nil {
			log.Printf("ERROR: upload mutual check: %v", err)
			writeError(w, "DB_UNAVAILABLE", "Database unavailable")
			return
		}
		if !mutual {
			log.Printf("INFO: upload rejected (not mutual): %s -> %s", userID, owner)
			LogAccess("[UPLOAD] %s->%s rejected NOT_MUTUAL", userID, owner)
			writeError(w, "NOT_MUTUAL", "对方未添加你，无法发送文件")
			return
		}

		// ── Stream body to disk (O_EXCL: never overwrite) ───────
		filePath := filepath.Join(fileDir, fileID+".enc")
		f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if os.IsExist(err) {
				writeError(w, "FILE_EXISTS", "file_id already uploaded")
				return
			}
			log.Printf("ERROR: upload create file: %v", err)
			writeError(w, "INTERNAL_ERROR", "Cannot create file")
			return
		}
		n, copyErr := io.Copy(f, io.LimitReader(r.Body, config.Cfg.MaxFileSize+1))
		f.Close()

		if copyErr != nil || n != size {
			os.Remove(filePath)
			log.Printf("ERROR: upload size mismatch got=%d want=%d", n, size)
			writeError(w, "UPLOAD_INCOMPLETE", "Uploaded bytes do not match declared size")
			return
		}

		// ── Record metadata ─────────────────────────────────────
		meta := &store.FileMeta{
			FileID:    fileID,
			Sender:    userID,
			Owner:     owner,
			Filename:  filename,
			Size:      size,
			SHA256:    sha256,
			Status:    "ready",
			CreatedAt: time.Now().Unix(),
		}
		if err := st.SaveFileMeta(ctx, meta); err != nil {
			os.Remove(filePath)
			log.Printf("ERROR: upload save meta: %v", err)
			writeError(w, "INTERNAL_ERROR", "Failed to save file metadata")
			return
		}

		log.Printf("INFO: file uploaded %s -> %s file_id=%s size=%d", userID, owner, fileID, size)
		LogAccess("[UPLOAD] user=%s to=%s file_id=%s size=%d", userID, owner, fileID, size)
		writeOK(w, types.FileUploadResponse{FileID: fileID, Size: n})
	}
}
