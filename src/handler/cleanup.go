package handler

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"e2e-msg-server/config"
	"e2e-msg-server/store"
)

// StartFileCleanup launches a background goroutine that periodically removes
// expired encrypted files from disk and their metadata rows from SQLite.
// Expiry is judged by the metadata row's created_at vs config.Cfg.FileTTL()
// (file mtime is not reliable after a machine restart).
func StartFileCleanup(st *store.Store, fileDir string) {
	go func() {
		for {
			time.Sleep(time.Hour)
			cleanExpiredFiles(st, fileDir)
		}
	}()
}

func cleanExpiredFiles(st *store.Store, fileDir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	before := time.Now().Add(-config.Cfg.FileTTL()).Unix()
	ids, err := st.ListExpiredFileIDs(ctx, before)
	if err != nil {
		log.Printf("WARN: cleanup list expired files: %v", err)
		return
	}

	for _, id := range ids {
		// Remove the disk ciphertext first (best effort), then the metadata row.
		path := filepath.Join(fileDir, id+".enc")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("WARN: cleanup remove file %s: %v", id, err)
		}
		if err := st.DeleteFileMeta(ctx, id); err != nil {
			log.Printf("WARN: cleanup delete meta %s: %v", id, err)
		}
		log.Printf("INFO: cleanup expired file %s", id)
	}

	// Also sweep orphaned .enc files that have no metadata row
	// (e.g. a crash between disk write and metadata save).
	entries, err := os.ReadDir(fileDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".enc")
		if _, err := st.GetFileMeta(ctx, id); err == store.ErrFileNotFound {
			os.Remove(filepath.Join(fileDir, e.Name()))
			log.Printf("INFO: cleanup orphan file %s", id)
		}
	}
}
