package handler

import (
	"context"
	"errors"
	"log"
	"time"

	"e2e-msg-server/store"
)

// groupCleanupBatchSize bounds how many groups one reclaim tick touches. The store has a single
// SQLite connection, so processing every group in one pass could hold the connection for a long
// time as the number of groups grows; paging keeps each tick bounded.
const groupCleanupBatchSize = 100

// StartGroupQueueCleanup launches a background goroutine that periodically reclaims group message queues
// (same shape as StartFileCleanup); the rules live in store.ReclaimGroupMessages and raise groups.min_seq
// atomically with the deletes (members without a cursor count as 0 and block reclamation).
func StartGroupQueueCleanup(st *store.Store, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()

		// Pages are ordered by group_id. The offset advances between ticks, so a deployment with
		// thousands of groups cannot monopolise the single SQLite writer in one cleanup pass.
		offset := 0
		for range t.C {
			next, err := cleanGroupQueuePage(st, offset, groupCleanupBatchSize)
			if err != nil {
				log.Printf("WARN: group cleanup page offset=%d: %v", offset, err)
				offset = 0
				continue
			}
			if next < groupCleanupBatchSize {
				offset = 0 // reached the end (or an empty/short page): start from the beginning next tick
			} else {
				offset += next
			}
		}
	}()
	log.Printf("INFO: group queue cleanup started (every %s, batch=%d)", interval, groupCleanupBatchSize)
}

// cleanGroupQueuePage reclaims one bounded page and returns the number of groups processed.
func cleanGroupQueuePage(st *store.Store, offset, limit int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids, err := st.ListActiveGroupIDsPage(ctx, limit, offset)
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		res, err := st.ReclaimGroupMessages(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrGroupNotFound) {
				continue
			}
			log.Printf("WARN: group cleanup reclaim %s: %v", id, err)
			continue
		}
		if res.DeletedByCursor > 0 || res.DeletedByCap > 0 {
			log.Printf("INFO: group cleanup %s deleted_by_cursor=%d deleted_by_cap=%d min_seq=%d",
				id, res.DeletedByCursor, res.DeletedByCap, res.MinSeq)
		}
	}
	return len(ids), nil
}
