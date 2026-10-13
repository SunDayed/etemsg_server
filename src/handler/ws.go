package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"e2e-msg-server/auth"
	"e2e-msg-server/config"
	"e2e-msg-server/session"
	"e2e-msg-server/store"
	"e2e-msg-server/types"
	"e2e-msg-server/utils"

	"github.com/gorilla/websocket"
)

func checkSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients (CLI/mobile) usually omit Origin.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     checkSameOrigin,
}

// wsClient wraps a WebSocket connection and serializes all writes with a mutex; gorilla/websocket
// allows only one concurrent writer per connection, so acks/errors from the read loop cannot race the
// writer goroutine's new_message/ping frames.
type wsClient struct {
	conn      *websocket.Conn
	closeOnce sync.Once
	writeMu   sync.Mutex
}

func (c *wsClient) WriteJSON(v interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(config.Cfg.WSWriteTimeoutD()))
	return c.conn.WriteJSON(v)
}

func (c *wsClient) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(config.Cfg.WSWriteTimeoutD()))
	return c.conn.WriteMessage(messageType, data)
}

func (c *wsClient) RemoteAddr() string {
	return c.conn.RemoteAddr().String()
}

// Close sends a WebSocket close frame and closes the underlying connection; safe to call from several goroutines.
func (c *wsClient) Close() {
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutting down"))
		c.conn.Close()
	})
}

// WSHandler manages WebSocket connections and message dispatch.
type WSHandler struct {
	store   *store.Store
	session *session.Manager
	connMu  sync.Mutex
	conns   map[*wsClient]struct{}

	replayMu sync.Mutex
	replay   map[string]map[string]time.Time
}

const replayWindow = 5 * time.Minute

const replayMax = 1000

const replayMaxPerUser = 1000

// NewWSHandler creates a new WebSocket handler.
func NewWSHandler(st *store.Store, sm *session.Manager) *WSHandler {
	return &WSHandler{store: st, session: sm, replay: map[string]map[string]time.Time{}, conns: map[*wsClient]struct{}{}}
}

func (h *WSHandler) isReplay(senderID, msgID string) bool {
	h.replayMu.Lock()
	defer h.replayMu.Unlock()

	now := time.Now()
	if len(h.replay) >= replayMax {
		for s, msgs := range h.replay {
			for id, t := range msgs {
				if now.Sub(t) > replayWindow {
					delete(msgs, id)
				}
			}
			if len(msgs) == 0 {
				delete(h.replay, s)
			}
		}
	}

	msgs, ok := h.replay[senderID]
	if !ok {
		msgs = map[string]time.Time{}
		h.replay[senderID] = msgs
	}

	if len(msgs) >= replayMaxPerUser {
		for id, t := range msgs {
			if now.Sub(t) > replayWindow {
				delete(msgs, id)
			}
		}
	}
	if len(msgs) >= replayMaxPerUser {
		for id := range msgs {
			delete(msgs, id)
			break
		}
	}

	if _, dup := msgs[msgID]; dup {
		return true
	}
	msgs[msgID] = now
	return false
}

func (h *WSHandler) rejectAck(conn *wsClient, env *types.WSEnvelope,
	msgID, targetID, code, message string) {
	h.sendOK(conn, "send_message", types.SendMessageAck{
		MsgID:     msgID,
		To:        targetID,
		Delivered: false,
		Timestamp: utils.CurrentTimestamp(),
		Error: &types.APIError{
			Code:    code,
			Message: message,
		},
	}, env.RequestID)
}

// track registers a live WebSocket client so it can be closed on shutdown.
func (h *WSHandler) track(client *wsClient) {
	h.connMu.Lock()
	h.conns[client] = struct{}{}
	h.connMu.Unlock()
}

// untrack removes a closed WebSocket client from the registry.
func (h *WSHandler) untrack(client *wsClient) {
	h.connMu.Lock()
	delete(h.conns, client)
	h.connMu.Unlock()
}

// CloseAll gracefully closes all active WebSocket connections.
func (h *WSHandler) CloseAll() {
	h.connMu.Lock()
	clients := make([]*wsClient, 0, len(h.conns))
	for c := range h.conns {
		clients = append(clients, c)
	}
	h.connMu.Unlock()

	for _, c := range clients {
		c.Close()
	}
}

// ServeWS handles GET /ws — upgrades to WebSocket and enters the dispatch loop.
func (h *WSHandler) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ERROR: WebSocket upgrade failed: %v", err)
		return
	}

	log.Printf("INFO: WebSocket connection upgraded from %s", r.RemoteAddr)

	client := &wsClient{conn: conn}
	h.track(client)

	var (
		userID      string
		connGen     uint64
		userIDMu    sync.RWMutex
		msgCh       chan *types.WSEnvelope
		startWriter sync.Once
	)

	conn.SetReadLimit(config.Cfg.WSMaxPayload)

	conn.SetReadDeadline(time.Now().Add(config.Cfg.WSReadTimeoutD()))

	// The writer goroutine starts only after connect (when msgCh exists), so it never idles for a ticker period first.
	start := func() {
		startWriter.Do(func() {
			go func() {
				ticker := time.NewTicker(config.Cfg.WSPingIntervalD())
				defer ticker.Stop()

				for {
					select {
					case msg, ok := <-msgCh:
						if !ok {
							return
						}
						if err := client.WriteJSON(msg); err != nil {
							log.Printf("ERROR: WS write failed: %v", err)
							return
						}

					case <-ticker.C:
						if err := client.WriteMessage(websocket.PingMessage, nil); err != nil {
							log.Printf("ERROR: WS ping failed: %v", err)
							return
						}
					}
				}
			}()
		})
	}

	defer func() {
		userIDMu.RLock()
		uid := userID
		userIDMu.RUnlock()

		if uid != "" {
			log.Printf("INFO: Cleaning up connection for user: %s", uid)
			LogAccess("[WS] disconnect user=%s", uid)
			// Broadcast offline only when this connection really took the user offline: cleaning up a
			// stale connection must not report a reconnected user as offline (SetOffline checks the generation).
			if h.session.SetOffline(uid, connGen) {
				h.broadcastPresence(uid, false)
			}
		}

		conn.Close()
		h.untrack(client)
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("ERROR: WS read error: %v", err)
			}
			return
		}

		// Every frame pushes the read deadline out by WSReadTimeout, making it an idle timeout rather
		// than a cap from connect time (the old one-shot deadline dropped active connections every ~5 min).
		conn.SetReadDeadline(time.Now().Add(config.Cfg.WSReadTimeoutD()))

		var env types.WSEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			h.sendError(client, "", "INVALID_JSON", "Message must be a JSON object with a 'type' field")
			continue
		}

		if env.Type == "" {
			h.sendError(client, "", "INVALID_JSON", "Message must have a 'type' field")
			continue
		}

		switch env.Type {
		case "connect":
			h.handleConnect(client, &env, &userID, &connGen, &userIDMu, &msgCh, start)

		case "send_message":
			h.handleSendMessage(client, &env, &userID, &userIDMu)

		case "heartbeat":
			h.handleHeartbeat(client, &env, &userID, &userIDMu)

		case "group_message":
			h.handleGroupMessage(client, &env, &userID, &userIDMu)

		default:
			h.sendError(client, env.RequestID, "INVALID_MESSAGE_TYPE",
				"Unknown message type: "+env.Type)
		}
	}
}

func (h *WSHandler) handleConnect(conn *wsClient, env *types.WSEnvelope,
	userID *string, connGen *uint64, mu *sync.RWMutex, msgCh *chan *types.WSEnvelope, start func()) {

	payload, err := parsePayload[types.ConnectPayload](env)
	if err != nil {
		h.sendError(conn, env.RequestID, "MISSING_PAYLOAD", "Field 'user_id' is required")
		return
	}

	uid := utils.TrimSpace(payload.UserID)
	if !utils.IsValidUserID(uid) {
		h.sendError(conn, env.RequestID, "INVALID_USER_ID",
			"user_id must be 3-32 characters (letters, numbers, underscore)")
		return
	}

	// A connection binds to one user exactly once: a second connect is rejected so the channel cannot be swapped under the writer goroutine.
	mu.RLock()
	already := *userID != ""
	mu.RUnlock()
	if already {
		h.sendError(conn, env.RequestID, "INVALID_REQUEST", "Already connected")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	exists, err := h.store.UserExists(ctx, uid)
	if err != nil {
		log.Printf("ERROR: connect check user: %v", err)
		h.sendError(conn, env.RequestID, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	if !exists {
		h.sendError(conn, env.RequestID, "USER_NOT_FOUND",
			"User '"+uid+"' is not registered. Use 'register' first.")
		return
	}

	tok := utils.TrimSpace(payload.Token)
	if tok == "" {
		h.sendError(conn, env.RequestID, "TOKEN_INVALID",
			"Session token required — please login first")
		return
	}
	storedToken, expiresAt, err := h.store.GetToken(ctx, uid)
	if err != nil {
		if errors.Is(err, store.ErrTokenNotFound) {
			h.sendError(conn, env.RequestID, "TOKEN_INVALID",
				"Session token not found — please login again")
			return
		}
		log.Printf("ERROR: connect get token: %v", err)
		h.sendError(conn, env.RequestID, "DB_UNAVAILABLE", "Database unavailable")
		return
	}
	if expiresAt < time.Now().Unix() {
		h.sendError(conn, env.RequestID, "TOKEN_EXPIRED",
			"Session token expired — please login again")
		return
	}
	if storedToken != tok {
		h.sendError(conn, env.RequestID, "TOKEN_INVALID",
			"Invalid session token")
		return
	}

	mu.Lock()
	*userID = uid
	*msgCh, *connGen = h.session.SetOnline(uid)
	mu.Unlock()

	// msgCh exists now, so start the writer; deferring it past connect keeps the writer from blocking on a nil channel for 0-30s.
	start()

	// Notify only people who explicitly added us (see store.ContactsOf).
	h.broadcastPresence(uid, true)

	log.Printf("INFO: User connected: %s", uid)
	LogAccess("[WS] connect user=%s remote=%s", uid, conn.RemoteAddr())
	h.sendOK(conn, "connect", map[string]string{"user_id": uid}, env.RequestID)
}

// filterMutualContacts keeps the contacts **mutually** added with `userID`: presence is only shared
// both ways, else a one-way contact could see a peer online but not message them. This is the
// **single** presence-visibility gate, used by the connect, offline and snapshot paths alike.
func filterMutualContacts(ctx context.Context, st *store.Store, userID string, candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	mutual, err := st.MutualContactIDs(ctx, userID)
	if err != nil {
		log.Printf("ERROR: presence mutual set %s: %v", userID, err)
		return nil // on failure treat as "not visible": better to under-send than to leak
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if _, ok := mutual[c]; ok {
			out = append(out, c)
		}
	}
	return out
}

// broadcastPresence pushes a presence update about `userID` to every online **mutual** contact.
// Best-effort (dropped when a queue is full): presence is idempotent state and clients refetch in full on (re)connect.
func (h *WSHandler) broadcastPresence(userID string, online bool) {
	ctx, cancel := bgCtx()
	defer cancel()

	watchers, err := h.store.ContactsOf(ctx, userID)
	if err != nil {
		log.Printf("ERROR: presence contacts-of %s: %v", userID, err)
		return
	}
	// One-way contacts must not learn presence.
	watchers = filterMutualContacts(ctx, h.store, userID, watchers)
	if len(watchers) == 0 {
		return
	}
	env := &types.WSEnvelope{
		Type: "presence",
		Payload: types.PresencePayload{
			UserID: userID,
			Online: online,
		},
	}
	sent := 0
	for _, w := range watchers {
		if h.session.EnqueueMessage(w, env) {
			sent++
		}
	}
	log.Printf("INFO: presence %s online=%v -> %d/%d watchers", userID, online, sent, len(watchers))
	LogAccess("[WS] presence user=%s online=%v watchers=%d", userID, online, len(watchers))
}

// StartPresenceTicker periodically re-sends a full presence snapshot to every online user. Presence
// is best-effort, so one dropped update leaves a client stuck on a wrong state until it reconnects;
// a full resend self-heals within 30s, and one presence_snapshot{contacts:{id:bool}} per user per
// tick beats event replay (O(online x contacts)). It must list **all** contacts with real state.
func (h *WSHandler) StartPresenceTicker(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				log.Println("INFO: presence ticker stopped")
				return
			case <-t.C:
				h.pushPresenceSnapshots()
			}
		}
	}()
	log.Printf("INFO: presence ticker started (every %s)", interval)
}

// pushPresenceSnapshots sends every online user a "my contacts' presence" snapshot.
func (h *WSHandler) pushPresenceSnapshots() {
	online := h.session.OnlineSet()
	if len(online) == 0 {
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	pushed := 0
	for uid := range online {
		// The people this user follows are the contacts they added (GetContacts: user_id → contact_id),
		// not ContactsOf ("who follows me", the opposite); mutuality is decided per entry below.
		watchers, err := h.store.GetContacts(ctx, uid)
		if err != nil {
			log.Printf("ERROR: presence snapshot get contacts %s: %v", uid, err)
			continue
		}
		if len(watchers) == 0 {
			continue
		}
		// One batch query replaces the old per-contact IsMutualContact loop (N+1).
		mutualSet, err := h.store.MutualContactIDs(ctx, uid)
		if err != nil {
			log.Printf("ERROR: presence snapshot mutual set %s: %v", uid, err)
			continue
		}
		// Crucial: include non-mutual contacts too, set to false. Clients replace the map wholesale, so
		// omitting them would preserve a stale "online" and one-way followers would see the peer online forever.
		state := make(map[string]bool, len(watchers))
		for _, w := range watchers {
			_, mutual := mutualSet[w]
			state[w] = online[w] && mutual
		}
		if h.session.EnqueueMessage(uid, &types.WSEnvelope{
			Type:    "presence_snapshot",
			Payload: types.PresenceSnapshotPayload{Contacts: state},
		}) {
			pushed++
		}
	}
	if pushed > 0 {
		LogAccess("[PRESENCE] snapshot tick online=%d pushed=%d", len(online), pushed)
	}
}

func (h *WSHandler) handleSendMessage(conn *wsClient, env *types.WSEnvelope,
	userID *string, mu *sync.RWMutex) {

	mu.RLock()
	senderID := *userID
	mu.RUnlock()

	if senderID == "" {
		h.sendError(conn, env.RequestID, "UNAUTHORIZED",
			"You must connect before sending messages")
		return
	}

	payload, err := parsePayload[types.SendMessagePayload](env)
	if err != nil {
		h.sendError(conn, env.RequestID, "MISSING_PAYLOAD",
			"Fields 'to' and 'ciphertext' are required")
		return
	}

	targetID := utils.TrimSpace(payload.To)
	if targetID == "" {
		h.sendError(conn, env.RequestID, "MISSING_PAYLOAD", "Field 'to' is required")
		return
	}
	if payload.MsgType == "file" {
		if payload.FileID == "" {
			h.sendError(conn, env.RequestID, "MISSING_PAYLOAD",
				"file message requires 'file_id'")
			return
		}
	} else if payload.Ciphertext == "" {
		h.sendError(conn, env.RequestID, "MISSING_PAYLOAD",
			"Field 'ciphertext' is required")
		return
	}

	if targetID == senderID {
		h.sendError(conn, env.RequestID, "INVALID_CONTACT",
			"Cannot send a message to yourself")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	mutual, err := h.store.IsMutualContact(ctx, senderID, targetID)
	if err != nil {
		log.Printf("ERROR: send_message mutual check: %v", err)
		h.sendError(conn, env.RequestID, "INTERNAL_ERROR", "Failed to check contact")
		return
	}
	if !mutual {
		msgID := payload.MsgID
		if msgID == "" {
			msgID = utils.GenerateMsgID()
		}
		h.sendOK(conn, "send_message", types.SendMessageAck{
			MsgID:     msgID,
			To:        targetID,
			Delivered: false,
			Timestamp: utils.CurrentTimestamp(),
			Error: &types.APIError{
				Code:    "NOT_MUTUAL",
				Message: "The other user has not added you; cannot send the message",
			},
		}, env.RequestID)
		log.Printf("INFO: send_message rejected (not mutual): %s -> %s", senderID, targetID)
		LogAccess("[WS] send_message %s->%s rejected NOT_MUTUAL", senderID, targetID)
		return
	}

	if payload.WrappedKey == "" || payload.IV == "" || payload.Tag == "" {
		h.sendOK(conn, "send_message", types.SendMessageAck{
			MsgID:     payload.MsgID,
			To:        targetID,
			Delivered: false,
			Timestamp: utils.CurrentTimestamp(),
			Error: &types.APIError{
				Code:    "MESSAGE_NOT_ENCRYPTED",
				Message: "Message must be encrypted (wrapped_key/iv/tag missing)",
			},
		}, env.RequestID)
		log.Printf("INFO: send_message rejected (not encrypted): %s -> %s", senderID, targetID)
		LogAccess("[WS] send_message %s->%s rejected MESSAGE_NOT_ENCRYPTED", senderID, targetID)
		return
	}

	msgID := payload.MsgID
	if msgID == "" {
		msgID = utils.GenerateMsgID()
	}

	ts := payload.Timestamp
	if ts == 0 {
		ts = utils.CurrentTimestamp()
	}

	if payload.Signature == "" {
		h.rejectAck(conn, env, msgID, targetID, "SIGNATURE_INVALID",
			"Message is missing a signature and was rejected")
		log.Printf("INFO: send_message rejected (no signature): %s -> %s", senderID, targetID)
		LogAccess("[WS] send_message %s->%s rejected SIGNATURE_INVALID", senderID, targetID)
		return
	}
	if payload.Signature != "" {
		senderPubKey, err := h.store.GetPublicKey(ctx, senderID)
		if err != nil {
			log.Printf("ERROR: send_message get sender pubkey: %v", err)
			h.sendError(conn, env.RequestID, "INTERNAL_ERROR", "Failed to verify signature")
			return
		}
		digest := auth.MessageDigest(
			msgID, targetID, senderID, strconv.FormatFloat(ts, 'f', -1, 64),
			payload.MsgType, payload.Ciphertext, payload.IV, payload.Tag,
			payload.WrappedKey, payload.FileID, payload.Filename,
			strconv.FormatInt(payload.Size, 10), payload.SHA256,
		)
		if err := auth.VerifyMessageSignature(senderPubKey, digest, payload.Signature); err != nil {
			h.rejectAck(conn, env, msgID, targetID, "SIGNATURE_INVALID",
				"Message signature verification failed")
			log.Printf("INFO: send_message rejected (bad signature): %s -> %s: %v", senderID, targetID, err)
			LogAccess("[WS] send_message %s->%s rejected SIGNATURE_INVALID", senderID, targetID)
			return
		}
	}

	if msgID != "" && h.isReplay(senderID, msgID) {
		h.rejectAck(conn, env, msgID, targetID, "DUPLICATE_MSG_ID",
			"Duplicate message (msg_id already processed)")
		log.Printf("INFO: send_message rejected (replay): %s -> %s msg_id=%s", senderID, targetID, msgID)
		LogAccess("[WS] send_message %s->%s rejected DUPLICATE_MSG_ID", senderID, targetID)
		return
	}

	newMsg := &types.NewMessagePayload{
		From:       senderID,
		Ciphertext: payload.Ciphertext,
		IV:         payload.IV,
		Tag:        payload.Tag,
		MsgID:      msgID,
		Timestamp:  ts,
		MsgType:    payload.MsgType,
		FileID:     payload.FileID,
		Filename:   payload.Filename,
		Size:       payload.Size,
		SHA256:     payload.SHA256,
		WrappedKey: payload.WrappedKey,
		Signature:  payload.Signature,
	}

	if h.session.IsOnline(targetID) {
		enqueued := h.session.EnqueueMessage(targetID, &types.WSEnvelope{
			Type:    "new_message",
			Payload: newMsg,
		})

		if enqueued {
			h.sendOK(conn, "send_message", types.SendMessageAck{
				MsgID:     msgID,
				To:        targetID,
				Delivered: true,
				Timestamp: utils.CurrentTimestamp(),
			}, env.RequestID)

			log.Printf("INFO: Message delivered online: %s -> %s msg_id=%s", senderID, targetID, msgID)
			LogAccess("[WS] send_message %s->%s msg_id=%s delivered=true", senderID, targetID, msgID)
			return
		}
		// Queue full or user went offline between check and enqueue — fall through to offline
	}

	offlineMsg := &types.OfflineMessage{
		From:       senderID,
		Ciphertext: payload.Ciphertext,
		IV:         payload.IV,
		Tag:        payload.Tag,
		MsgID:      msgID,
		Timestamp:  ts,
		MsgType:    payload.MsgType,
		FileID:     payload.FileID,
		Filename:   payload.Filename,
		Size:       payload.Size,
		SHA256:     payload.SHA256,
		WrappedKey: payload.WrappedKey,
		Signature:  payload.Signature,
	}

	if err := h.store.PushOfflineMsg(ctx, targetID, offlineMsg); err != nil {
		if errors.Is(err, store.ErrOfflineQueueFull) {
			h.sendOK(conn, "send_message", types.SendMessageAck{
				MsgID:     msgID,
				To:        targetID,
				Delivered: false,
				Timestamp: utils.CurrentTimestamp(),
				Error: &types.APIError{
					Code:    "OFFLINE_QUEUE_FULL",
					Message: "The other user's offline message queue is full",
				},
			}, env.RequestID)
			log.Printf("INFO: send_message rejected (offline queue full): %s -> %s msg_id=%s", senderID, targetID, msgID)
			LogAccess("[WS] send_message %s->%s rejected OFFLINE_QUEUE_FULL", senderID, targetID)
			return
		}
		log.Printf("ERROR: Store offline msg: %v", err)
		h.sendError(conn, env.RequestID, "INTERNAL_ERROR", "Failed to store offline message")
		return
	}

	log.Printf("INFO: Message queued offline: %s -> %s msg_id=%s", senderID, targetID, msgID)
	LogAccess("[WS] send_message %s->%s msg_id=%s delivered=false", senderID, targetID, msgID)
	h.sendOK(conn, "send_message", types.SendMessageAck{
		MsgID:     msgID,
		To:        targetID,
		Delivered: false,
		Timestamp: utils.CurrentTimestamp(),
	}, env.RequestID)
}

func (h *WSHandler) handleHeartbeat(conn *wsClient, env *types.WSEnvelope,
	userID *string, mu *sync.RWMutex) {

	mu.RLock()
	uid := *userID
	mu.RUnlock()

	if uid == "" {
		h.sendOK(conn, "heartbeat", types.HeartbeatPayload{Online: false}, env.RequestID)
		return
	}

	// Presence lives only in the in-process session.Manager; heartbeats just keep the connection alive and are not persisted.

	h.sendOK(conn, "heartbeat", types.HeartbeatPayload{Online: true}, env.RequestID)
}

// handleGroupMessage processes a WS "group_message" frame: checks membership and epoch, verifies the
// signature, appends the opaque ciphertext to the group's single queue (one seq, one copy per group)
// and fans it out to other online members. The signature covers [group_id, epoch, msg_id, ciphertext,
// msg_type, file_id, from], and `from` is the **connection identity**, so impersonation never verifies.
func (h *WSHandler) handleGroupMessage(conn *wsClient, env *types.WSEnvelope,
	userID *string, mu *sync.RWMutex) {

	mu.RLock()
	senderID := *userID
	mu.RUnlock()

	if senderID == "" {
		h.sendError(conn, env.RequestID, "UNAUTHORIZED",
			"You must connect before sending group messages")
		return
	}

	payload, err := parsePayload[types.GroupMessagePayload](env)
	if err != nil {
		h.sendError(conn, env.RequestID, "MISSING_PAYLOAD",
			"Fields 'group_id', 'msg_id' and 'ciphertext' are required")
		return
	}

	groupID := utils.TrimSpace(payload.GroupID)
	msgID := utils.TrimSpace(payload.MsgID)
	if groupID == "" || msgID == "" || payload.Ciphertext == "" {
		h.sendError(conn, env.RequestID, "MISSING_PAYLOAD",
			"Fields 'group_id', 'msg_id' and 'ciphertext' are required")
		return
	}
	if !isGroupID(groupID) {
		h.sendError(conn, env.RequestID, "INVALID_GROUP_ID",
			"group_id must be 10 lowercase base36 characters (digits + a-z)")
		return
	}
	if payload.Signature == "" {
		h.sendError(conn, env.RequestID, "SIGNATURE_REQUIRED",
			"Group messages must carry a signature")
		return
	}
	if len(payload.Ciphertext) > maxGroupMsgLen {
		h.sendError(conn, env.RequestID, "PAYLOAD_TOO_LARGE", "ciphertext too large")
		return
	}

	ctx, cancel := bgCtx()
	defer cancel()

	g, member, code, msg := loadActiveGroupMember(ctx, h.store, groupID, senderID)
	if code != "" {
		h.sendError(conn, env.RequestID, code, msg)
		return
	}
	if member.JoinedEpoch > payload.Epoch {
		h.sendError(conn, env.RequestID, "EPOCH_BEFORE_JOIN",
			"epoch is before the epoch the member joined the group")
		return
	}
	if payload.Epoch != g.CurrentEpoch {
		h.sendError(conn, env.RequestID, "EPOCH_MISMATCH",
			"epoch does not match the group's current epoch")
		return
	}

	senderPubKey, err := h.store.GetPublicKey(ctx, senderID)
	if err != nil {
		log.Printf("ERROR: group_message get sender pubkey: %v", err)
		h.sendError(conn, env.RequestID, "INTERNAL_ERROR", "Failed to verify signature")
		return
	}
	digest := auth.MessageDigest(
		groupID,
		strconv.FormatInt(payload.Epoch, 10),
		msgID,
		payload.Ciphertext,
		payload.MsgType,
		payload.FileID,
		senderID,
	)
	if err := auth.VerifyMessageSignature(senderPubKey, digest, payload.Signature); err != nil {
		h.sendError(conn, env.RequestID, "SIGNATURE_INVALID", "Group message signature verification failed")
		LogAccess("[WS] group_message %s group=%s rejected SIGNATURE_INVALID",
			senderID, groupID)
		return
	}

	gm := &store.GroupMessage{
		GroupID:    groupID,
		Epoch:      payload.Epoch,
		Sender:     senderID,
		MsgID:      msgID,
		Ciphertext: payload.Ciphertext,
		MsgType:    payload.MsgType,
		FileID:     payload.FileID,
	}
	seq, err := h.store.AppendGroupMessage(ctx, gm)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateGroupMsg) {
			h.sendError(conn, env.RequestID, "DUPLICATE_MSG_ID",
				"Duplicate message (msg_id already exists)")
			return
		}
		log.Printf("ERROR: group_message append: %v", err)
		h.sendError(conn, env.RequestID, "INTERNAL_ERROR", "Failed to store group message")
		return
	}

	// Fan out to the other online members: the push is a convenience, offline (or queue-full) members pull on their own.
	push := &types.GroupNewMessagePayload{
		GroupID:    groupID,
		Seq:        seq,
		Epoch:      payload.Epoch,
		Sender:     senderID,
		MsgID:      msgID,
		Ciphertext: payload.Ciphertext,
		MsgType:    payload.MsgType,
		FileID:     payload.FileID,
	}
	members, err := h.store.GroupMemberIDs(ctx, groupID)
	if err != nil {
		log.Printf("WARN: group_message member ids %s: %v", groupID, err)
	} else {
		for _, uid := range members {
			if uid == senderID {
				continue
			}
			if h.session.IsOnline(uid) {
				h.session.EnqueueMessage(uid, &types.WSEnvelope{
					Type:    "group_new_message",
					Payload: push,
				})
			}
		}
	}

	log.Printf("INFO: group_message %s group=%s msg_id=%s seq=%d", senderID, groupID, msgID, seq)
	LogAccess("[WS] group_message sender=%s group=%s msg_id=%s seq=%d", senderID, groupID, msgID, seq)
	h.sendOK(conn, "group_message", types.GroupMessageResponse{MsgID: msgID, Seq: seq}, env.RequestID)
}

func (h *WSHandler) sendOK(conn *wsClient, msgType string, payload interface{}, requestID string) {
	resp := types.WSEnvelope{
		Type:      msgType,
		Status:    "ok",
		Payload:   payload,
		RequestID: requestID,
	}
	if err := conn.WriteJSON(resp); err != nil {
		log.Printf("ERROR: WS sendOK failed: %v", err)
	}
}

func (h *WSHandler) sendError(conn *wsClient, requestID, code, message string) {
	resp := types.WSEnvelope{
		Type:      "error",
		Status:    "error",
		RequestID: requestID,
		Error: &types.APIError{
			Code:    code,
			Message: message,
		},
	}
	if err := conn.WriteJSON(resp); err != nil {
		log.Printf("ERROR: WS sendError failed: %v", err)
	}
}

func parsePayload[T any](env *types.WSEnvelope) (*T, error) {
	raw, err := json.Marshal(env.Payload)
	if err != nil {
		return nil, err
	}
	var p T
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
