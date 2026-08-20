package handler

import (
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

// wsClient wraps a WebSocket connection and serializes all writes with a mutex.
// gorilla/websocket requires that a connection has at most one concurrent writer;
// this wrapper guarantees that even when acks/errors are written from the read loop
// while the writer goroutine sends new_message/ping frames.
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

// Close sends a WebSocket close frame and closes the underlying connection.
// It is safe to call multiple times and from any goroutine.
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

	// Set max message size (20 MB)
	conn.SetReadLimit(config.Cfg.WSMaxPayload)

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(config.Cfg.WSReadTimeoutD()))

	// Writer goroutine is started AFTER connect (when msgCh is set),
	// so there is no initial delay waiting for the ticker to re-read msgCh.
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

	// ── Cleanup ────────────────────────────────────────────────────
	defer func() {
		userIDMu.RLock()
		uid := userID
		userIDMu.RUnlock()

		if uid != "" {
			log.Printf("INFO: Cleaning up connection for user: %s", uid)
			LogAccess("[WS] disconnect user=%s", uid)
			h.session.SetOffline(uid, connGen)
		}

		conn.Close()
		h.untrack(client)
	}()

	// ── Read loop ──────────────────────────────────────────────────
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("ERROR: WS read error: %v", err)
			}
			return
		}

		// Parse JSON envelope
		var env types.WSEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			h.sendError(client, "", "INVALID_JSON", "Message must be a JSON object with a 'type' field")
			continue
		}

		if env.Type == "" {
			h.sendError(client, "", "INVALID_JSON", "Message must have a 'type' field")
			continue
		}

		// Dispatch by message type
		switch env.Type {
		case "connect":
			h.handleConnect(client, &env, &userID, &connGen, &userIDMu, &msgCh, start)

		case "send_message":
			h.handleSendMessage(client, &env, &userID, &userIDMu)

		case "heartbeat":
			h.handleHeartbeat(client, &env, &userID, &userIDMu)

		default:
			h.sendError(client, env.RequestID, "INVALID_MESSAGE_TYPE",
				"Unknown message type: "+env.Type)
		}
	}
}

// ─── Handler methods ───────────────────────────────────────────────

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

	// A WebSocket connection can only bind one user once. Rejecting duplicate
	// connect avoids replacing the channel while the existing writer is running.
	mu.RLock()
	already := *userID != ""
	mu.RUnlock()
	if already {
		h.sendError(conn, env.RequestID, "INVALID_REQUEST", "Already connected")
		return
	}

	// Verify user exists
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

	// Bind session
	mu.Lock()
	*userID = uid
	*msgCh, *connGen = h.session.SetOnline(uid)
	mu.Unlock()

	// Start the writer goroutine now that msgCh is set.
	// Delaying start until after connect avoids the initial 0–30s delay
	// caused by the writer blocking on a nil channel in the select loop.
	start()

	log.Printf("INFO: User connected: %s", uid)
	LogAccess("[WS] connect user=%s remote=%s", uid, conn.RemoteAddr())
	h.sendOK(conn, "connect", map[string]string{"user_id": uid}, env.RequestID)
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
				Message: "对方未添加你，无法发送消息",
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
				Message: "消息必须加密（wrapped_key/iv/tag 缺失）",
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
			"消息缺少签名，已被拒绝")
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
				"消息签名验证失败")
			log.Printf("INFO: send_message rejected (bad signature): %s -> %s: %v", senderID, targetID, err)
			LogAccess("[WS] send_message %s->%s rejected SIGNATURE_INVALID", senderID, targetID)
			return
		}
	}

	if msgID != "" && h.isReplay(senderID, msgID) {
		h.rejectAck(conn, env, msgID, targetID, "DUPLICATE_MSG_ID",
			"重复消息（msg_id 已处理过）")
		log.Printf("INFO: send_message rejected (replay): %s -> %s msg_id=%s", senderID, targetID, msgID)
		LogAccess("[WS] send_message %s->%s rejected DUPLICATE_MSG_ID", senderID, targetID)
		return
	}

	// Build the forwarded message
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

	// Try direct delivery via in-process channel
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
					Message: "对方离线消息队列已满",
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

	// Online status lives in the in-process session.Manager;
	// the heartbeat keeps the WebSocket alive, nothing to persist.

	h.sendOK(conn, "heartbeat", types.HeartbeatPayload{Online: true}, env.RequestID)
}

// ─── Response helpers ──────────────────────────────────────────────

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

// ─── Helper ────────────────────────────────────────────────────────

func parsePayload[T any](env *types.WSEnvelope) (*T, error) {
	// Re-marshal and unmarshal into typed payload
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
