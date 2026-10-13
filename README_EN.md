# etemsg Server — End-to-End Encrypted Message Relay

A Go 1.21 server that provides HTTPS REST and WebSocket relay services for end-to-end encrypted chat. It stores and forwards ciphertext, encrypted file blobs and opaque MLS objects; it never has group keys, epoch secrets or plaintext message columns.

### In one sentence

The client owns identities and encryption; the server owns accounts, contact relationships, offline queues, file ciphertext, presence and the ordered opaque group queue.

---

## 1. Features

- Registration and challenge-response login:
  - `POST /register` binds `user_id` to a public key.
  - `POST /login/challenge` + `POST /login` issue a short-lived challenge and return a session token.
- Signed REST requests: timestamp + nonce + RSA/ECDSA/Ed25519 signature, with a ±5 minute window and in-process nonce replay cache.
- WebSocket realtime channel: `connect`, `heartbeat`, `send_message`, `new_message`, `presence`, `presence_snapshot`, `contact_notify`, `group_new_message`, `group_notify`.
- Contact relationships, mutual-contact enforcement, one-way friend requests and pending-incoming list.
- Online presence that only exposes a user to mutual contacts.
- Offline ciphertext queue: up to 1000 messages per user.
- Encrypted file upload/download with streaming, UUID validation, `O_EXCL` create, Range resume, and TTL cleanup.
- Group relay: create/search, KeyPackage upload, join requests, Commit/Welcome relay, group messages, ACK cursors, queue retention, leave/kick/dissolve and ownership transfer workflows.
- Pure-Go SQLite (`modernc.org/sqlite`), WAL mode and a single-writer connection.
- Self-contained watchdog process model: the launcher starts a watcher and exits; the watcher runs and restarts the actual worker on crashes.
- Periodic background jobs: file TTL cleanup (hourly) and group message queue reclamation (every minute).

---

## 2. Architecture

```text
server/src/
├── main.go                 process model, routes, background jobs, TLS HTTP server
├── config/                 config.json loading and defaults
├── auth/                   challenge, message digest/signature, timestamp/nonce replay
├── store/                  SQLite schema, users/contacts/messages/files/groups
├── handler/                REST handlers, WebSocket handler, access log
├── session/                in-memory online session manager and delivery queues
├── types/                  request/response/WS payload structs (1v1 + group)
├── utils/                  ID validation, public-key ID, message IDs
└── generate-certs.sh       development self-signed certificate generator (certificates are generated at build time, never committed)
```

Data flow:

```text
client HTTPS REST ── signed request ──▶ handler ── SQLite
client WSS ───────── connect/token ───▶ session.Manager
     │  send_message/group_message
     ▼
handler verifies signature, mutual contact / group membership,
stores offline ciphertext or appends one opaque group row,
then fans out a push frame to online recipients.
```

---

## 3. Requirements

- Go 1.21 or newer
- OpenSSL in `PATH` if you use `build.sh` / `generate-certs.sh`
- Linux is the primary deployment target; the pure-Go SQLite driver removes CGO/runtime library concerns
- No external database required

---

## 4. Build and Run

Recommended developer build (also generates the TLS pair):

```bash
cd server
bash build.sh
cd build
./msg_server
```

Binary-only build:

```bash
cd server/src
go build -o ../build/msg_server .
# On a clean checkout, generate the TLS pair before first start:
bash src/generate-certs.sh ../build/certs
cd ../build && ./msg_server
```

`build.sh` additionally regenerates the self-signed certificate and copies the cert script into `build/`.

> **Important:** `build.sh` creates a new certificate and private key. Existing clients pin the old certificate fingerprint, so a routine binary upgrade should **replace only the binary** and keep `certs/` and `etemsg.db` unchanged.

First start creates defaults and runtime files next to the binary:

```text
msg_server
config.json          generated with defaults on first start
certs/server.crt     TLS certificate (must already exist or be generated)
certs/server.key     TLS private key
etemsg.db            SQLite database
files/               encrypted file blobs
init.log             watcher/worker log
access.log           access log
```

Process model:

- Run `./msg_server` → it starts a detached watcher and exits.
- Watcher runs the worker with `E2E_DAEMON=1`.
- If the worker exits quickly, watcher backs off (3 seconds normally, 30 seconds after three fast crashes).
- `SIGTERM`/`SIGINT` to the watcher stops the worker gracefully.

---

## 5. Configuration

`config.json` is generated next to the binary on first start. Relative paths resolve against the binary directory.

| Key | Default | Meaning |
|---|---|---|
| `listen_addr` | `:60345` | HTTPS listen address |
| `cert_file` | `certs/server.crt` | TLS certificate path |
| `key_file` | `certs/server.key` | TLS private key path |
| `ws_read_timeout_seconds` | `300` | WebSocket idle read deadline |
| `ws_ping_interval_seconds` | `30` | Server ping interval |
| `ws_write_timeout_seconds` | `10` | WebSocket write deadline |
| `ws_max_payload_bytes` | `20971520` | WebSocket read limit (20 MiB) |
| `max_file_size_bytes` | `524288000` | Maximum upload size (500 MiB) |
| `file_ttl_seconds` | `604800` | File retention (7 days) |
| `file_name_max` | `1024` | Maximum filename metadata length |
| `file_dir_name` | `files` | Encrypted blob directory |
| `token_ttl_seconds` | `604800` | Session token validity (7 days) |

`load` validates only the TLS certificate/key existence plus JSON syntax; other values are used as provided.

---

## 6. Main Endpoints

### 1v1, auth and contacts

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/register` | Register user ID + public key (ID must match public-key hash) |
| `POST` | `/login/challenge` | Request a login challenge (TTL 300s) |
| `POST` | `/login` | Verify signed challenge and issue token |
| `POST` | `/add_contact` | One-way contact add; returns peer public key |
| `POST` | `/contacts/pending_incoming` | Incoming one-way contact requests |
| `POST` | `/contacts/online` | Online state of the caller's mutual contacts |
| `POST` | `/get_offline_msg` | Atomically fetch and clear the caller's offline queue |
| `POST` | `/upload_file` | Stream encrypted file body and save metadata |
| `GET` | `/download_file/{file_id}` | Owner-only download, supports `Range` resume |
| `GET` | `/ws` | WebSocket realtime channel |

### Groups (`/groups` subtree)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/groups` | Create group (epoch 0) |
| `GET` | `/groups` | List own groups |
| `GET` | `/groups/{gid}` | Group metadata and members |
| `GET` | `/groups/search?by=id&q=` | Search by group ID/prefix |
| `POST/GET` | `/groups/{gid}/key-packages` | Publish / fetch MLS KeyPackage |
| `POST/GET` | `/groups/{gid}/join_requests` | Create / list pending join requests |
| `POST` | `/groups/{gid}/join_requests/{rid}/decide` | Owner/admin allow or deny |
| `POST/GET` | `/groups/{gid}/commits` | Relay / list opaque MLS Commits |
| `POST/GET` | `/groups/{gid}/welcomes` | Relay / list opaque MLS Welcomes |
| `POST/GET` | `/groups/{gid}/messages` | Append / list group ciphertext |
| `POST` | `/groups/{gid}/messages/ack` | Advance caller's group cursor |
| `POST` | `/groups/{gid}/leave` | Leave; owner must name a successor |
| `POST` | `/groups/{gid}/kick` | Owner removes a member and records pending removal |
| `GET/POST` | `/groups/{gid}/pending-removals[/clear]` | Owner pending-removal queue |
| `POST/GET` | `/groups/{gid}/transfer[/accept|/decline]` | Ownership transfer workflow |
| `DELETE` | `/groups/{gid}` | Dissolve group (owner only) |

All group endpoints are signed. The server validates membership and coarse roles (owner/admin where applicable), but does not interpret MLS semantics.

---

## 7. Storage

SQLite tables (created with `CREATE TABLE IF NOT EXISTS`):

- `users`: user ID, public key, creation time
- `contacts`: one-way `(user_id, contact_id)` edges
- `offline_messages`: encrypted messages queued for offline delivery
- `login_challenges`: challenge string with TTL
- `auth_tokens`: session token with TTL
- `files`: encrypted file metadata and ownership
- `groups`, `group_members`: group metadata and coarse membership
- `group_join_requests`, `mls_key_packages`: onboarding objects
- `group_mls_log`: opaque Commit/Welcome log
- `group_messages`: one ciphertext queue per group
- `group_cursor`: per-user ACK cursor
- `group_pending_removals`: owner follow-up tasks
- `group_owner_transfers`: pending ownership transfer state

The SQLite driver opens one connection (`SetMaxOpenConns(1)`), WAL mode and a 5-second busy timeout. Encrypted file bodies live in `files/{file_id}.enc`.

---

## 8. Security Model

What the server verifies:

- Public key / user ID binding at registration and contact-add time.
- Signed requests over business fields + timestamp + nonce; timestamps are limited to ±5 minutes.
- Message signatures for 1v1 and group messages (the 13-field 1v1 digest is part of the protocol).
- Mutual-contact relationships before 1v1 messaging/files.
- Group membership and owner/admin role on privileged group endpoints.
- The Welcome endpoint now explicitly requires `owner`/`admin`; a plain member can no longer add arbitrary users to the member table.
- Login challenges are consumed atomically (`DELETE ... RETURNING`), so two concurrent `/login` requests cannot both mint a token from the same challenge.
- Group child tables declare `ON DELETE CASCADE` foreign keys to `groups` on newly created databases, preventing orphan rows when a group row is removed.
- Blob hash for KeyPackage/Commit/Welcome, group queue uniqueness and epoch monotonicity.
- File UUID regex to prevent path traversal, bounded request bodies and streamed uploads.

What the server does **not** know or do:

- No plaintext messages, AES keys or RSA private keys.
- No MLS group key, epoch secret, ratchet tree or decrypted group message.
- No ability to validate the semantic content of a Commit/Welcome; clients enforce MLS.

### Important server-side caveats

1. **TLS private keys are runtime artifacts, not source.** `server/src/certs/` was removed from the repository; `build.sh` / `generate-certs.sh` generate a fresh pair under the build directory before deployment. Never commit `server.key`.
2. WSS on the client does not validate the server certificate; server-side TLS alone cannot hide metadata from a network MITM in that path.
3. Replay caches are in-process; multi-instance deployments and restarts lose replay state.
4. There is no global rate limiting, registration throttle, per-user quota or total disk quota.
5. Several log/retention areas are missing: `group_mls_log`, `group_join_requests`, and `mls_key_packages` have no cleanup path.

See `../ASSESSMENT.md` for the full review.

---

## 9. Operations

- **Logs:** `init.log` (watcher/worker) and `access.log` (HTTP requests and key relay events). Check permissions and rotate externally; the server does not rotate logs.
- **Backups:** back up `etemsg.db` together with any `-wal`/`-shm` files while the service is stopped, or use SQLite backup semantics; also back up `files/` and `certs/`.
- **Certificate rotation:** clients pin the SPKI fingerprint, so rotating a certificate invalidates existing pins. Plan a client-side re-trust path.
- **Graceful stop:** signal the watcher (`SIGTERM`). The worker gets 15 seconds to exit before it is killed.
- **File cleanup:** hourly background job removes files older than `file_ttl_seconds` and orphan `.enc` files.
- **Group cleanup:** every minute the server advances per-group retention based on member cursors and drops the oldest messages above 10,000 rows.
- **Upgrades:** the schema is created with `IF NOT EXISTS` and there are no migrations; a database created by a different schema version may require manual migration.

---

## 10. Tests

```bash
cd server/src
go test ./...
go vet ./...
```

At the time this README was generated, all four test packages (`auth`, `handler`, `session`, `store`) passed.

---

## 11. Known Limitations

- No group file transfer.
- `admin` is a defined role but there is no endpoint to grant it; in production every group currently has at most one `owner` and the rest are `member`.
- If the owner starts a transfer and leaves while the designee neither accepts nor declines, the group becomes an owner-vacant "dead state": joins/approvals are blocked until the designee acts. There is no automatic timeout or rollback; messages still flow.
- `group_mls_log` grows forever; old Commit/Welcome rows are never collected.
- KeyPackages and decided join requests are never deleted.
- No total disk quota or per-user registration/upload quota.
- HTTP server has no explicit header/idle/read timeouts beyond WebSocket deadlines.
- SQLite is serialized through one connection; this is simple and safe, but limits throughput.
- The server stores coarse metadata (sender, recipient, timestamps, group membership, sequence numbers) by design.

---

## 12. Related Documents

- Repository root: `../README.md`
- Project assessment: `../ASSESSMENT.md`
- Client documentation: `../client/README.md`
