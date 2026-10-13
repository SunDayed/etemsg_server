# etemsg Server

[简体中文](README_CN.md)

A Go relay server for the `etemsg` end-to-end encrypted chat system. It provides HTTPS REST APIs and WebSocket delivery for accounts, contacts, offline messages, encrypted files, and opaque MLS group traffic. The server never stores plaintext messages, group keys, or private keys.

## Features

- User registration, challenge-response login, and signed REST requests.
- WebSocket realtime messaging, heartbeats, presence, and delivery acknowledgements.
- Mutual-contact enforcement, one-way contact requests, and pending incoming requests.
- Encrypted file upload/download with streaming and Range resume.
- Offline ciphertext message queues.
- MLS group relay: groups, KeyPackages, join requests, commits, welcomes, group messages, ACKs, leave, kick, transfer, and dissolve.
- Opaque storage of MLS objects, ciphertext, and encrypted file bodies.
- Pure-Go SQLite storage with WAL mode and periodic file/group queue cleanup.
- Self-contained watcher/worker process model for crash recovery.

## Build

Requirements: Go 1.21+; OpenSSL is required when generating the self-signed development certificate.

```bash
cd server

# Recommended: build the server and generate build/certs
bash build.sh
```

Or build the binary and generate certificates manually:

```bash
cd server/src
go build -o ../build/msg_server .
bash src/generate-certs.sh ../build/certs
```

Build outputs are written under `server/build/`:

```text
build/msg_server
build/certs/server.crt
build/certs/server.key
```

Run tests:

```bash
cd server/src
go test ./...
go vet ./...
```
