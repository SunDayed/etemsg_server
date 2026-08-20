# E2E Encrypted Message Server

> [简体中文](README_CN.md)

---

## 1. Overview

- **Language**: Go 1.21 + SQLite
- **Description**: A message relay server for end-to-end encrypted chat.
- **Features**:
  - REST APIs for registration, login, contacts, offline messages, file upload/download
  - WebSocket real-time messaging
  - Stores and forwards ciphertext only
  - TLS with self-signed certificate
  - Token authentication and message signature verification
  - Mutual contact enforcement

## 2. Build

Option 1:

```bash
bash build.sh
```

Option 2:

```bash
cd src
go build -o ../build/msg_server .
```

Output:

```text
build/msg_server
```

## 3. Security Model

- The server never sees plaintext.
- Text and file messages are encrypted on the client side.
- The server stores:
  - Ciphertext
  - Wrapped AES keys
  - Encrypted filenames
  - Metadata (sender, recipient, size, timestamps)
- Without the recipient's private key, the server cannot decrypt content.

## 4. Directory

```text
server/
├── src/
├── build.sh
└── build/
```
