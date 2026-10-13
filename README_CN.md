# etemsg 服务端 — 端到端加密消息中继

基于 Go 1.21 的 HTTPS REST + WebSocket 中继服务，为 `msg-client-rust` 等端到端加密客户端提供账号、联系人、离线消息、文件密文和 MLS 群组不透明转发能力。服务端不持有私钥、群密钥、epoch secret，也不存明文消息。

> 当前 README 基于源码生成。完整协议见项目根目录 `README.md`；当前问题清单见根目录 `ASSESSMENT.md`。

---

## 1. 功能概览

- 注册与挑战登录：`POST /register`、`POST /login/challenge`、`POST /login`
- 带签 REST：业务字段 + 时间戳 + nonce + 签名，允许 ±5 分钟窗口
- WebSocket 实时通道：`connect`、`heartbeat`、`send_message`、`new_message`、`presence`、`presence_snapshot`、`contact_notify`、`group_new_message`、`group_notify`
- 联系人与互为联系人校验、单向好友申请、待处理申请列表
- 在线状态：只对**互为联系人**可见
- 离线消息队列：每用户最多 1000 条密文
- 加密文件上传/下载：流式、UUID 校验、`O_EXCL`、Range 断点续传、TTL 清理
- 群组中继：建群/搜索、KeyPackage、入群申请、Commit/Welcome、群消息、ACK 游标、队列回收、退群/踢人/解散/转让
- 纯 Go SQLite（`modernc.org/sqlite`），WAL 模式，单写连接
- 自带 watcher/worker 看门狗，不依赖 systemd
- 后台任务：文件 TTL 每小时清理；群消息队列每分钟回收

---

## 2. 架构

```text
server/src/
├── main.go                 进程模型、路由、后台任务、TLS HTTP 服务
├── config/                 config.json 加载与默认值
├── auth/                   挑战、摘要/签名校验、timestamp/nonce 防重放
├── store/                  SQLite schema 与全部 SQL
├── handler/                REST/WS 处理器、访问日志
├── session/                内存在线会话与投递队列
├── types/                  请求/响应/WS payload
├── utils/                  ID 校验、公钥 ID、消息 ID
└── generate-certs.sh       开发用自签证书脚本（证书在构建后生成，不提交到源码）
```

基本数据流：

```text
客户端 HTTPS + 签名 ──▶ handler 校验签名/成员关系 ──▶ SQLite/文件系统
客户端 WSS connect(token) ──▶ session.Manager
send_message/group_message ──▶ 校验签名/互为联系人/群成员
                                  ├─ 离线：写入离线队列
                                  └─ 在线：经 WS 推送
群 Commit/Welcome/群消息 ──▶ 仅做哈希校验/顺序校验/不透明存储
```

---

## 3. 环境要求

- Go 1.21+
- 使用 `build.sh` / `generate-certs.sh` 时需要 OpenSSL
- 纯 Go SQLite，无 CGO；建议 Linux 部署

---

## 4. 构建与启动

推荐开发构建（同时生成证书）：

```bash
cd server
bash build.sh
cd build
./msg_server
```

只编译二进制时：

```bash
cd server/src
go build -o ../build/msg_server .
# 干净检出时还需要先生成 TLS 证书：
bash src/generate-certs.sh ../build/certs
cd ../build && ./msg_server
```

`build.sh` 还会重新生成自签证书和复制证书脚本：

```bash
cd server
bash build.sh
```

> **注意：** `build.sh` 会生成一套新的证书/私钥，已有客户端固定的是旧指纹。常规升级应**只替换二进制**，保留 `certs/` 和 `etemsg.db`。

首次启动会在二进制旁生成：

```text
msg_server
config.json       默认配置
certs/server.crt  TLS 证书（需已有或另行生成）
certs/server.key  TLS 私钥
etemsg.db         SQLite 数据库
files/            加密文件体
init.log          watcher/worker 日志
access.log        访问日志
```

进程模型：

- 直接运行 `./msg_server`：启动后台 watcher 进程后主进程退出。
- watcher 以 `E2E_DAEMON=1` 启动真正的 worker。
- worker 崩溃快速重启；10 秒内连续崩 3 次后延迟 30 秒。
- 给 watcher 发 `SIGTERM` / `SIGINT` 可优雅停止 worker。

---

## 5. 配置项

`config.json` 首次启动时生成，相对路径按二进制目录解析。

| 键 | 默认值 | 说明 |
|---|---|---|
| `listen_addr` | `:60345` | HTTPS 监听地址 |
| `cert_file` | `certs/server.crt` | 证书路径 |
| `key_file` | `certs/server.key` | 私钥路径 |
| `ws_read_timeout_seconds` | `300` | WebSocket 空闲读超时 |
| `ws_ping_interval_seconds` | `30` | 服务端 ping 间隔 |
| `ws_write_timeout_seconds` | `10` | WebSocket 写超时 |
| `ws_max_payload_bytes` | `20971520` | WS 读上限 20 MiB |
| `max_file_size_bytes` | `524288000` | 单文件上限 500 MiB |
| `file_ttl_seconds` | `604800` | 文件保留 7 天 |
| `file_name_max` | `1024` | 文件名字段上限 |
| `file_dir_name` | `files` | 加密文件目录 |
| `token_ttl_seconds` | `604800` | 会话 token 有效期 7 天 |

---

## 6. 主要端点

### 1v1、认证与联系人

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/` | 健康检查 |
| `POST` | `/register` | 注册 user_id + 公钥；ID 必须等于公钥 ID |
| `POST` | `/login/challenge` | 获取登录挑战（300 秒 TTL） |
| `POST` | `/login` | 校验挑战签名并下发 token |
| `POST` | `/add_contact` | 单向添加联系人并返回对方公钥 |
| `POST` | `/contacts/pending_incoming` | 别人加我、我尚未加回的列表 |
| `POST` | `/contacts/online` | 互为联系人的在线状态 |
| `POST` | `/get_offline_msg` | 原子拉取并清空离线队列 |
| `POST` | `/upload_file` | 流式上传加密文件 |
| `GET` | `/download_file/{file_id}` | 仅文件接收方下载，支持 Range |
| `GET` | `/ws` | WebSocket 实时连接 |

### 群组（`/groups` 子树）

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/groups` | 建群（epoch 0） |
| `GET` | `/groups` | 我参与的群 |
| `GET` | `/groups/{gid}` | 群元数据与成员 |
| `GET` | `/groups/search?by=id&q=` | 按群 ID/前缀搜索 |
| `POST/GET` | `/groups/{gid}/key-packages` | 上传/获取 KeyPackage |
| `POST/GET` | `/groups/{gid}/join_requests` | 申请/查看入群申请 |
| `POST` | `/groups/{gid}/join_requests/{rid}/decide` | owner/admin 批准/拒绝 |
| `POST/GET` | `/groups/{gid}/commits` | 不透明 Commit 转发/拉取 |
| `POST/GET` | `/groups/{gid}/welcomes` | 不透明 Welcome 转发/拉取 |
| `POST/GET` | `/groups/{gid}/messages` | 群密文追加/拉取 |
| `POST` | `/groups/{gid}/messages/ack` | 推进个人群游标 |
| `POST` | `/groups/{gid}/leave` | 退群；群主必须指定继任者 |
| `POST` | `/groups/{gid}/kick` | 群主移除成员并登记待办 |
| `GET/POST` | `/groups/{gid}/pending-removals[/clear]` | 群主待移除待办 |
| `POST/GET` | `/groups/{gid}/transfer[/accept|/decline]` | 群主转让流程 |
| `DELETE` | `/groups/{gid}` | 解散群（仅群主） |

所有群组端点都要求签名；服务端校验成员/粗粒度角色，但不解析 MLS 语义。

---

## 7. 存储

SQLite 表（全部 `CREATE TABLE IF NOT EXISTS`）：

- `users`、`contacts`
- `offline_messages`
- `login_challenges`、`auth_tokens`
- `files`
- `groups`、`group_members`
- `group_join_requests`、`mls_key_packages`
- `group_mls_log`（不透明 Commit/Welcome）
- `group_messages`、`group_cursor`
- `group_pending_removals`、`group_owner_transfers`

SQLite 使用单连接、WAL、5 秒 busy timeout。加密文件体位于 `files/{file_id}.enc`。

---

## 8. 安全模型

服务端会校验：

- 注册和加联系人时的公钥/ID 绑定
- 带签 REST 的签名、时间窗口和 nonce 防重放
- 1v1 与群消息签名
- 互为联系人关系（1v1 消息/文件）
- 群成员和 owner/admin 粗粒度权限
- Welcome 端点现在明确要求 owner/admin，普通成员不能再把任意用户写入成员表
- 登录挑战使用 `DELETE ... RETURNING` 原子消费，同一挑战不会被两个并发 `/login` 同时换成 token
- 群组子表在新建库中声明 `ON DELETE CASCADE` 外键到 `groups`，删除群行时避免孤儿记录
- KeyPackage/Commit/Welcome 哈希、群消息唯一性、epoch 单调性
- 文件 UUID 正则防路径穿越、请求体上限、流式上传

服务端**不知道也不做**：

- 明文消息、AES 密钥、RSA 私钥
- MLS 群密钥、epoch secret、棘轮树、解密群消息
- 不解析 Commit/Welcome 的 MLS 语义，由客户端验收

### 重要注意事项

1. **TLS 私钥是运行时产物，不是源码**：`server/src/certs/` 已从仓库删除；`build.sh` / `generate-certs.sh` 会在部署前于 build 目录生成新证书/私钥。不要把 `server.key` 提交到仓库。
2. 客户端 WSS 当前不校验证书；仅靠服务端 TLS 无法在该路径隐藏元数据。
3. 防重放缓存是进程内状态，多实例部署和重启会失效。
4. 没有全局限流、注册节流、用户配额或磁盘总量配额。
5. `group_mls_log`、`group_join_requests`、`mls_key_packages` 没有清理路径。

完整评估见 `../ASSESSMENT.md`。

---

## 9. 运维

- **日志：** `init.log`、`access.log`；服务端不做日志轮转，需外部处理。
- **备份：** 停止服务后同时备份 `etemsg.db` 与 `-wal`/`-shm`，以及 `files/`、`certs/`；不要只复制主库。
- **证书轮换：** 客户端固定 SPKI 指纹，换证会使已有客户端失联，需要规划重新信任。
- **停止：** 对 watcher 发 `SIGTERM`；worker 有 15 秒退出窗口。
- **文件清理：** 每小时清理过期文件和孤儿 `.enc`。
- **群队列清理：** 每分钟按成员游标回收，超过 10000 条丢弃最旧。
- **升级：** 无自动迁移；schema 变化需要手工处理。

---

## 10. 测试

```bash
cd server/src
go test ./...
go vet ./...
```

生成文档时 `auth`、`handler`、`session`、`store` 四个包全部通过。

---

## 11. 已知限制

- 群组文件传输未实现。
- `admin` 角色目前无法授予，实际每个群通常只有 owner 和 member。
- 群主发起转让并退出后，如果继任者既不接受也不拒绝，群会进入 owner 空缺的“死状态”：加群/审批被阻塞，直到继任者处理；当前没有自动超时或回退，消息收发不受影响。
- `group_mls_log` 永不回收。
- KeyPackage 和已决入群申请永不删除。
- 无总量磁盘配额、无用户注册/上传配额。
- HTTP 服务未显式设置 Header/Read/Idle 超时，存在慢速连接耗尽风险。
- SQLite 单连接串行化，简单安全但吞吐有限。
- 服务端按设计可见发送者、接收者、时间戳、群成员、序号等元数据。

---

## 12. 相关文档

- 项目根目录：`../README.md`
- 项目评估：`../ASSESSMENT.md`
- 客户端文档：`../client/README.md`
