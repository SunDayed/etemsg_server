# etemsg Server

[English](README.md)

`etemsg` 端到端加密聊天系统的 Go 中继服务端。它提供 HTTPS REST API 与 WebSocket 投递，用于账号、联系人、离线消息、加密文件和不透明 MLS 群组流量。服务端不保存明文消息、群密钥或私钥。

## 功能

- 用户注册、挑战-应答登录、带签 REST 请求。
- WebSocket 实时消息、心跳、在线状态与投递回执。
- 互为联系人校验、单向好友申请、待处理入站申请。
- 加密文件流式上传/下载，支持 Range 断点续传。
- 离线密文消息队列。
- MLS 群组中继：建群、KeyPackage、入群申请、Commit、Welcome、群消息、ACK、退群、踢人、转让、解散。
- 不透明保存 MLS 对象、密文和加密文件体。
- 纯 Go SQLite 存储，WAL 模式，定期清理文件与群消息队列。
- 自带 watcher/worker 看门狗进程模型，崩溃后自动恢复。

## 构建

环境要求：Go 1.21+；生成开发用自签证书时需要 OpenSSL。

```bash
cd server

# 推荐：编译服务端并生成 build/certs
bash build.sh
```

或手动构建二进制并生成证书：

```bash
cd server/src
go build -o ../build/msg_server .
bash src/generate-certs.sh ../build/certs
```

构建产物位于 `server/build/`：

```text
build/msg_server
build/certs/server.crt
build/certs/server.key
```

运行测试：

```bash
cd server/src
go test ./...
go vet ./...
```
