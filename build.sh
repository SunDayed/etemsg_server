#!/bin/bash
# =============================================================================
# E2E Chat Server — 一键构建可分发部署包
#
# 构建流程:
#   1. 编译 Go 二进制，输出到 build/msg_server
#   2. 在 build/certs 中生成一套新的 HTTPS 证书和私钥
#   3. 将证书更新脚本同步到 build/generate-certs.sh
#
# 产物: build/
#   build/msg_server         二进制（纯 Go 静态 + 纯 Go SQLite，无运行时依赖）
#   build/certs/server.crt   新生成的自签证书
#   build/certs/server.key   新生成的私钥
#   build/certs/dhparam.pem  DH 参数
#   build/generate-certs.sh  证书再生成脚本（可随时重新生成并替换 build/certs）
#
# 部署: 将 build/ 整个目录复制到目标 Linux 服务器，执行 ./msg_server 即可。
#       全新部署会自动生成 etemsg.db 与 files/；带数据迁移则连同
#       etemsg.db、files/ 一起复制。
# =============================================================================
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== [1/3] 编译 msg_server ==="
export PATH="$PATH:/usr/local/go/bin"
export GOPROXY=https://goproxy.cn,direct
mkdir -p build
(cd src && go build -o ../build/msg_server .)

echo "=== [2/3] 生成新的 HTTPS 证书和私钥 ==="
mkdir -p build/certs
bash src/generate-certs.sh "$SCRIPT_DIR/build/certs"
chmod 600 build/certs/server.key

echo "=== [3/3] 同步证书更新脚本 ==="
cp src/generate-certs.sh build/generate-certs.sh
chmod +x build/generate-certs.sh

echo ""
echo "✅ 构建完成: ${SCRIPT_DIR}/build/"
echo "部署方式: 复制 build/ 目录到目标服务器，执行 ./msg_server"
echo "重新生成证书: cd build && ./generate-certs.sh"
ls -la build/
