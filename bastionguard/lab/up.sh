#!/usr/bin/env bash
# 一键启动三台模拟受管主机，并在主机内准备规则引用的目录
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"

echo "[1/4] 生成密钥（如尚未生成）"
./gen-keys.sh >/dev/null

echo "[2/4] 构建模拟主机镜像"
docker compose build

echo "[3/4] 启动 app-01 / db-01 / web-01"
docker compose up -d

echo "[4/4] 等待 sshd 就绪"
for port in 2201 2202 2203; do
  for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then break; fi
    sleep 1
  done
done

docker compose ps
cat <<EOF

模拟主机已启动:
  app-01  ssh -p 2201 -i keys/ops_ed25519 ...@127.0.0.1
  db-01   ssh -p 2202
  web-01  ssh -p 2203

运行端到端验证: ./e2e-demo.sh
语料库回归:     go run ./cmd/bguard corpus
停止环境:       docker compose down
EOF
