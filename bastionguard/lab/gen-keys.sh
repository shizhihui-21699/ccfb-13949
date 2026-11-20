#!/usr/bin/env bash
# 生成实验所需的全部 SSH 密钥（仅用于本地 lab，切勿用于生产）
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

mkdir -p keys

echo "[1/3] 堡垒机主机密钥 (bguard host key)"
[ -f keys/bguard_host_ed25519 ] || ssh-keygen -t ed25519 -N "" -C "bguard-lab" -f keys/bguard_host_ed25519

echo "[2/3] 运维人员密钥对"
[ -f keys/ops_ed25519 ] || ssh-keygen -t ed25519 -N "" -C "ops@lab" -f keys/ops_ed25519

echo "[3/3] 受管主机登录授权密钥"
cp keys/ops_ed25519.pub keys/authorized_keys

# linuxserver/openssh-server 通过 PUBLIC_KEY 环境变量注入公钥
PUB="$(cat keys/ops_ed25519.pub)"
cat > .env <<EOF
# 由 gen-keys.sh 自动生成，仅用于本地 lab
PUID=1000
PGID=1000
TZ=Asia/Shanghai
USER_NAME=ops
PASSWORD_ACCESS=false
PUBLIC_KEY=${PUB}
SUDO_ACCESS=false
EOF

cat <<EOF

密钥已生成在 $HERE/keys，环境变量写入 $HERE/.env:
  bguard_host_ed25519      堡垒机 SSH 主机私钥
  ops_ed25519 / .pub       运维登录密钥对
  authorized_keys          受管主机授权公钥副本

下一步: ./up.sh 构建并启动模拟主机
EOF
