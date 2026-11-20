# BastionGuard — 语义级堡垒机命令管控

传统堡垒机用**字符串匹配**过滤命令，换个别名、拆成变量、写进脚本、套层
base64 就全部绕过。BastionGuard 用 Go 重做命令管控，在命令**真正生效之前**
按它在服务器上**实际会产生的效果**判定，而不是看字面。

## 核心思路：从"匹配字符串"到"判定效果"

每条输入先经过 Bash 语法解析（`mvdan.cc/sh/v3`），再做**静态语义归约**：

1. **别名/函数展开** —— `alias c='rm -rf /etc'; c` 归约成真实的 `rm`
2. **变量求值** —— `$D`、`${x:1:2}` 切片、`${a:-default}` 在会话状态上求值
3. **脚本/载荷递归** —— heredoc 写的脚本、`bash -c`、`source` 进入虚拟 FS 后递归分析
4. **编码解码** —— `base64 -d` 静态解码后继续分析；解不出的（openssl/xxd）按 fail-closed
5. **管道连接** —— `echo b64 | base64 -d | sh` 沿管道把载荷还原成最终命令
6. **远程/提权包裹** —— `ssh host '...'`、`sudo ...`、`docker exec ...` 内部命令同样过规则
7. **动态构造兜底** —— 程序名/参数无法静态还原时（`$TOOL $ARG`），默认拒绝

归约产出的是结构化 **Effect**（程序、标志、目标路径、载荷、是否交互/后台/远程），
规则只匹配 Effect，永远不碰原始字符串。

## 能力覆盖

| 要求 | 实现位置 |
|------|----------|
| 交互式编辑器（vim/nano shell 逃逸） | `engine.ScanInteractiveLine` + PTY raw 子模式 |
| 远程执行（ssh/scp/rsync） | `handleSSH` 递归分析远程载荷、隧道标志识别 |
| 管道 | `pipeline.go` 还原生产者→消费者载荷 |
| 后台任务（nohup/&/at/cron/setsid） | `handleJobWrapper` 递归、Background 标记 |
| 拦截时说明原因 | 裁决输出规则 ID + 语义证据 + 归约链 + break-glass 指引 |
| 正常运维流畅度 | 典型命令 3.7µs/次（见基准测试），无网络外呼 |

## 默认高危清单（十大类，见 configs/default-policy.yaml）

| 前缀 | 类别 | 示例 |
|------|------|------|
| DG-1xxx | 数据销毁 | 删库目录、DROP/TRUNCATE、find 批量删、截断系统文件 |
| DK-2xxx | 磁盘销毁 | dd 写裸盘、mkfs、wipefs、/dev/zero 占满、分区表 |
| AU-3xxx | 审计篡改 | 停 auditd、清日志、history -c、auditctl -D、关堡垒机 agent |
| AV-4xxx | 可用性 | 关机重启、停关键服务、kill -9 -1、清防火墙 |
| PR-5xxx | 提权账号 | 加 sudo 账号、改 sudoers、SUID 后门、改密码 |
| NE-6xxx | 网络外连 | 反弹 shell、nc -e、SSH 隧道、curl\|bash、数据外传 |
| PK-7xxx | 软件包生命周期 | remove/purge 卸载、-y 跳过确认 |
| CT-8xxx | 容器编排 | 特权容器、docker exec 高危、prune 卷、kubectl delete |
| KN-9xxx | 内核 | 模块加载、sysctl -w、写 /proc/sys |
| SC-10xxx | 定时任务 | crontab 植入/删除、at 后台任务 |
| FB-9xxx | 兜底 | 无法静态解析的动态构造，fail-closed |

每条规则有三种动作：`deny`（直接拦）、`approve`（break-glass 审批后放行）、
`warn`（放行但高亮审计）。

## 快速开始

```bash
# 1. 跑全部单测 + 绕过语料库（77 个样本，含 53 绕过 + 24 正常）
go test ./...
go run ./cmd/bguard corpus

# 2. 离线检查一条命令，看语义归约过程和拦截原因
go run ./cmd/bguard check --cmd 'echo cm0gLXJmIC92YXIvbGliL215c3FsCg== | base64 -d | sh'

# 3. 起三台模拟主机（app-01/db-01/web-01，容器内带模拟 systemctl/mysql/auditctl）
cd lab && ./up.sh
cd .. && ./lab/e2e-demo.sh
```

## 目录结构

```
cmd/bguard/            CLI：serve(SSH代理) / check(离线) / corpus(语料回归)
internal/policy/       规则模型 + YAML 加载
internal/engine/       语法解析、语义归约、Effect 模型、规则判定（核心）
internal/audit/        JSONL + 可读 transcript 双写审计
internal/sshd/         SSH 代理会话、行缓冲、PTY raw 模式、break-glass
configs/               默认高危策略清单
test/bypass/           绕过样本语料库（cases.yaml）
lab/                   三台模拟主机的 Docker 实验环境
docs/                  架构与设计说明
```

## 设计原则

- **Fail-closed**：无法静态判定真实效果时默认拒绝，宁可误拦不可漏放
- **判定前不改状态**：一条输入被拒后，它产生的变量/别名/文件变更全部回滚
- **全程可审计**：每次放行、拦截、break-glass 都落 JSONL，附原始输入和归约证据
- **规则与引擎解耦**：新增高危模式只改 YAML，不动引擎代码
