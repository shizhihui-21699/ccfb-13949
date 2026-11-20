# BastionGuard 架构与设计说明

## 1. 数据流

```
运维键盘
   │  PTY 字节流
   ▼
sshd.Session.HandleInput
   │  行缓冲（Enter 才判定，Ctrl-U/C 处理，未输入完整不判）
   ▼
engine.Evaluator.EvaluateLine
   ├─ parser.Parse            mvdan/sh Bash 方言 → AST
   ├─ snapshotState           快照（拒绝时回滚）
   ├─ analyzeStmts            遍历 AST
   │    ├─ reduceWord         变量/切片/引号/glob/cmdsubst 静态归约
   │    ├─ analyzeCall        别名/函数/PATH 归约 → Effect
   │    ├─ dispatch           程序级语义（shell/ssh/db/find/decoder…）
   │    │    └─ 递归 effectsFromScript（-c、脚本文件、解码、远程载荷）
   │    ├─ linkPipelines      管道载荷沿生产者→消费者连接
   │    └─ materializeWrites  heredoc/重定向写入会话虚拟 FS
   ├─ judge                   Effect 树对规则目录匹配（含 inner 递归）
   └─ 拒绝则 restoreState
   ▼
Decision（allow / deny + 原因 + 命中规则）
   ├─ 允许 → 字节转发上游主机
   ├─ 拒绝 → 抑制 + 回显红色原因 + Ctrl-U 清远端缓冲 + 审计
   └─ break-glass → 授权规则 ID（带原因，全程审计）
```

## 2. 关键设计决策

### 2.1 为什么用真实 shell 解析器而不是正则
正则无法理解引号、嵌套、复合命令。`mvdan.cc/sh/v3` 产出完整 AST，
别名展开、`&&/||/|`、`if/for/case`、命令替换、进程替换、coproc 都有确定节点。
**所有分支都分析**——包括 `false && rm -rf /` 里"不会执行"的那一支，
因为静态检查的目标是意图，不是运行时分支结果。

### 2.2 会话状态与虚拟文件系统
后续命令的含义依赖前面建立的状态：`cd` 影响相对路径，`alias`/函数影响
程序归约，`cat > x.sh <<EOF` 写出的脚本要能被随后的 `bash x.sh` 递归分析。
`SessionState` 维护 CWD、变量、别名、函数和一个虚拟 FS（仅记录会话内写入）。
每次判定前快照，拒绝即回滚，保证被拦的输入不会"污染"后续判定。

### 2.3 静态分析的 fail-closed 边界
能静态确定的（字面量、已知变量、可解码的 base64）精确归约；
不能确定的（未知变量、命令替换结果、无密钥的 openssl、glob 展开、
完全动态的程序名）统一打 `Dynamic` 标记，由 FB-9xxx 兜底规则拒绝。
这是"宁可误拦不可漏放"的安全取舍，正常运维因很少动态构造命令而不受影响。

### 2.4 交互式程序的 raw 子模式
vim/mysql/python 等 REPL 一旦进入，输入不再是 shell 语法。会话切换到
`ModeRaw`：每条 Enter 提交的行用程序专属规则扫描（vim 的 `:!sh`、
mysql 的 DROP、python 的 pty.spawn），其余按键透传以保证编辑流畅。
检测到交互程序启动（无 -c/脚本参数的对应 basename）自动进入，退出时回 line 模式。

### 2.5 规则匹配的 AND/OR 语义
`has_flags` 是 AND（要求全部出现，如 `--remove` + 确认标志）；
`has_flags_any` 是 OR（等价变体，如 `--privileged` 或 `--cap-add=ALL`）。
路径支持精确/前缀/glob，动态目标命中敏感前缀时同样算匹配。

## 3. 已知边界与生产化待办

当前是可验证的参考实现，生产部署还需补：

1. **真实上游转发**：`serve.go` 现在是回环演示，生产要在握手后 dial 真实
   主机并调用 `Session.Pump`（接口已就绪），管理 host key 校验和目标白名单。
2. **强认证与角色**：`PublicKeyCallback` 实验室里接受任意密钥，生产需对接
   vault/IAM，把密钥映射到角色和可登录主机范围。
3. **虚拟 FS 与真实 FS 对齐**：当前只追踪会话内写入。生产可让 agent 上报
   主机真实文件元数据（是否存在、是否块设备、是否系统目录），提升路径判定精度。
4. **更复杂的混淆**：多层异构编码（gzip→base64→hex）、多态变量、
   `$'\x72\x6d'` ANSI-C 引号、IFS 分隔可继续扩展归约器；未知形态已由兜底规则收口。
5. **审计防篡改**：JSONL 当前本地落盘，生产应转发到只追加的远端日志服务
   并加签名/哈希链，防止主机被拿下后删日志。
6. **策略热加载**：规则文件变更通过 SIGHUP 或 watcher 重载，无需断连。
7. **PTY 行编辑边界**：Tab 补全、历史回溯（上下箭头）、多行 bracketed paste
   的缓冲需要在真实终端做更充分的兼容性测试。

## 4. 测试矩阵

- `internal/engine` 单测：19 类绕过 + 20 条正常命令 + 切片边界
- `internal/sshd` 单测：行拦截、raw 模式、break-glass、Ctrl-U、分片缓冲
- `test/bypass/cases.yaml`：77 样本语料（53 绕过 / 24 正常），`bguard corpus` 回归
- `lab/`：三台真实容器主机，SSH 登录验证模拟命令与规则端到端一致
- 基准：典型 3.7µs、混淆 7.9µs 每条
