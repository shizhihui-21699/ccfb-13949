package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"bastionguard/internal/audit"
	"bastionguard/internal/engine"
	"bastionguard/internal/policy"
	"bastionguard/internal/sshd"

	gossh "golang.org/x/crypto/ssh"
)

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	policyPath := fs.String("policy", "configs/default-policy.yaml", "策略 YAML 路径")
	listen := fs.String("listen", ":2222", "SSH 监听地址")
	auditDir := fs.String("audit-dir", "audit-data", "审计日志目录")
	hostKey := fs.String("host-key", "lab/host_key", "SSH 主机私钥(PEM)")
	upstream := fs.String("upstream", "", "上游主机 user@host:port（实验环境默认回环演示）")
	_ = fs.Parse(args)

	cat, err := policy.Load(*policyPath)
	if err != nil {
		fatal("加载策略: %v", err)
	}

	keyBytes, err := os.ReadFile(*hostKey)
	if err != nil {
		fatal("读取主机密钥 %s: %v（可用 lab/gen-keys.sh 生成）", *hostKey, err)
	}
	signer, err := gossh.ParsePrivateKey(keyBytes)
	if err != nil {
		fatal("解析主机密钥: %v", err)
	}

	cfg := sshd.ServerConfig(signer, func(key gossh.PublicKey) bool {
		// Lab: accept any presented key. Production maps key->role in a vault.
		return true
	})

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal("监听 %s: %v", *listen, err)
	}
	fmt.Fprintf(os.Stderr, "[bguard] 堡垒机已启动 listen=%s policy=%s upstream=%s\n",
		*listen, *policyPath, *upstream)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		_ = listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleConn(conn, cfg, cat, *auditDir, *upstream)
	}
}

func handleConn(nConn net.Conn, cfg *gossh.ServerConfig, cat *policy.Catalog, auditDir, upstream string) {
	defer nConn.Close()
	sshConn, chans, reqs, err := gossh.NewServerConn(nConn, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[bguard] 握手失败: %v\n", err)
		return
	}
	go gossh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(gossh.UnknownChannelType, "only session channels supported")
			continue
		}
		ch, reqs2, err := newCh.Accept()
		if err != nil {
			continue
		}
		go handleSession(sshConn, ch, reqs2, cat, auditDir, upstream)
	}
}

func handleSession(conn *gossh.ServerConn, ch gossh.Channel, reqs <-chan *gossh.Request,
	cat *policy.Catalog, auditDir, upstream string) {
	defer ch.Close()

	sessionID := conn.SessionID()
	user := conn.User()
	sid := fmt.Sprintf("%x-%d", sessionID[:8], os.Getpid())

	aud, err := audit.New(auditDir, sid, user, upstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[bguard] 审计初始化失败: %v\n", err)
		return
	}
	defer aud.Close()

	sess := sshd.NewSession(sid, user, upstream, cat, aud)

	// In this reference build the "upstream host" is modeled by an in-process
	// shell echo: the lab drives the same Session.HandleInput via tests and
	// the corpus runner. A production deployment dials the real host here and
	// calls sess.Pump(ch, ch, upstreamConn).
	for req := range reqs {
		switch req.Type {
		case "exec":
			var pl struct{ Command string }
			if err := gossh.Unmarshal(req.Payload, &pl); err == nil {
				dec, _ := engine.New(engine.NewSessionState(), cat, user).EvaluateLine(pl.Command)
				if dec.Allow {
					_ = req.Reply(true, nil)
					fmt.Fprintf(ch, "[bguard] 已放行(演示回环): %s\n", pl.Command)
				} else {
					_ = req.Reply(false, nil)
					fmt.Fprintf(ch, "\033[31m[bguard] 已拦截:\n%s\033[0m\n", dec.DenyReason)
				}
			}
		case "shell", "pty-req":
			_ = req.Reply(true, nil)
			fmt.Fprint(ch, "BastionGuard 语义管控会话（演示回环，输入 exit 退出）\r\n")
			// Loop reading operator keystrokes through the policy gate.
			buf := make([]byte, 4096)
			for {
				n, err := ch.Read(buf)
				if err != nil {
					return
				}
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				allowed := sess.HandleInput(chunk)
				if msg := sess.DenyMessage(); msg != "" {
					fmt.Fprintf(ch, "\r\n\033[31m[bguard] %s\033[0m\r\n", msg)
					continue
				}
				for _, line := range allowed {
					fmt.Fprint(ch, line)
				}
			}
		default:
			_ = req.Reply(true, nil)
		}
	}
}
