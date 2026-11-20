package sshd_test

import (
	"path/filepath"
	"strings"
	"testing"

	"bastionguard/internal/audit"
	"bastionguard/internal/policy"
	"bastionguard/internal/sshd"
)

func newTestSession(t *testing.T) *sshd.Session {
	t.Helper()
	cat, err := policy.Load("../../configs/default-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	aud, err := audit.New(filepath.Join(dir, "audit"), "sess-1", "ops", "db-01")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(aud.Close)
	return sshd.NewSession("sess-1", "ops", "db-01", cat, aud)
}

func feed(s *sshd.Session, line string) []string {
	return s.HandleInput(append([]byte(line), '\r'))
}

func TestLineAllowAndDeny(t *testing.T) {
	s := newTestSession(t)

	if got := feed(s, "ls -la"); len(got) != 1 {
		t.Fatalf("正常命令应转发，got=%v", got)
	}
	if got := feed(s, "rm -rf /var/lib/mysql"); len(got) != 0 {
		t.Fatalf("高危命令必须拦截，got=%v", got)
	}
	if !strings.Contains(s.DenyMessage(), "DG-") {
		t.Errorf("拦截原因应包含规则ID，got=%q", s.DenyMessage())
	}
}

func TestObfuscatedLineBlocked(t *testing.T) {
	s := newTestSession(t)
	// alias then invoke: both lines share session state.
	feed(s, "alias c='rm -rf /etc'")
	if got := feed(s, "c"); len(got) != 0 {
		t.Fatalf("别名包裹的删除必须拦截，got=%v", got)
	}
}

func TestBreakGlass(t *testing.T) {
	s := newTestSession(t)
	// approve-class rule (shred) needs break-glass; first deny it.
	if got := feed(s, "shred /data/secret.bin"); len(got) != 0 {
		t.Fatalf("approve 类规则默认应拦截")
	}
	// Missing reason -> rejected (token line not forwarded, deny message set).
	if got := feed(s, "!break-glass DG-1007"); len(got) != 0 {
		t.Fatalf("缺少审批原因应拒绝，令牌行不得转发")
	}
	if !strings.Contains(s.DenyMessage(), "审批原因") {
		t.Fatalf("应提示缺少审批原因，got=%q", s.DenyMessage())
	}
	// Valid approval.
	if got := feed(s, "!break-glass DG-1007 值班窗口清理测试文件工单号4521"); len(got) != 0 {
		t.Fatalf("break-glass 令牌行本身不应转发给 shell")
	}
	// Same rule now allowed for this session.
	if got := feed(s, "shred /data/secret.bin"); len(got) != 1 {
		t.Fatalf("审批后同规则应放行，got=%v", got)
	}
}

func TestRawModeInteractive(t *testing.T) {
	s := newTestSession(t)
	// Launching mysql REPL switches to raw mode.
	feed(s, "mysql appdb")
	if s.Mode() != sshd.ModeRaw {
		t.Fatalf("进入 mysql 后应为 raw 模式")
	}
	// Benign query passes.
	if got := feed(s, "SELECT 1;"); len(got) != 1 {
		t.Fatalf("普通查询应放行")
	}
	// Destructive query inside REPL is blocked.
	if got := feed(s, "DROP TABLE orders;"); len(got) != 0 {
		t.Fatalf("REPL 内 DROP 必须拦截，got=%v", got)
	}
	s.ExitRaw()
	if s.Mode() != sshd.ModeLine {
		t.Fatalf("退出后应回到 line 模式")
	}
}

func TestPartialLineBuffering(t *testing.T) {
	s := newTestSession(t)
	// Type a dangerous command in chunks without Enter: nothing forwarded.
	if got := s.HandleInput([]byte("rm -rf /v")); len(got) != 0 {
		t.Fatalf("未按回车不应有转发，got=%v", got)
	}
	if got := s.HandleInput(append([]byte("ar/lib/mysql"), '\r')); len(got) != 0 {
		t.Fatalf("完整高危命令在回车时应拦截，got=%v", got)
	}
}

func TestCtrlUClearsBuffer(t *testing.T) {
	s := newTestSession(t)
	s.HandleInput([]byte("rm -rf /etc"))
	// Ctrl-U then Enter: buffer discarded, empty line forwarded.
	got := s.HandleInput([]byte{0x15, '\r'})
	if len(got) != 2 {
		t.Fatalf("Ctrl-U 和回车都应透传，got=%v", got)
	}
}
