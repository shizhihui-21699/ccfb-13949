// Package sshd implements the bastion SSH proxy. It terminates the operator's
// SSH connection, runs every command line through the semantic engine before
// forwarding it to the upstream host, and enforces decisions inline.
package sshd

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"

	"bastionguard/internal/audit"
	"bastionguard/internal/engine"
	"bastionguard/internal/policy"

	gossh "golang.org/x/crypto/ssh"
)

// LineMode controls how input bytes are inspected.
type LineMode int

const (
	ModeLine LineMode = iota // normal shell: inspect at Enter
	ModeRaw                  // inside vim/psql/python: scan each submitted line, pass through otherwise
)

// Session is one live operator connection.
type Session struct {
	ID        string
	User      string
	Target    string
	engine    *engine.Evaluator
	auditor   *audit.Auditor
	catalog   *policy.Catalog

	mu       sync.Mutex
	mode     LineMode
	rawProg  string // program foregrounded in raw mode
	lineBuf  bytes.Buffer
	pending  bool // a line is currently being assembled

	lastDeny    string
	lastDenyIDs []string
}

// NewSession wires engine + audit for one connection.
func NewSession(id, user, target string, cat *policy.Catalog, aud *audit.Auditor) *Session {
	return &Session{
		ID:      id,
		User:    user,
		Target:  target,
		engine:  engine.New(engine.NewSessionState(), cat, user),
		auditor: aud,
		catalog: cat,
		mode:    ModeLine,
	}
}

// HandleInput processes bytes coming from the operator's PTY. It returns the
// bytes that may be forwarded upstream: denied input is replaced with a
// line-kill (Ctrl-U) so the remote shell never executes it.
func (s *Session) HandleInput(data []byte) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var forwarded []string
	for _, b := range data {
		switch b {
		case '\r', '\n':
			line := s.lineBuf.String()
			s.lineBuf.Reset()
			if s.mode == ModeRaw {
				if s.handleRawLine(line) {
					forwarded = append(forwarded, string(b))
				}
				continue
			}
			if s.handleLine(line) {
				forwarded = append(forwarded, line+string(b))
			}
		case 0x15: // Ctrl-U: operator clears line themselves
			s.lineBuf.Reset()
			forwarded = append(forwarded, string(b))
		case 0x03: // Ctrl-C
			s.lineBuf.Reset()
			forwarded = append(forwarded, string(b))
		default:
			s.lineBuf.WriteByte(b)
		}
	}
	return forwarded
}

// handleLine returns true when the line is allowed upstream.
func (s *Session) handleLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}

	// Break-glass flow: operator approves a previously blocked rule.
	if strings.HasPrefix(trimmed, s.catalog.BreakGlassToken) {
		return s.handleBreakGlass(trimmed)
	}

	dec, effects := s.engine.EvaluateLine(line)
	summary := summarizeEffects(effects)

	if dec.Allow {
		s.auditor.Record(audit.Event{
			SessionID: s.ID, User: s.User, Target: s.Target,
			Kind: "line-allow", RawInput: line, Effects: summary,
		})
		s.detectRawTransition(effects)
		return true
	}

	ids := make([]string, 0, len(dec.Hits))
	for _, h := range dec.Hits {
		ids = append(ids, h.Rule.ID)
	}
	s.auditor.Record(audit.Event{
		SessionID: s.ID, User: s.User, Target: s.Target,
		Kind: "line-deny", RawInput: line, RuleIDs: ids,
		Reason: dec.DenyReason, Effects: summary,
	})
	s.lastDeny = dec.DenyReason
	s.lastDenyIDs = ids
	return false
}

// handleRawLine scans a line submitted inside an interactive program.
func (s *Session) handleRawLine(line string) bool {
	dec := s.engine.ScanInteractiveLine(s.rawProg, line)
	if dec.Allow {
		return true
	}
	s.auditor.Record(audit.Event{
		SessionID: s.ID, User: s.User, Target: s.Target,
		Kind: "repl-deny", RawInput: line, Reason: dec.DenyReason,
	})
	s.lastDeny = dec.DenyReason
	return false
}

// handleBreakGlass grants a one-time rule approval with an audited reason.
func (s *Session) handleBreakGlass(line string) bool {
	rest := strings.TrimSpace(strings.TrimPrefix(line, s.catalog.BreakGlassToken))
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		s.lastDeny = "break-glass 用法: " + s.catalog.BreakGlassToken + " <规则ID> <审批原因>"
		return false
	}
	ruleID := fields[0]
	note := strings.Join(fields[1:], " ")
	if note == "" {
		s.lastDeny = "break-glass 必须提供审批原因，该原因会写入审计日志"
		return false
	}
	if !s.engine.GrantApproval(ruleID) {
		s.lastDeny = "规则ID不存在: " + ruleID
		return false
	}
	s.auditor.Record(audit.Event{
		SessionID: s.ID, User: s.User, Target: s.Target,
		Kind: "approval", RuleIDs: []string{ruleID},
		ApprovalNote: note, BreakGlass: true,
	})
	s.lastDeny = ""
	return false // the token line itself is never forwarded as a shell command
}

// detectRawTransition enters raw mode when an interactive program is launched.
func (s *Session) detectRawTransition(effects []*engine.Effect) {
	for _, ef := range effects {
		if ef.Interactive {
			s.mode = ModeRaw
			s.rawProg = ef.Basename
			return
		}
	}
}

// ExitRaw is called when the foreground interactive program ends.
func (s *Session) ExitRaw() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = ModeLine
	s.rawProg = ""
	s.lineBuf.Reset()
}

// DenyMessage returns the explanation queued for the most recent denial.
func (s *Session) DenyMessage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastDeny
}

// Mode reports the current input mode (for tests/metrics).
func (s *Session) Mode() LineMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

func summarizeEffects(effects []*engine.Effect) []string {
	var out []string
	var walk func([]*engine.Effect, string)
	walk = func(es []*engine.Effect, prefix string) {
		for _, ef := range es {
			out = append(out, prefix+ef.Basename+effectTail(ef))
			if len(ef.Inner) > 0 {
				walk(ef.Inner, prefix+"  ")
			}
		}
	}
	walk(effects, "")
	return out
}

func effectTail(ef *engine.Effect) string {
	var b strings.Builder
	if ef.UIDElevated {
		b.WriteString(" [sudo]")
	}
	if ef.RemoteHost != "" {
		b.WriteString(" ->" + ef.RemoteHost)
	}
	if len(ef.Targets) > 0 {
		var ts []string
		for _, t := range ef.Targets {
			if t.Absolute != "" {
				ts = append(ts, t.Absolute)
			} else {
				ts = append(ts, t.Raw+"?")
			}
		}
		b.WriteString(" " + strings.Join(ts, ","))
	}
	if ef.Dynamic {
		b.WriteString(" [dynamic]")
	}
	return b.String()
}

// Pump wires the proxy between operator and upstream connections. The
// upstream writer receives only cleared input; denied lines are suppressed and
// the operator gets an explanation plus a Ctrl-U to discard their buffer.
func (s *Session) Pump(operator io.Reader, operatorOut io.Writer, upstream io.ReadWriter) error {
	buf := make([]byte, 4096)
	var wg sync.WaitGroup

	// Upstream -> operator (pass through).
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(operatorOut, upstream)
	}()

	// Operator -> upstream (policy gated).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			n, err := operator.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				allowed := s.HandleInput(chunk)
				if msg := s.DenyMessage(); msg != "" {
					fmt.Fprintf(operatorOut, "\r\n\033[31m[bguard] %s\033[0m\r\n", msg)
					_, _ = upstream.Write([]byte{0x15}) // Ctrl-U clears remote buffer
					s.clearDeny()
				}
				for _, line := range allowed {
					_, _ = io.WriteString(upstream, line)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

func (s *Session) clearDeny() {
	s.mu.Lock()
	s.lastDeny = ""
	s.mu.Unlock()
}

// ServerConfig builds the SSH server config using an authorized-keys callback.
func ServerConfig(signer gossh.Signer, auth func(key gossh.PublicKey) bool) *gossh.ServerConfig {
	cfg := &gossh.ServerConfig{}
	cfg.AddHostKey(signer)
	cfg.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if auth(key) {
			return &gossh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
		}
		return nil, fmt.Errorf("unauthorized key for %s", conn.User())
	}
	return cfg
}
