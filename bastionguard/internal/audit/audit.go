// Package audit provides tamper-evident, append-only session auditing.
// Every decision (allow/deny/approval), raw input and reduced effect is
// written as one JSON line so SIEM tooling can consume it directly.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one auditable record.
type Event struct {
	TS        string   `json:"ts"`
	SessionID string   `json:"session_id"`
	User      string   `json:"user"`
	Target    string   `json:"target_host"`
	Kind      string   `json:"kind"` // line-allow | line-deny | approval | session-start | session-end | repl-deny
	RawInput  string   `json:"raw_input,omitempty"`
	RuleIDs   []string `json:"rule_ids,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Effects   []string `json:"effects,omitempty"` // human-readable effect summary
	BreakGlass bool    `json:"break_glass,omitempty"`
	ApprovalNote string `json:"approval_note,omitempty"`
}

// Auditor appends JSONL events and mirrors a human-readable session transcript.
type Auditor struct {
	mu       sync.Mutex
	jsonl    *os.File
	transcript *os.File
	dir      string

	// Session identity, auto-stamped on every record so callers can't omit it.
	sessionID string
	user      string
	target    string
}

// New opens (or creates) the per-session audit files under baseDir/<date>/.
func New(baseDir, sessionID, user, target string) (*Auditor, error) {
	day := time.Now().Format("2006-01-02")
	dir := filepath.Join(baseDir, day)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("audit dir: %w", err)
	}
	jf, err := os.OpenFile(filepath.Join(dir, sessionID+".jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	tf, err := os.OpenFile(filepath.Join(dir, sessionID+".transcript.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		_ = jf.Close()
		return nil, err
	}
	a := &Auditor{
		jsonl: jf, transcript: tf, dir: dir,
		sessionID: sessionID, user: user, target: target,
	}
	a.Record(Event{
		Kind: "session-start",
	})
	return a, nil
}

// Record writes one event atomically. Session identity is stamped automatically.
func (a *Auditor) Record(ev Event) {
	if ev.TS == "" {
		ev.TS = nowTS()
	}
	// Always inherit the session the auditor was created for.
	ev.SessionID = a.sessionID
	ev.User = a.user
	ev.Target = a.target
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(ev)
	b = append(b, '\n')
	_, _ = a.jsonl.Write(b)
	_ = a.jsonl.Sync()

	// Human-readable mirror for the incident responder.
	switch ev.Kind {
	case "line-deny", "repl-deny":
		fmt.Fprintf(a.transcript, "[%s] DENY  %s rules=%v\n        input: %s\n        reason: %s\n",
			ev.TS, ev.User, ev.RuleIDs, ev.RawInput, ev.Reason)
	case "approval":
		fmt.Fprintf(a.transcript, "[%s] BREAK-GLASS %s rules=%v note=%q\n", ev.TS, ev.User, ev.RuleIDs, ev.ApprovalNote)
	case "line-allow":
		fmt.Fprintf(a.transcript, "[%s] ALLOW %s: %s\n", ev.TS, ev.User, ev.RawInput)
	default:
		fmt.Fprintf(a.transcript, "[%s] %s %s\n", ev.TS, ev.Kind, ev.User)
	}
	_ = a.transcript.Sync()
}

// Close finalizes the session.
func (a *Auditor) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.jsonl != nil {
		_ = a.jsonl.Close()
	}
	if a.transcript != nil {
		_ = a.transcript.Close()
	}
}

func nowTS() string {
	return time.Now().UTC().Format(time.RFC3339)
}
