// Package engine turns shell input into resolved *effects* and evaluates them
// against the policy catalog. It never matches raw command strings.
package engine

import "bastionguard/internal/policy"

// Origin records where an effect came from, so denial messages can point at
// the exact construct (outer command, decoded payload, heredoc, remote hop…).
type Origin struct {
	Kind     string // "line" | "script-file" | "flag -c" | "heredoc" | "decode" | "stdin" | "remote-hop" | "repl"
	Source   string // path / decoder name / remote host
	Line     int
	Snippet  string // the original literal text, for human display only
}

// ResolvedPath is a filesystem target with information about how confidently
// we could resolve it.
type ResolvedPath struct {
	Raw       string // literal as typed
	Absolute  string // after in-session cwd/variable resolution; "" when dynamic
	Dynamic   bool   // contained an unresolvable variable/glob/cmd-subst
	Exists    bool   // known to virtual FS (e.g. script created earlier in session)
}

// EffectArg is one positional argument after static reduction.
type EffectArg struct {
	Value   string // reduced literal; may be "" when fully dynamic
	Dynamic bool   // true if any part could not be statically resolved
	Raw     string // original word text (display only)
}

// Effect is the semantic representation of one command invocation.
type Effect struct {
	// Program resolution.
	Basename string // e.g. "rm" (after alias/function/builtin resolution)
	Resolved string // full path when known, e.g. "/usr/bin/rm"
	AliasOf  string // non-empty when reached via an alias/function
	Dynamic  bool   // program name itself is constructed dynamically

	Args []EffectArg

	// Flags in normalized long form where known; always include raw spelling.
	Flags []string

	// Filesystem targets (redirections plus path-shaped positional args).
	Targets []ResolvedPath

	// Heredoc / -c / piped stdin payload.
	Payload      *Payload
	Redirects    []Redirect
	Interactive  bool // vim, psql, python REPL, bash without -c, top…
	Background   bool // &, nohup, setsid, disown, at/cron submission
	RemoteHost   string // non-empty for ssh/scp/psql -h style hops
	Recursive    bool
	UIDElevated  bool // sudo / setuid bit invocation / su

	Origin Origin

	// Inner effects produced by recursively analyzing payloads:
	// `echo b64 | base64 -d | sh`, `bash -c …`, `mysql < f.sql`, nested ssh.
	Inner []*Effect
}

// Payload describes content handed to an interpreter or written somewhere.
type Payload struct {
	Kind     string // "shell" | "sql" | "text" | "unknown"
	Text     string // resolved literal when statically known
	Dynamic  bool
	FromDecode string // decoder name when materialized via a pipe, e.g. "base64"
	FromFile   string // virtual-FS path when redirected from a file
}

// KKind returns the human label used in denial evidence.
func (p *Payload) KKind() string {
	if p == nil {
		return "无"
	}
	switch p.Kind {
	case "shell":
		return "Shell 脚本"
	case "sql":
		return "SQL 语句"
	case "text":
		return "代码文本"
	default:
		return "未知类型内容"
	}
}

// Redirect is a normalized I/O redirection.
type Redirect struct {
	Op     string // ">", ">>", ">|", "<", "&>", "<<", "<<-"
	FD     int    // target fd, 1 by default
	Path   ResolvedPath
	Heredoc *Payload
}

// MatchHit pairs a rule with the effect that triggered it and human evidence.
type MatchHit struct {
	Rule     *policy.Rule
	Effect   *Effect
	Evidence string // why it matched, in operator-readable language
}

// Decision is the verdict for one evaluation request.
type Decision struct {
	Allow      bool
	Hits       []MatchHit
	DenyReason string // assembled, translated explanation
}

// SessionState tracks everything a single interactive session has established,
// because the meaning of later commands depends on it (cwd, vars, aliases,
// functions, files written in-session, approved break-glass tokens).
type SessionState struct {
	CWD        string
	Vars       map[string]string
	Aliases    map[string]string
	Functions  map[string]string // name -> body source
	Files      map[string][]byte // virtual FS of in-session writes
	Approvals  map[string]bool   // rule ids approved via break-glass this session
	LastStatus int
}

func NewSessionState() *SessionState {
	return &SessionState{
		CWD:       "/",
		Vars:      map[string]string{},
		Aliases:   map[string]string{},
		Functions: map[string]string{},
		Files:     map[string][]byte{},
		Approvals: map[string]bool{},
	}
}
