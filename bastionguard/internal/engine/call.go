package engine

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// analyzeCall reduces one simple command: assignments, redirections, program
// resolution and per-program semantics.
func (e *Evaluator) analyzeCall(st *syntax.Stmt, c *syntax.CallExpr, origin Origin) {
	// Leading assignments without a command mutate session state.
	if len(c.Args) == 0 {
		for _, a := range c.Assigns {
			e.applyAssign(a)
		}
		return
	}

	// Inline prefix assignments (FOO=bar cmd) become session-visible vars,
	// mirroring bash scoping closely enough for static checks.
	for _, a := range c.Assigns {
		e.applyAssign(a)
	}

	prog := e.reduceWord(c.Args[0])
	args := e.reduceArgs(c.Args[1:])
	eff := &Effect{
		Origin:     origin,
		Background: st.Background || st.Disown,
	}

	// Resolve aliases first: `alias rmi='rm -i'` must still become rm.
	if !prog.dynamic {
		if expanded, ok := e.state.Aliases[prog.value]; ok {
			eff.AliasOf = prog.value
			// Aliases may embed flags/args; re-parse the alias text in context.
			e.expandAlias(expanded, args, st, origin)
			return
		}
		if body, ok := e.state.Functions[prog.value]; ok {
			eff.AliasOf = prog.value
			e.analyzeFunctionBody(prog.value, body, args, origin)
			return
		}
	}

	eff.Basename = basename(prog.value)
	eff.Resolved = e.resolveProgram(prog)
	eff.Dynamic = prog.dynamic
	if prog.dynamic {
		// A constructed program name (e.g. "$y -rf /", "${a}${b}") cannot be
		// resolved to any concrete binary: mark it so the fail-closed rule
		// FB-9002 catches the indirection rather than matching nothing.
		eff.Basename = "<dynamic-program>"
	}
	eff.Args = args
	e.classifyFlags(eff)
	e.collectRedirects(st, eff)
	e.detectInteractive(eff)
	e.detectBackground(eff)

	// Builtins mutate session state (cd/alias/export) and must run before
	// generic dispatch; they still produce an auditable effect. Redirection
	// writes (echo/printf > file) must be materialized first so later `source`
	// or `bash <file>` can recursively analyze the content.
	if !prog.dynamic && e.handleBuiltin(eff, st) {
		e.materializeWrites(eff)
		e.emit(st, eff)
		return
	}

	// Program-specific semantics (recursive payload analysis).
	e.dispatch(eff)
	e.materializeWrites(eff)

	e.emit(st, eff)
}

func (e *Evaluator) emit(st *syntax.Stmt, eff *Effect) {
	e.collected = append(e.collected, eff)
	if st != nil && e.stmtIndex != nil {
		e.stmtIndex[stmtKey(st)] = eff
	}
}

// resolveProgram mirrors PATH lookup conservatively; absolute/relative paths
// are kept as given, dynamic names stay empty and flagged.
func (e *Evaluator) resolveProgram(prog reducedWord) string {
	if prog.dynamic {
		return ""
	}
	v := prog.value
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		return filepath.Clean(v)
	}
	for _, dir := range strings.Split(e.envPath, ":") {
		cand := filepath.Join(dir, v)
		// We have no real FS metadata here; virtual FS marks known files.
		if _, ok := e.state.Files[cand]; ok {
			return cand
		}
	}
	// Conventional location for reporting; basename rules do not require
	// the path to exist.
	return filepath.Join("/usr/bin", v)
}

func (e *Evaluator) expandAlias(text string, rest []EffectArg, st *syntax.Stmt, origin Origin) {
	// Re-parse the alias body, then append the original trailing arguments as
	// raw shell words so the merged command goes through full reduction and
	// flag classification (rather than bolting args onto a finished effect).
	var rawArgs []string
	for _, a := range rest {
		if a.Raw != "" {
			rawArgs = append(rawArgs, a.Raw)
		} else {
			rawArgs = append(rawArgs, shellQuote(a.Value))
		}
	}
	merged := text
	if len(rawArgs) > 0 {
		merged = text + " " + strings.Join(rawArgs, " ")
	}
	pr := Parse(merged)
	if pr.Err != nil || pr.File == nil || len(pr.File.Stmts) == 0 {
		e.collected = append(e.collected, &Effect{Basename: "<bad-alias>", Dynamic: true, Origin: origin})
		return
	}
	for _, as := range pr.File.Stmts {
		if call, ok := as.Cmd.(*syntax.CallExpr); ok {
			e.analyzeCall(as, call, origin)
		} else {
			e.analyzeStmt(as, origin)
		}
	}
}

// shellQuote renders a value as a safe single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (e *Evaluator) analyzeFunctionBody(name, body string, rest []EffectArg, origin Origin) {
	pr := Parse(body)
	if pr.Err != nil || pr.File == nil {
		e.collected = append(e.collected, &Effect{Basename: "<bad-function>", Dynamic: true, Origin: origin})
		return
	}
	// Positional parameters $1.. take the call's arguments.
	saved := e.savePositional(rest)
	e.analyzeStmts(pr.File.Stmts, Origin{Kind: "function", Source: name, Snippet: firstLine(body)})
	e.restorePositional(saved)
}

func (e *Evaluator) savePositional(rest []EffectArg) map[string]string {
	saved := map[string]string{}
	for i, a := range rest {
		key := posKey(i + 1)
		saved[key] = e.state.Vars[key]
		e.state.Vars[key] = a.Value
	}
	return saved
}

func (e *Evaluator) restorePositional(saved map[string]string) {
	for k, v := range saved {
		if v == "" {
			delete(e.state.Vars, k)
		} else {
			e.state.Vars[k] = v
		}
	}
}

func posKey(i int) string {
	// 0..9 then nothing exotic; call sites needing >9 args are themselves
	// unusual enough to be covered by dynamic marking elsewhere.
	return string(rune('0' + i%10))
}

func (e *Evaluator) registerFunction(c *syntax.FuncDecl) {
	if c.Name == nil || c.Body == nil {
		return
	}
	var sb strings.Builder
	_ = e.printer.Print(&sb, c.Body)
	e.state.Functions[c.Name.Value] = sb.String()
}

func (e *Evaluator) applyDecl(c *syntax.DeclClause) {
	for _, a := range c.Args {
		if a.Name != nil {
			e.applyAssign(a)
		}
	}
}

func (e *Evaluator) applyAssign(a *syntax.Assign) {
	if a.Name == nil || a.Value == nil {
		return
	}
	rw := e.reduceWord(a.Value)
	if a.Append {
		e.state.Vars[a.Name.Value] += rw.value
		return
	}
	e.state.Vars[a.Name.Value] = rw.value
}

// classifyFlags normalizes flags and records structural switch effects.
func (e *Evaluator) classifyFlags(eff *Effect) {
	for _, a := range eff.Args {
		v := a.Value
		if v == "--" {
			continue
		}
		if strings.HasPrefix(v, "--") {
			// Long options stay whole: "--name" must never be split into
			// single letters or it would shadow real short flags like -n -a -m.
			name := v
			if i := strings.IndexByte(v, '='); i >= 0 {
				name = v[:i]
			}
			eff.Flags = append(eff.Flags, name)
			continue
		}
		if strings.HasPrefix(v, "-") && len(v) > 1 && !isNumeric(v) {
			// Split bundled short flags (-rf -> -r -f) for robust matching.
			for _, ch := range v[1:] {
				eff.Flags = append(eff.Flags, "-"+string(ch))
			}
		}
	}
	for _, f := range eff.Flags {
		switch f {
		case "-r", "-R", "--recursive":
			eff.Recursive = true
		}
	}
}

func (e *Evaluator) collectRedirects(st *syntax.Stmt, eff *Effect) {
	for _, r := range st.Redirs {
		red := Redirect{FD: 1, Op: r.Op.String()}
		if r.N != nil {
			red.FD = atoiSafe(r.N.Value)
		}
		if r.Word != nil {
			red.Path = e.resolvePath(e.reduceWord(r.Word))
			if isWriteOp(r.Op) && eff != nil {
				eff.Targets = appendUniquePath(eff.Targets, red.Path)
			}
		}
		if r.Hdoc != nil {
			rw := e.reduceWord(r.Hdoc)
			red.Heredoc = &Payload{Kind: "text", Text: rw.value, Dynamic: rw.dynamic}
		}
		if eff != nil {
			eff.Redirects = append(eff.Redirects, red)
		} else {
			// redirection-only statement still produces a truncation effect.
			synthetic := &Effect{
				Basename:  "<redirect>",
				Origin:    Origin{Kind: "line"},
				Redirects: []Redirect{red},
				Targets:   []ResolvedPath{red.Path},
			}
			e.collected = append(e.collected, synthetic)
			if st != nil && e.stmtIndex != nil {
				e.stmtIndex[stmtKey(st)] = synthetic
			}
		}
	}
}

func (e *Evaluator) analyzeRedirOnly(st *syntax.Stmt, origin Origin) {
	e.collectRedirects(st, nil)
}

func isWriteOp(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll:
		return true
	}
	return false
}

func (e *Evaluator) detectInteractive(eff *Effect) {
	switch eff.Basename {
	case "vim", "vi", "nano", "emacs", "ed",
		"mysql", "psql", "sqlite3", "redis-cli", "mongo", "mongosh",
		"python", "python3", "ipython", "perl", "ruby", "node",
		"bash", "sh", "zsh", "dash", "fish",
		"top", "htop", "less", "more", "man", "tail":
		// Interactive only when no -c / script / piped payload is present.
		if !e.hasPayloadFlag(eff) {
			eff.Interactive = true
		}
	}
}

func (e *Evaluator) hasPayloadFlag(eff *Effect) bool {
	for _, a := range eff.Args {
		if a.Value == "-c" || a.Value == "-e" || strings.HasPrefix(a.Value, "-c") {
			return true
		}
	}
	return eff.Payload != nil
}

func (e *Evaluator) detectBackground(eff *Effect) {
	switch eff.Basename {
	case "nohup", "setsid", "disown", "at", "batch", "crontab":
		eff.Background = true
	}
}

func appendUniquePath(in []ResolvedPath, p ResolvedPath) []ResolvedPath {
	key := p.Absolute
	if key == "" {
		key = p.Raw
	}
	for _, x := range in {
		k := x.Absolute
		if k == "" {
			k = x.Raw
		}
		if k == key {
			return in
		}
	}
	return append(in, p)
}

func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isNumeric(s string) bool {
	if s == "-" {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 1
		}
		n = n*10 + int(r-'0')
	}
	return n
}
