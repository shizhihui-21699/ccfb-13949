package engine

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// handleBuiltin processes shell builtins that mutate session semantics. It
// returns true when the basename was consumed as a builtin.
func (e *Evaluator) handleBuiltin(eff *Effect, st *syntax.Stmt) bool {
	switch eff.Basename {
	case "cd", "pushd":
		e.builtinCD(eff)
		return true
	case "popd":
		return true
	case "alias":
		e.builtinAlias(eff)
		return true
	case "unalias":
		for _, a := range eff.Args {
			delete(e.state.Aliases, a.Value)
		}
		return true
	case "export", "declare", "local", "readonly", "typeset", "let":
		// applyDecl already handled DeclClause; bare export VAR=x arrives here.
		for _, a := range eff.Args {
			if i := strings.IndexByte(a.Value, '='); i > 0 {
				e.state.Vars[a.Value[:i]] = a.Value[i+1:]
			}
		}
		return true
	case "unset":
		for _, a := range eff.Args {
			delete(e.state.Vars, a.Value)
		}
		return true
	case "history":
		if hasFlag(eff, "-c") || hasFlag(eff, "--clear") {
			eff.Flags = append(eff.Flags, "--clear-history")
		}
		return true
	case "true", "false", "pwd", "echo", "printf", ":", "test", "[":
		return true
	case "exit", "logout", "return", "break", "continue", "shift", "wait", "jobs", "umask", "trap":
		return true
	}
	return false
}

func (e *Evaluator) builtinCD(eff *Effect) {
	target := "/"
	if len(eff.Args) > 0 {
		target = eff.Args[0].Value
		if eff.Args[0].Dynamic {
			// cd into dynamic path: cwd becomes unknowable, mark conservatively
			// by keeping old cwd but flagging subsequent relative paths dynamic.
			e.state.Vars["__BG_CWD_DYNAMIC__"] = "1"
			return
		}
	}
	if v, ok := e.state.Vars["HOME"]; ok && target == "~" {
		target = v
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(e.state.CWD, target)
	}
	e.state.CWD = filepath.Clean(target)
	delete(e.state.Vars, "__BG_CWD_DYNAMIC__")
}

func (e *Evaluator) builtinAlias(eff *Effect) {
	// alias name='value'  (also alias name=value without quotes). Keep the
	// raw RHS including quote structure so re-parsing reconstructs things like
	// `alias x='r''m'` (adjacent quoted segments concatenating to "rm").
	for _, a := range eff.Args {
		raw := a.Raw
		if raw == "" {
			raw = a.Value
		}
		i := strings.IndexByte(raw, '=')
		if i <= 0 {
			continue
		}
		name := raw[:i]
		val := raw[i+1:]
		e.state.Aliases[name] = val
	}
}

func hasFlag(eff *Effect, want string) bool {
	for _, f := range eff.Flags {
		if f == want {
			return true
		}
	}
	return false
}

// materializeWrites mirrors output redirections into the virtual FS so that a
// script written in-session (`cat > x.sh <<'EOF' … EOF`) can be recursively
// analyzed when later executed. Only statically known content is stored.
func (e *Evaluator) materializeWrites(eff *Effect) {
	// A heredoc anywhere on the statement feeds stdin; for `cat > f <<EOF`
	// that stdin is exactly the file content.
	var heredocContent []byte
	for _, r := range eff.Redirects {
		if r.Heredoc != nil && !r.Heredoc.Dynamic {
			heredocContent = []byte(r.Heredoc.Text)
		}
	}
	for _, r := range eff.Redirects {
		if r.Op != ">" && r.Op != ">|" && r.Op != "&>" && r.Op != ">>" {
			continue
		}
		abs := r.Path.Absolute
		if abs == "" || r.Path.Dynamic {
			continue
		}
		content := e.staticOutput(eff)
		if r.Heredoc != nil && !r.Heredoc.Dynamic {
			content = []byte(r.Heredoc.Text)
		} else if heredocContent != nil && eff.Basename == "cat" {
			// cat with no file args copies its heredoc stdin to the output.
			content = heredocContent
		}
		if content == nil {
			// Truncation still creates an empty file; record existence.
			if _, ok := e.state.Files[abs]; !ok {
				e.state.Files[abs] = []byte{}
			}
			continue
		}
		if r.Op == ">>" {
			e.state.Files[abs] = append(e.state.Files[abs], content...)
		} else {
			e.state.Files[abs] = content
		}
	}
	// tee writes its stdin to named files.
	if eff.Basename == "tee" && eff.Payload != nil && !eff.Payload.Dynamic {
		for _, t := range eff.Targets {
			if t.Absolute != "" {
				e.state.Files[t.Absolute] = []byte(eff.Payload.Text)
			}
		}
	}
}

func (e *Evaluator) staticOutput(eff *Effect) []byte {
	switch eff.Basename {
	case "echo":
		var b strings.Builder
		nl := true
		for _, a := range eff.Args {
			if a.Value == "-n" || a.Value == "-e" || a.Value == "-E" {
				if a.Value == "-n" {
					nl = false
				}
				continue
			}
			if a.Dynamic {
				return nil
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(a.Value)
		}
		if nl {
			b.WriteByte('\n')
		}
		return []byte(b.String())
	case "printf":
		// printf interprets backslash escapes in its format string, which is
		// exactly how heredoc-style script drops obfuscate newlines.
		if len(eff.Args) == 0 || eff.Args[0].Dynamic {
			return nil
		}
		return []byte(interpretEscapes(eff.Args[0].Value))
	}
	return nil
}

// interpretEscapes expands the small set of escapes used in script drops.
func interpretEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		case '\'':
			b.WriteByte('\'')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// snapshot captures mutable session state for rollback on denial.
type snapshot struct {
	cwd       string
	vars      map[string]string
	aliases   map[string]string
	functions map[string]string
	files     map[string][]byte
}

func (e *Evaluator) snapshotState() snapshot {
	return snapshot{
		cwd:       e.state.CWD,
		vars:      copyStringMap(e.state.Vars),
		aliases:   copyStringMap(e.state.Aliases),
		functions: copyStringMap(e.state.Functions),
		files:     copyByteMap(e.state.Files),
	}
}

func copyStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyByteMap(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		dup := make([]byte, len(v))
		copy(dup, v)
		out[k] = dup
	}
	return out
}

func (e *Evaluator) restoreState(s snapshot) {
	e.state.CWD = s.cwd
	e.state.Vars = s.vars
	e.state.Aliases = s.aliases
	e.state.Functions = s.functions
	e.state.Files = s.files
}
