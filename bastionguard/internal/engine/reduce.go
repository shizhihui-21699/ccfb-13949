package engine

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// reducedWord is the static reduction of a shell word.
type reducedWord struct {
	value   string // literal value when !dynamic; best-effort concatenation otherwise
	dynamic bool   // any part could not be fully resolved at check time
	parts   []partNote
}

type partNote struct {
	text    string
	dynamic bool
	kind    string // lit, sq, dq, var, cmdsub, arith, glob
}

// reduceWord performs static expansion against the in-session state. It mirrors
// what bash would do for the cases an attacker abuses: vars, ${modifiers},
// quotes, globs and nested command substitution.
func (e *Evaluator) reduceWord(w *syntax.Word) reducedWord {
	rw := reducedWord{}
	for _, p := range w.Parts {
		rw.parts = append(rw.parts, e.reducePart(p)...)
	}
	var b strings.Builder
	for _, p := range rw.parts {
		b.WriteString(p.text)
		if p.dynamic {
			rw.dynamic = true
		}
	}
	rw.value = b.String()
	return rw
}

func (e *Evaluator) reducePart(p syntax.WordPart) []partNote {
	switch x := p.(type) {
	case *syntax.Lit:
		return []partNote{{text: x.Value, kind: "lit"}}

	case *syntax.SglQuoted:
		return []partNote{{text: x.Value, kind: "sq"}}

	case *syntax.DblQuoted:
		var out []partNote
		for _, q := range x.Parts {
			out = append(out, e.reducePart(q)...)
		}
		return out

	case *syntax.ParamExp:
		return e.reduceParam(x)

	case *syntax.CmdSubst:
		// The substitution's own effects are still policy-checked (nested),
		// and the resulting word is always dynamic at check time.
		snippet := e.nodeText(x)
		e.analyzeStmts(x.Stmts, Origin{Kind: "cmdsub", Source: snippet, Line: int(x.Pos().Line())})
		return []partNote{{text: "$(...)", dynamic: true, kind: "cmdsub"}}

	case *syntax.ArithmExp:
		// Arithmetic can include command substitution / variable values; mark
		// dynamic rather than guess numbers.
		return []partNote{{text: "$((...))", dynamic: true, kind: "arith"}}

	case *syntax.ProcSubst:
		e.analyzeStmts(x.Stmts, Origin{Kind: "cmdsub", Source: e.nodeText(x)})
		return []partNote{{text: ">(...)", dynamic: true, kind: "cmdsub"}}

	case *syntax.ExtGlob:
		return []partNote{{text: x.Pattern.Value, dynamic: true, kind: "glob"}}
	}
	return []partNote{{text: "", dynamic: true, kind: "unknown"}}
}

func (e *Evaluator) reduceParam(px *syntax.ParamExp) []partNote {
	if px.Param == nil {
		// ${!prefix*}, nested zsh forms etc.
		return []partNote{{text: "${...}", dynamic: true, kind: "var"}}
	}
	name := px.Param.Value
	val, known := e.state.Vars[name]

	// Special parameters that are environment-derived.
	switch name {
	case "HOME":
		val, known = e.lookupHome()
	case "PWD":
		val, known = e.state.CWD, true
	case "USER", "LOGNAME":
		val, known = e.envUser, true
	case "PATH":
		val, known = e.envPath, true
	case "IFS", "SHELL", "TERM":
		known = true // harmless defaults; value not security relevant
	case "RANDOM", "SECONDS", "LINENO", "BASHPID", "PPID", "!":
		return []partNote{{text: "$" + name, dynamic: true, kind: "var"}}
	}

	// ${#a} length: static when value known; never dangerous on its own.
	if px.Length {
		if known {
			return []partNote{{text: itoa(len(val)), kind: "var"}}
		}
		return []partNote{{text: "${#}", dynamic: true, kind: "var"}}
	}

	if px.Exp != nil {
		return e.reduceExpansion(px, name, val, known)
	}
	if px.Slice != nil || px.Repl != nil || px.Names != 0 || px.Index != nil {
		if !known {
			return []partNote{{text: "${" + name + "..}", dynamic: true, kind: "var"}}
		}
		// Known source variable: compute the common ${a:offset:length} form
		// statically, which is exactly the slicing trick used to hide command
		// names (e.g. x=armless; ${x:3:2} -> "rm").
		if px.Slice != nil {
			if s := evalStaticSlice(val, px.Slice, e); s != nil {
				return []partNote{{text: *s, kind: "var"}}
			}
		}
		// Other modifiers still derive from a known var; expose the value but
		// keep dynamic flag so path rules stay honest.
		return []partNote{{text: val, dynamic: true, kind: "var"}}
	}
	if !known {
		// Unset variable expands to empty but its future runtime value is
		// unknown: mark dynamic so rules fail closed.
		return []partNote{{text: "", dynamic: true, kind: "var"}}
	}
	return []partNote{{text: val, kind: "var"}}
}

func (e *Evaluator) reduceExpansion(px *syntax.ParamExp, name, val string, known bool) []partNote {
	op := px.Exp.Op
	arg := ""
	dyn := false
	if px.Exp.Word != nil {
		rw := e.reduceWord(px.Exp.Word)
		arg = rw.value
		dyn = rw.dynamic
	}
	switch op {
	case syntax.DefaultUnsetOrNull, syntax.DefaultUnset: // ${a:-b} / ${a-b}
		if known && val != "" {
			return []partNote{{text: val, kind: "var"}}
		}
		return []partNote{{text: arg, dynamic: dyn, kind: "var"}}
	case syntax.AlternateUnsetOrNull, syntax.AlternateUnset: // ${a:+b}
		if known && val != "" {
			return []partNote{{text: arg, dynamic: dyn, kind: "var"}}
		}
		return []partNote{{kind: "var"}}
	case syntax.ErrorUnsetOrNull, syntax.ErrorUnset: // ${a:?b}
		if known && val != "" {
			return []partNote{{text: val, kind: "var"}}
		}
		// Would abort at runtime; treat as dynamic.
		return []partNote{{text: "", dynamic: true, kind: "var"}}
	case syntax.AssignUnsetOrNull, syntax.AssignUnset: // ${a:=b}
		if !known || val == "" {
			if !dyn {
				e.state.Vars[name] = arg
			}
			return []partNote{{text: arg, dynamic: dyn, kind: "var"}}
		}
		return []partNote{{text: val, kind: "var"}}
	case syntax.RemSmallPrefix, syntax.RemLargePrefix: // ${a#p} ${a##p}
		if !known {
			return []partNote{{text: "", dynamic: true, kind: "var"}}
		}
		return []partNote{{text: stripPattern(val, arg, op == syntax.RemLargePrefix, true), dynamic: dyn, kind: "var"}}
	case syntax.RemSmallSuffix, syntax.RemLargeSuffix: // ${a%p} ${a%%p}
		if !known {
			return []partNote{{text: "", dynamic: true, kind: "var"}}
		}
		return []partNote{{text: stripPattern(val, arg, op == syntax.RemLargeSuffix, false), dynamic: dyn, kind: "var"}}
	case syntax.UpperFirst, syntax.UpperAll, syntax.LowerFirst, syntax.LowerAll:
		if !known {
			return []partNote{{text: "", dynamic: true, kind: "var"}}
		}
		if op == syntax.UpperFirst || op == syntax.UpperAll {
			return []partNote{{text: strings.ToUpper(val), kind: "var"}}
		}
		return []partNote{{text: strings.ToLower(val), kind: "var"}}
	}
	return []partNote{{text: val, dynamic: true, kind: "var"}}
}

// reduceArgs turns a call's words into normalized effect arguments, recording
// any glob/unquoted pattern on the note list.
func (e *Evaluator) reduceArgs(words []*syntax.Word) []EffectArg {
	out := make([]EffectArg, 0, len(words))
	for _, w := range words {
		rw := e.reduceWord(w)
		note := EffectArg{Value: rw.value, Dynamic: rw.dynamic, Raw: w.Lit()}
		for _, p := range rw.parts {
			if p.kind == "glob" {
				note.Dynamic = true
			}
		}
		out = append(out, note)
	}
	return out
}

// resolvePath maps a word to a ResolvedPath relative to session CWD.
func (e *Evaluator) resolvePath(rw reducedWord) ResolvedPath {
	p := ResolvedPath{Raw: rw.value, Dynamic: rw.dynamic}
	if rw.dynamic {
		p.Absolute = ""
		_, p.Exists = e.state.Files[p.Raw]
		return p
	}
	abs := rw.value
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(e.state.CWD, abs)
	}
	abs = filepath.Clean(abs)
	p.Absolute = abs
	_, p.Exists = e.state.Files[abs]
	return p
}

func (e *Evaluator) lookupHome() (string, bool) {
	if h := e.state.Vars["HOME"]; h != "" {
		return h, true
	}
	return "/root", true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// stripPattern implements a conservative ${#}/% glob strip (no full extglob).
func stripPattern(s, pat string, greedy, prefix bool) string {
	if pat == "" {
		return s
	}
	match := func(p, sub string) bool {
		ok, _ := filepath.Match(p, sub)
		return ok
	}
	if prefix {
		// Try longest/shortest prefix matching pattern.
		limit := len(s)
		if !greedy {
			limit = 1
		}
		best := -1
		for n := 0; n <= len(s); n++ {
			if match(pat, s[:n]) {
				best = n
				if !greedy {
					break
				}
			}
		}
		_ = limit
		if best >= 0 {
			return s[best:]
		}
		return s
	}
	best := -1
	for n := 0; n <= len(s); n++ {
		if match(pat, s[n:]) {
			best = n
			if greedy {
				break
			}
		}
	}
	if best >= 0 {
		return s[:best]
	}
	return s
}

// evalStaticSlice resolves ${var:offset:length} when both bounds are literal
// integers; returns nil when any bound is itself dynamic.
func evalStaticSlice(val string, sl *syntax.Slice, e *Evaluator) *string {
	offPtr := evalArithmLit(sl.Offset, e)
	if offPtr == nil {
		return nil
	}
	off := *offPtr
	// Negative offset is relative to the end.
	if off < 0 {
		off += len(val)
	}
	if off < 0 {
		off = 0
	}
	if off > len(val) {
		s := ""
		return &s
	}
	end := len(val)
	if sl.Length != nil {
		lenPtr := evalArithmLit(sl.Length, e)
		if lenPtr == nil {
			return nil
		}
		length := *lenPtr
		// Negative length means "stop that many chars from the end".
		if length < 0 {
			end = len(val) + length
			if end < off {
				s := ""
				return &s
			}
		} else {
			end = off + length
			if end > len(val) {
				end = len(val)
			}
		}
	}
	s := val[off:end]
	return &s
}

// evalArithmLit evaluates arithmetic that is just a literal integer word.
func evalArithmLit(expr syntax.ArithmExpr, e *Evaluator) *int {
	w, ok := expr.(*syntax.Word)
	if !ok {
		return nil
	}
	rw := e.reduceWord(w)
	if rw.dynamic || rw.value == "" {
		return nil
	}
	neg := false
	s := rw.value
	if s[0] == '-' {
		neg = true
		s = s[1:]
	} else if s[0] == '+' {
		s = s[1:]
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return nil
		}
		n = n*10 + int(r-'0')
	}
	if neg {
		n = -n
	}
	return &n
}
