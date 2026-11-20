package engine

import (
	"fmt"
	"strings"

	"bastionguard/internal/policy"

	"mvdan.cc/sh/v3/syntax"
)

// Evaluator reduces parsed shell to effects and applies the catalog.
type Evaluator struct {
	state   *SessionState
	catalog *policy.Catalog
	printer *syntax.Printer

	// Host environment the bastion injects (read-only facts).
	envUser  string
	envPath  string
	cwdRoots map[string]bool // mount points considered "system" paths

	collected  []*Effect // all effects in the current evaluation unit
	stmtIndex  map[uint64]*Effect
}

// New builds an evaluator. catalog may be nil for effect-only inspection/tests.
func New(state *SessionState, cat *policy.Catalog, user string) *Evaluator {
	return &Evaluator{
		state:    state,
		catalog:  cat,
		printer:  syntax.NewPrinter(syntax.Indent(0)),
		envUser:  defaultStr(user, "ops"),
		envPath:  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		cwdRoots: map[string]bool{"/": true, "/etc": true, "/var": true, "/usr": true, "/boot": true, "/sys": true, "/proc": true},
	}
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// EvaluateLine is the entry point used by the SSH proxy: one logical input
// line (possibly multi-line after paste) plus its origin metadata.
func (e *Evaluator) EvaluateLine(input string) (*Decision, []*Effect) {
	e.collected = nil
	e.stmtIndex = map[uint64]*Effect{}
	pr := Parse(input)
	if pr.Incomplete {
		return &Decision{Allow: false, DenyReason: "命令尚未输入完整（存在未闭合的引号或复合结构），请继续输入"}, nil
	}
	if pr.Err != nil {
		// Unparseable input is blocked: bash would error anyway, and letting
		// unknown syntax through defeats the purpose of a chokepoint.
		return &Decision{Allow: false, DenyReason: "语法无法解析，已按未知风险拦截: " + pr.Err.Error()}, nil
	}
	if pr.File == nil {
		return &Decision{Allow: true}, nil
	}
	snap := e.snapshotState()
	e.analyzeStmts(pr.File.Stmts, Origin{Kind: "line", Snippet: firstLine(input)})
	e.linkPipelines(pr.File)
	dec := e.judge()
	if !dec.Allow {
		// State mutations inferred from a denied line never take effect.
		e.restoreState(snap)
	}
	return dec, e.collected
}

// AnalyzeForTest exposes effect extraction without policy, for unit tests.
func (e *Evaluator) AnalyzeForTest(input string) []*Effect {
	e.collected = nil
	e.stmtIndex = map[uint64]*Effect{}
	pr := Parse(input)
	if pr.Err != nil && !pr.Incomplete {
		return nil
	}
	if pr.File != nil {
		e.analyzeStmts(pr.File.Stmts, Origin{Kind: "line", Snippet: firstLine(input)})
		e.linkPipelines(pr.File)
	}
	return e.collected
}

func (e *Evaluator) analyzeStmts(stmts []*syntax.Stmt, origin Origin) {
	for _, st := range stmts {
		e.analyzeStmt(st, origin)
	}
}

func (e *Evaluator) analyzeStmt(st *syntax.Stmt, origin Origin) {
	switch c := st.Cmd.(type) {
	case *syntax.CallExpr:
		e.analyzeCall(st, c, origin)

	case *syntax.BinaryCmd:
		// && || ; | -- all branches are analyzed: an attacker hides payloads
		// in the "untaken" branch of `false && rm -rf /`.
		e.analyzeStmt(c.X, origin)
		e.analyzeStmt(c.Y, origin)

	case *syntax.Subshell, *syntax.Block:
		var body []*syntax.Stmt
		if s, ok := c.(*syntax.Subshell); ok {
			body = s.Stmts
		} else {
			body = c.(*syntax.Block).Stmts
		}
		e.analyzeStmts(body, origin)

	case *syntax.IfClause:
		e.analyzeStmts(c.Cond, origin)
		e.analyzeStmts(c.Then, origin)
		if c.Else != nil {
			e.analyzeStmts(c.Else.Then, origin)
			if c.Else.Cond != nil {
				e.analyzeStmts(c.Else.Cond, origin)
			}
		}

	case *syntax.ForClause:
		e.analyzeStmts(c.Do, origin)
		// The word list itself can carry command substitution.
		if wc, ok := c.Loop.(*syntax.WordIter); ok {
			for _, w := range wc.Items {
				e.reduceWord(w)
			}
		}

	case *syntax.WhileClause:
		// WhileClause.Until == true makes this an `until` loop.
		e.analyzeStmts(c.Cond, origin)
		e.analyzeStmts(c.Do, origin)

	case *syntax.CaseClause:
		for _, item := range c.Items {
			e.analyzeStmts(item.Stmts, origin)
		}

	case *syntax.FuncDecl:
		e.registerFunction(c)

	case *syntax.DeclClause:
		e.applyDecl(c)

	case *syntax.LetClause:
		// Arithmetic assignment; no filesystem effect worth matching.
		return

	case *syntax.TimeClause:
		if c.Stmt != nil {
			e.analyzeStmt(c.Stmt, origin)
		}

	case *syntax.CoprocClause:
		if c.Stmt != nil {
			st2 := *c.Stmt
			st2.Background = true
			e.analyzeStmt(&st2, origin)
		}

	case nil:
		// Redirection-only statement: `> /etc/passwd` truncates a file.
		e.analyzeRedirOnly(st, origin)

	default:
		// Unknown construct: fail closed with a dedicated explanation.
		e.emitUnknown(origin, fmt.Sprintf("%T", c))
	}

	// Statement-level redirections apply regardless of command type.
	if st.Cmd != nil {
		e.collectRedirects(st, nil)
	}
}

func (e *Evaluator) emitUnknown(o Origin, what string) {
	e.collected = append(e.collected, &Effect{
		Basename: "<unknown-construct>",
		Dynamic:  true,
		Origin:   o,
		Args:     []EffectArg{{Value: what, Dynamic: true}},
	})
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// nodeText renders an AST node back to canonical shell source.
func (e *Evaluator) nodeText(node syntax.Node) string {
	var sb strings.Builder
	if err := e.printer.Print(&sb, node); err != nil {
		return ""
	}
	return sb.String()
}
