package engine

import (
	"fmt"
	"path"
	"strings"

	"bastionguard/internal/policy"
)

// judge evaluates every collected effect (including recursive inner effects
// and pipeline-derived payloads) against the catalog.
func (e *Evaluator) judge() *Decision {
	if e.catalog == nil {
		return &Decision{Allow: true}
	}
	var hits []MatchHit
	for _, eff := range e.collected {
		hits = append(hits, e.matchEffect(eff, 0)...)
	}
	if len(hits) == 0 {
		return &Decision{Allow: true}
	}

	// Break-glass approvals are applied per rule id.
	var blocked []MatchHit
	for _, h := range hits {
		if e.state.Approvals[h.Rule.ID] {
			continue
		}
		blocked = append(blocked, h)
	}
	if len(blocked) == 0 {
		return &Decision{Allow: true, Hits: hits}
	}

	seen := map[string]bool{}
	var reasons []string
	for _, h := range blocked {
		if seen[h.Rule.ID] {
			continue
		}
		seen[h.Rule.ID] = true
		reasons = append(reasons, formatReason(h))
	}
	return &Decision{
		Allow:      false,
		Hits:       blocked,
		DenyReason: "已拦截高危操作（共 " + itoa(len(reasons)) + " 项）:\n  - " +
			strings.Join(reasons, "\n  - ") +
			"\n如需执行，请联系安全管理员走 break-glass 审批（令牌 " + e.catalog.BreakGlassToken + "），审批原因将写入审计日志。",
	}
}

func (e *Evaluator) matchEffect(eff *Effect, depth int) []MatchHit {
	if depth > 16 || eff == nil {
		return nil
	}
	var hits []MatchHit
	for i := range e.catalog.Rules {
		r := &e.catalog.Rules[i]
		if !r.Enabled {
			continue
		}
		if evidence, ok := e.matchRule(r, eff); ok {
			hits = append(hits, MatchHit{Rule: r, Effect: eff, Evidence: evidence})
		}
	}
	for _, inner := range eff.Inner {
		hits = append(hits, e.matchEffect(inner, depth+1)...)
	}
	return hits
}

func (e *Evaluator) matchRule(r *policy.Rule, eff *Effect) (string, bool) {
	m := r.Match

	if len(m.AnyOf) > 0 && !contains(m.AnyOf, eff.Basename) {
		return "", false
	}
	if m.DynamicOnly && !eff.Dynamic && !argsDynamic(eff) {
		return "", false
	}
	if m.IsInteractive && !eff.Interactive {
		return "", false
	}
	if m.IsBackground && !eff.Background {
		return "", false
	}
	if m.IsRemote && eff.RemoteHost == "" {
		return "", false
	}
	if m.IsRecursive && !eff.Recursive {
		return "", false
	}
	if len(m.HasFlags) > 0 {
		for _, f := range m.HasFlags {
			if !contains(eff.Flags, f) {
				return "", false
			}
		}
	}
	if len(m.HasFlagsAny) > 0 {
		matched := false
		for _, f := range m.HasFlagsAny {
			if contains(eff.Flags, f) {
				matched = true
				break
			}
		}
		if !matched {
			return "", false
		}
	}
	if len(m.ArgContains) > 0 {
		ok := false
		for _, a := range eff.Args {
			for _, sub := range m.ArgContains {
				if strings.Contains(a.Value, sub) {
					ok = true
				}
			}
		}
		if !ok {
			return "", false
		}
	}
	if len(m.ArgEqualsAny) > 0 || len(m.ArgPrefixAny) > 0 {
		ok := false
		for _, a := range eff.Args {
			if contains(m.ArgEqualsAny, a.Value) {
				ok = true
			}
			for _, p := range m.ArgPrefixAny {
				if strings.HasPrefix(a.Value, p) {
					ok = true
				}
			}
		}
		if !ok {
			return "", false
		}
	}
	if len(m.PathAny) > 0 || len(m.PathPrefix) > 0 || len(m.PathGlob) > 0 {
		if !matchPaths(m, eff) {
			return "", false
		}
	}
	if m.PayloadDynamic && (eff.Payload == nil || !eff.Payload.Dynamic) {
		return "", false
	}
	if m.PayloadShell && (eff.Payload == nil || eff.Payload.Kind != "shell") {
		return "", false
	}
	if len(m.InnerRuleIDs) > 0 {
		if !e.innerHasRule(eff, m.InnerRuleIDs, 0) {
			return "", false
		}
	}

	return e.explain(r, eff), true
}

func (e *Evaluator) innerHasRule(eff *Effect, want []string, depth int) bool {
	if depth > 16 {
		return false
	}
	byID := e.catalog.ByID()
	for _, inner := range eff.Inner {
		for _, id := range want {
			if r, ok := byID[id]; ok && e.ruleMatchesEffect(r, inner, depth+1) {
				return true
			}
		}
		if e.innerHasRule(inner, want, depth+1) {
			return true
		}
	}
	return false
}

// ruleMatchesEffect re-runs matching for one rule against a foreign effect tree.
func (e *Evaluator) ruleMatchesEffect(r *policy.Rule, eff *Effect, depth int) bool {
	if depth > 16 {
		return false
	}
	if _, ok := e.matchRule(r, eff); ok {
		return true
	}
	for _, inner := range eff.Inner {
		if e.ruleMatchesEffect(r, inner, depth+1) {
			return true
		}
	}
	return false
}

func matchPaths(m policy.Match, eff *Effect) bool {
	for _, t := range eff.Targets {
		ref := t.Absolute
		if ref == "" {
			ref = t.Raw
		}
		for _, want := range m.PathAny {
			if ref == want {
				return true
			}
			// Dynamic target touching a sensitive parent: fail closed.
			if t.Dynamic && strings.HasPrefix(want, "/") && strings.HasPrefix(ref, want) {
				return true
			}
		}
		for _, pre := range m.PathPrefix {
			if strings.HasPrefix(ref, pre) {
				return true
			}
		}
		for _, g := range m.PathGlob {
			if ok, _ := path.Match(g, ref); ok {
				return true
			}
			// Unresolved glob target: treat as match on sensitive patterns.
			if t.Dynamic && strings.Contains(g, "*") {
				return true
			}
		}
	}
	return false
}

func argsDynamic(eff *Effect) bool {
	for _, a := range eff.Args {
		if a.Dynamic {
			return true
		}
	}
	return false
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func (e *Evaluator) explain(r *policy.Rule, eff *Effect) string {
	parts := []string{
		"规则 " + r.ID + " [" + string(r.Category) + "/" + string(r.Action) + "]",
		"命令归约为 " + eff.Basename,
	}
	if eff.AliasOf != "" {
		parts = append(parts, "经由别名/函数 "+eff.AliasOf+" 展开")
	}
	if eff.UIDElevated {
		parts = append(parts, "含提权(sudo/su)")
	}
	if eff.RemoteHost != "" {
		parts = append(parts, "远程跳转至 "+eff.RemoteHost)
	}
	if len(eff.Targets) > 0 {
		var ts []string
		for _, t := range eff.Targets {
			if t.Absolute != "" {
				ts = append(ts, t.Absolute)
			} else {
				ts = append(ts, t.Raw+"(动态)")
			}
		}
		parts = append(parts, "目标 "+strings.Join(ts, ","))
	}
	if eff.Payload != nil && (eff.Payload.Dynamic || eff.Payload.Kind != "") {
		if eff.Payload.Dynamic {
			parts = append(parts, "载荷无法静态解析（fail-closed）")
		} else {
			parts = append(parts, "载荷已递归解析为 "+eff.Payload.KKind())
		}
	}
	return strings.Join(parts, "，")
}

func formatReason(h MatchHit) string {
	return fmt.Sprintf("%s: %s —— %s | 判定依据: %s",
		h.Rule.ID, h.Rule.Title, h.Rule.Description, h.Evidence)
}

// GrantApproval records a break-glass approval for one rule for this session.
func (e *Evaluator) GrantApproval(ruleID string) bool {
	if e.catalog == nil {
		return false
	}
	if _, ok := e.catalog.ByID()[ruleID]; !ok {
		return false
	}
	e.state.Approvals[ruleID] = true
	return true
}
