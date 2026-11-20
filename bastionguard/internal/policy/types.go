// Package policy defines the rule model and the default high-risk catalog.
// A rule matches against an engine.Effect (the *resolved* meaning of a
// command), never against raw command text.
package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Action decides what happens when a rule matches.
type Action string

const (
	ActionDeny    Action = "deny"    // block before execution
	ActionWarn    Action = "warn"    // allow but loudly audit
	ActionApprove Action = "approve" // block until in-session approval is granted
)

// Category groups rules for reporting and grouped approval.
type Category string

const (
	CatDataDestruction  Category = "data-destruction"   // 删库/删数据
	CatDiskDestruction  Category = "disk-destruction"   // 清空/占满磁盘
	CatAuditTampering   Category = "audit-tampering"    // 关闭审计/清痕迹
	CatAvailability     Category = "availability"       // 关机/停服/杀进程
	CatPrivilege        Category = "privilege"          // 提权/账号边界
	CatNetworkEgress    Category = "network-egress"     // 反弹shell/隧道
	CatPackageLifecycle Category = "package-lifecycle"  // 卸载软件
	CatContainerRuntime Category = "container-runtime"  // 容器高危
	CatKernel           Category = "kernel"             // 内核/模块
	CatSchedule         Category = "schedule"           // 定时任务持久化
)

// Rule is a single policy entry expressed against semantic effects.
type Rule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Category    Category `yaml:"category"`
	Action      Action   `yaml:"action"`
	Enabled     bool     `yaml:"enabled"`

	// Match semantics (all present fields must hold = AND).
	Match Match `yaml:"match"`
}

// Match describes how to recognize a command by its resolved effect.
type Match struct {
	// AnyOf matches when any listed program/basename resolves to it.
	AnyOf []string `yaml:"any_of,omitempty"`
	// All flags present (e.g. "--remove-local" or "force" -f style).
	HasFlags []string `yaml:"has_flags,omitempty"`
	// Any one flag present (OR semantics, used when variants are equivalent).
	HasFlagsAny []string `yaml:"has_flags_any,omitempty"`
	// Argument-level conditions.
	ArgContains   []string `yaml:"arg_contains,omitempty"`   // substring on any arg
	ArgEqualsAny  []string `yaml:"arg_equals_any,omitempty"` // exact match on any arg
	ArgPrefixAny  []string `yaml:"arg_prefix_any,omitempty"` // prefix match on any arg
	// Path target conditions (apply to resolved target paths).
	PathAny    []string `yaml:"path_any,omitempty"`     // any target equals one of these
	PathPrefix []string `yaml:"path_prefix,omitempty"`  // any target starts with one of these
	PathGlob   []string `yaml:"path_glob,omitempty"`    // glob over targets
	// Meta conditions on the effect itself.
	IsInteractive bool `yaml:"is_interactive,omitempty"` // vim/psql REPLs etc.
	IsBackground  bool `yaml:"is_background,omitempty"`  // nohup/&/setsid/at
	IsRemote      bool `yaml:"is_remote,omitempty"`      // ssh/scp/curl style hop
	IsRecursive   bool `yaml:"recursive,omitempty"`      // -r/-R traversal
	// Re-evaluated inner content (e.g. decoded payload, -c script, piped SQL)
	// contains a rule id from this same catalog.
	InnerRuleIDs []string `yaml:"inner_rule_ids,omitempty"`
	// Only fire when the argument/flag is dynamically constructed (can't be
	// statically resolved) - fail closed on obfuscated indirection.
	DynamicOnly bool `yaml:"dynamic_only,omitempty"`
	// Payload conditions (bash -c / heredoc / decoded stream / piped SQL).
	PayloadDynamic bool `yaml:"payload_dynamic,omitempty"`
	PayloadShell   bool `yaml:"payload_shell,omitempty"`
}

// Catalog is the whole rule set plus runtime settings.
type Catalog struct {
	Rules []Rule `yaml:"rules"`

	// Break-glass: entering this magic token in a session grants one-time
	// approval for an ActionApprove rule; always audited with reason text.
	BreakGlassToken string `yaml:"break_glass_token"`
}

// Load reads a YAML catalog; a missing file yields an error so operators never
// silently run with an empty policy.
func Load(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load policy %s: %w", path, err)
	}
	var c Catalog
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	if c.BreakGlassToken == "" {
		c.BreakGlassToken = "!break-glass"
	}
	ids := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("rule #%d has no id", i)
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		ids[r.ID] = true
		if r.Action == "" {
			r.Action = ActionDeny
		}
		if r.Category == "" {
			return nil, fmt.Errorf("rule %s has no category", r.ID)
		}
	}
	return &c, nil
}

// ByID indexes rules for recursive inner-content matching.
func (c *Catalog) ByID() map[string]*Rule {
	m := make(map[string]*Rule, len(c.Rules))
	for i := range c.Rules {
		m[c.Rules[i].ID] = &c.Rules[i]
	}
	return m
}
