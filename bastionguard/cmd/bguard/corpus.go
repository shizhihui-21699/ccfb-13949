package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"bastionguard/internal/engine"
	"bastionguard/internal/policy"

	"gopkg.in/yaml.v3"
)

// CorpusCase is one bypass or benign sample.
type CorpusCase struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Class       string   `yaml:"class"` // bypass | benign
	Technique   string   `yaml:"technique"`
	Lines       []string `yaml:"lines"` // sequential, share one session
	ExpectDeny  bool     `yaml:"expect_deny"`
	RuleHints   []string `yaml:"rule_hints,omitempty"`
}

type Corpus struct {
	Cases []CorpusCase `yaml:"cases"`
}

// CorpusResult is one case outcome.
type CorpusResult struct {
	C        CorpusCase
	Denied   bool
	RuleIDs  []string
	Reason   string
	Passed   bool
}

func runCorpus(args []string) {
	fs := flag.NewFlagSet("corpus", flag.ExitOnError)
	policyPath := fs.String("policy", "configs/default-policy.yaml", "策略 YAML 路径")
	corpusPath := fs.String("corpus", "test/bypass/cases.yaml", "样本语料 YAML")
	verbose := fs.Bool("v", false, "打印每个样本的归约细节")
	_ = fs.Parse(args)

	cat := loadPolicy(*policyPath)
	raw, err := os.ReadFile(*corpusPath)
	if err != nil {
		fatal("读取语料库: %v", err)
	}
	var corpus Corpus
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		fatal("解析语料库: %v", err)
	}

	var results []CorpusResult
	pass, fail := 0, 0
	for _, c := range corpus.Cases {
		res := runCase(cat, c)
		results = append(results, res)
		if res.Passed {
			pass++
		} else {
			fail++
		}
		if *verbose || !res.Passed {
			mark := "PASS"
			if !res.Passed {
				mark = "FAIL"
			}
			fmt.Printf("[%s] %s %s — %s\n", mark, c.ID, c.Technique, c.Description)
			if !res.Passed {
				fmt.Printf("        期望 deny=%v 实际 deny=%v rules=%v\n", c.ExpectDeny, res.Denied, res.RuleIDs)
				if res.Reason != "" {
					fmt.Printf("        原因: %s\n", firstNL(res.Reason))
				}
			}
		}
	}

	fmt.Printf("\n==== 语料库结果 ====\n通过 %d / 失败 %d / 共 %d\n", pass, fail, len(results))
	if fail > 0 {
		os.Exit(1)
	}
}

func runCase(cat *policy.Catalog, c CorpusCase) CorpusResult {
	ev := engine.New(engine.NewSessionState(), cat, "ops")
	res := CorpusResult{C: c}
	var last *engine.Decision
	for _, line := range c.Lines {
		dec, _ := ev.EvaluateLine(line)
		last = dec
	}
	if last == nil {
		res.Passed = false
		return res
	}
	res.Denied = !last.Allow
	for _, h := range last.Hits {
		res.RuleIDs = append(res.RuleIDs, h.Rule.ID)
	}
	res.Reason = last.DenyReason
	res.Passed = (res.Denied == c.ExpectDeny)
	return res
}

func firstNL(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}
