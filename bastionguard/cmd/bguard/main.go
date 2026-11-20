// Command bguard is the BastionGuard entry point.
//
//	bguard serve   - run the SSH bastion proxy
//	bguard check   - offline policy check of a command line / script file
//	bguard corpus  - run the bypass-sample corpus and print a report
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"bastionguard/internal/engine"
	"bastionguard/internal/policy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "check":
		runCheck(os.Args[2:])
	case "corpus":
		runCorpus(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `BastionGuard - 语义级堡垒机命令管控

用法:
  bguard serve  --policy <yaml> --listen :2222 --audit-dir ./audit
  bguard check  --policy <yaml> --cmd 'rm -rf /var/lib/mysql'
  bguard check  --policy <yaml> --file script.sh
  bguard corpus --policy <yaml> --corpus test/bypass/cases.yaml
`)
}

func loadPolicy(path string) *policy.Catalog {
	cat, err := policy.Load(path)
	if err != nil {
		fatal("加载策略失败: %v", err)
	}
	return cat
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	policyPath := fs.String("policy", "configs/default-policy.yaml", "策略 YAML 路径")
	cmd := fs.String("cmd", "", "待检查的单行命令")
	file := fs.String("file", "", "待检查的脚本文件")
	_ = fs.Parse(args)

	cat := loadPolicy(*policyPath)
	ev := engine.New(engine.NewSessionState(), cat, currentUser())

	var input string
	switch {
	case *cmd != "":
		input = *cmd
	case *file != "":
		b, err := os.ReadFile(*file)
		if err != nil {
			fatal("读取脚本失败: %v", err)
		}
		input = string(b)
	default:
		fatal("必须提供 --cmd 或 --file")
	}

	dec, effects := ev.EvaluateLine(input)
	fmt.Println("==== 语义归约结果 ====")
	for _, line := range effectLines(effects, 0) {
		fmt.Println(line)
	}
	fmt.Println()
	if dec.Allow {
		fmt.Println("裁决: 放行")
		return
	}
	fmt.Println("裁决: 拦截")
	fmt.Println(dec.DenyReason)
	os.Exit(1)
}

func effectLines(es []*engine.Effect, depth int) []string {
	var out []string
	pad := strings.Repeat("  ", depth)
	for _, ef := range es {
		line := fmt.Sprintf("%s- %s", pad, ef.Basename)
		if len(ef.Flags) > 0 {
			line += " flags=" + strings.Join(ef.Flags, ",")
		}
		if len(ef.Targets) > 0 {
			var ts []string
			for _, t := range ef.Targets {
				if t.Absolute != "" {
					ts = append(ts, t.Absolute)
				} else {
					ts = append(ts, t.Raw+"(动态)")
				}
			}
			line += " targets=" + strings.Join(ts, ",")
		}
		if ef.Dynamic {
			line += " [动态构造]"
		}
		if ef.RemoteHost != "" {
			line += " 远程=" + ef.RemoteHost
		}
		out = append(out, line)
		out = append(out, effectLines(ef.Inner, depth+1)...)
	}
	return out
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "ops"
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}
