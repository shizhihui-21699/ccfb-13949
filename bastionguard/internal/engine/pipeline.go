package engine

import "mvdan.cc/sh/v3/syntax"

// linkPipelines post-processes collected effects for one analysis unit: when
// commands are joined by `|` (or `|&`), the producer's output becomes the
// consumer's stdin payload. This is what makes
// `echo Z20... | base64 -d | sh` resolvable end to end.
func (e *Evaluator) linkPipelines(file *syntax.File) {
	if file == nil {
		return
	}
	pipes := map[*syntax.Stmt]*Effect{}
	// Re-walk to preserve pipe topology without disturbing collected order.
	syntax.Walk(file, func(node syntax.Node) bool {
		bc, ok := node.(*syntax.BinaryCmd)
		if !ok || (bc.Op != syntax.Pipe && bc.Op != syntax.PipeAll) {
			return true
		}
		left := e.effectForStmt(bc.X)
		right := e.effectForStmt(bc.Y)
		if left == nil || right == nil {
			return true
		}
		pipes[bc.X] = left
		pipes[bc.Y] = right
		e.wirePipe(left, right)
		return true
	})
}

// effectForStmt maps a parsed statement back to the effect it produced via the
// position index populated at collection time.
func (e *Evaluator) effectForStmt(st *syntax.Stmt) *Effect {
	if e.stmtIndex == nil {
		return nil
	}
	return e.stmtIndex[stmtKey(st)]
}

func stmtKey(st *syntax.Stmt) uint64 {
	p := st.Pos()
	return uint64(p.Line())*1_000_000 + uint64(p.Col())
}

// wirePipe transfers meaning from producer to consumer.
func (e *Evaluator) wirePipe(producer, consumer *Effect) {
	// Producer literally emits static text (echo/printf with known args).
	if (producer.Basename == "echo" || producer.Basename == "printf") && producer.Payload == nil {
		text := concatStaticArgs(producer.Args)
		if text != "" {
			consumer.Payload = mergePayload(consumer.Payload, &Payload{Kind: "unknown", Text: text})
			e.tryInterpretPipe(producer, consumer, text)
		}
		return
	}
	// A decoder consumer receiving unknown stdin must fail closed.
	switch consumer.Basename {
	case "base64", "xxd", "openssl":
		if consumer.Payload == nil || consumer.Payload.Dynamic {
			consumer.Payload = &Payload{Kind: "unknown", Dynamic: true, FromDecode: consumer.Basename}
		}
	case "sh", "bash", "zsh", "dash", "eval":
		if consumer.Payload == nil {
			consumer.Payload = &Payload{Kind: "shell", Dynamic: true}
			consumer.Interactive = false
		}
		// Record the upstream producer even when its content is dynamic (e.g.
		// `curl http://x | bash`): the download-then-exec pattern must match
		// NE-6004 on its shape, not just the fail-closed fallback.
		consumer.Flags = appendUniqueFlag(consumer.Flags, "--piped-from-"+producer.Basename)
	}
}

func (e *Evaluator) tryInterpretPipe(producer, consumer *Effect, text string) {
	switch consumer.Basename {
	case "base64":
		e.tryDecodeAndAnalyze(consumer, text, "base64", Origin{Kind: "decode", Source: "pipe:base64"})
	case "xxd":
		consumer.Payload = &Payload{Kind: "unknown", Text: text, Dynamic: true, FromDecode: "xxd"}
	case "sh", "bash", "zsh", "dash":
		consumer.Payload = &Payload{Kind: "shell", Text: text}
		consumer.Interactive = false
		consumer.Flags = appendUniqueFlag(consumer.Flags, "--piped-from-"+producer.Basename)
		consumer.Inner = append(consumer.Inner,
			e.effectsFromScript(text, Origin{Kind: "stdin", Source: "pipe:" + producer.Basename})...)
	case "eval":
		consumer.Payload = &Payload{Kind: "shell", Text: text}
		consumer.Flags = appendUniqueFlag(consumer.Flags, "--piped-from-"+producer.Basename)
		consumer.Inner = append(consumer.Inner,
			e.effectsFromScript(text, Origin{Kind: "eval", Source: "pipe:" + producer.Basename})...)
	case "mysql", "psql", "sqlite3", "redis-cli", "mongosh":
		consumer.Payload = &Payload{Kind: "sql", Text: text}
		if sqlDanger.MatchString(text) {
			consumer.Inner = append(consumer.Inner, &Effect{Basename: "<sql-destructive>", Origin: Origin{Kind: "stdin", Source: "pipe:sql"}})
		}
	case "python", "python3", "perl", "ruby", "node":
		consumer.Payload = &Payload{Kind: "text", Text: text}
		rx := pyDanger
		if consumer.Basename == "perl" || consumer.Basename == "ruby" {
			rx = plDanger
		}
		if rx.MatchString(text) {
			consumer.Inner = append(consumer.Inner, &Effect{Basename: "<" + consumer.Basename + "-dangerous-api>", Origin: Origin{Kind: "stdin"}})
		}
	}
}

func mergePayload(existing, incoming *Payload) *Payload {
	if existing == nil {
		return incoming
	}
	existing.Text = incoming.Text + existing.Text
	return existing
}

func concatStaticArgs(args []EffectArg) string {
	var out string
	for i, a := range args {
		if a.Dynamic {
			return ""
		}
		if i > 0 {
			out += " "
		}
		out += a.Value
	}
	return out
}
