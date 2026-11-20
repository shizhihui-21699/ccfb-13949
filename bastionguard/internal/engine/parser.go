package engine

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ParseResult is one parser round-trip. Incomplete=true means the shell would
// print PS2 (open quote / unfinished compound) - the SSH layer asks for more
// bytes rather than judging a half-typed command.
type ParseResult struct {
	File       *syntax.File
	Incomplete bool
	Err        error
}

// Parse performs Bash-dialect parsing (the login shell on managed hosts).
func Parse(input string) ParseResult {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).
		Parse(strings.NewReader(input), "")
	if err != nil {
		// mvdan reports continuation needs as parse errors on EOF.
		if isIncomplete(err) {
			return ParseResult{File: f, Incomplete: true, Err: err}
		}
		return ParseResult{File: f, Err: err}
	}
	return ParseResult{File: f}
}

func isIncomplete(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Library messages for unclosed constructs; keep this list narrow and
	// back it with tests so a typo is never mistaken for a continuation.
	for _, frag := range []string{
		"unclosed quote",
		"no matching token",
		"EOF",
		"not a valid operator",
	} {
		if strings.Contains(msg, frag) {
			return true
		}
	}
	return false
}
