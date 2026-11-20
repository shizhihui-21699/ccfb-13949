package engine

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func parseSlice(t *testing.T, expr string) *syntax.Slice {
	t.Helper()
	pr, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader("echo " + expr), "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var sl *syntax.Slice
	syntax.Walk(pr, func(n syntax.Node) bool {
		if px, ok := n.(*syntax.ParamExp); ok && px.Slice != nil {
			sl = px.Slice
		}
		return true
	})
	if sl == nil {
		t.Fatalf("no slice in %q", expr)
	}
	return sl
}

func TestEvalStaticSlice(t *testing.T) {
	ev := New(NewSessionState(), nil, "ops")
	cases := []struct {
		src   string
		val   string
		want  string
	}{
		{"${x:1:2}", "armless", "rm"},
		{"${x:3:2}", "armless", "le"},
		{"${x:3}", "armless", "less"},
		{"${x:0:4}", "armless", "arml"},
		{"${x:5}", "armless", "ss"}, // plain positive offset, length omitted
	}
	for _, tc := range cases {
		// rebuild because negative forms parse differently
		sl := parseSlice(t, tc.src)
		got := evalStaticSlice(tc.val, sl, ev)
		if got == nil {
			t.Errorf("%s: got nil, want %q", tc.src, tc.want)
			continue
		}
		if *got != tc.want {
			t.Errorf("%s on %q = %q, want %q", tc.src, tc.val, *got, tc.want)
		}
	}
}

func TestEvalStaticSliceDynamic(t *testing.T) {
	ev := New(NewSessionState(), nil, "ops")
	// ${x:$z:2} with unknown z must yield nil (fail-closed).
	sl := parseSlice(t, "${x:$z:2}")
	if got := evalStaticSlice("armless", sl, ev); got != nil {
		t.Errorf("dynamic offset should return nil, got %q", *got)
	}
}
