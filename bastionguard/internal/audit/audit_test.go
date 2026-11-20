package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bastionguard/internal/audit"
)

func TestRecordStampsIdentity(t *testing.T) {
	dir := t.TempDir()
	aud, err := audit.New(dir, "sess-9", "ops-li", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	aud.Record(audit.Event{Kind: "line-deny", RawInput: "rm -rf /etc", RuleIDs: []string{"DG-1001"}})
	aud.Close()

	var got []audit.Event
	walk := func(p string, info os.FileInfo, err error) error {
		if err != nil || !strings.HasSuffix(p, ".jsonl") {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var ev audit.Event
			if e := json.Unmarshal([]byte(line), &ev); e == nil {
				got = append(got, ev)
			}
		}
		return nil
	}
	_ = filepath.Walk(dir, walk)

	var deny *audit.Event
	for i := range got {
		if got[i].Kind == "line-deny" {
			deny = &got[i]
		}
	}
	if deny == nil {
		t.Fatal("未找到 line-deny 事件")
	}
	if deny.SessionID != "sess-9" || deny.User != "ops-li" || deny.Target != "web-01" {
		t.Errorf("会话身份未自动填充: %+v", deny)
	}
	if len(deny.RuleIDs) != 1 || deny.RuleIDs[0] != "DG-1001" {
		t.Errorf("规则ID丢失: %+v", deny.RuleIDs)
	}
}
