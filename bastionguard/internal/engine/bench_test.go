package engine_test

import (
	"testing"

	"bastionguard/internal/engine"
	"bastionguard/internal/policy"
)

// BenchmarkEvaluateTypicalLine measures the per-command check latency on the
// hot path. The bastion must add negligible latency to interactive work.
func BenchmarkEvaluateTypicalLine(b *testing.B) {
	cat, err := policy.Load("../../configs/default-policy.yaml")
	if err != nil {
		b.Fatal(err)
	}
	lines := []string{
		"ls -la /var/log",
		"grep error /var/log/messages | head -20",
		"systemctl status nginx",
		"mysql -e 'SELECT COUNT(*) FROM orders;'",
		"cd /opt/app && tar czf /tmp/b.tgz conf && ls -la",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := engine.New(engine.NewSessionState(), cat, "ops")
		ev.EvaluateLine(lines[i%len(lines)])
	}
}

// BenchmarkEvaluateObfuscated stresses the recursive/decoding path.
func BenchmarkEvaluateObfuscated(b *testing.B) {
	cat, _ := policy.Load("../../configs/default-policy.yaml")
	lines := []string{
		"echo cm0gLXJmIC92YXIvbGliL215c3FsCg== | base64 -d | sh",
		"find /var/lib/mysql -name '*.ibd' -exec rm -f {} +",
		"ssh db-01 'rm -rf /var/lib/mysql'",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := engine.New(engine.NewSessionState(), cat, "ops")
		ev.EvaluateLine(lines[i%len(lines)])
	}
}
