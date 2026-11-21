package app

import (
	"testing"

	"trail/internal/mcp/builtin"
)

// 清单解析要按段标记判定来源，且丢弃不完整行（否则 rpm 的 name 会被当成版本去比对）。
func TestParsePackageInventory(t *testing.T) {
	output := `=== dpkg ===
openssl	1.1.1f-1ubuntu2.16
openssh-client	9.0p1
=== rpm ===
httpd	2.4.49-1.el8
=== pip ===
requests==2.31.0
=== npm ===
/usr/lib/node_modules/express@4.18.2
/usr/local/lib/node_modules/@scope/pkg@1.2.3
=== gem ===
rails (7.1.3)
nokogiri (1.16.0, 1.15.5, default: 1.14.0)
=== cargo ===
ripgrep v14.1.0:
    ripgrep
cargo-audit v0.20.0:
    cargo-audit
=== go ===
github.com/gin-gonic/gin	v1.10.0
example.com/tool	(devel)
=== docker ===
nginx	1.21.6
redis	<none>
=== end ===`

	pkgs := parsePackageInventory(output)
	if len(pkgs) != 12 {
		t.Fatalf("应解析出 12 个包，实际 %d: %+v", len(pkgs), pkgs)
	}
	want := map[string]string{
		"openssl":        "1.1.1f-1ubuntu2.16",
		"openssh-client": "9.0p1",
		"httpd":          "2.4.49-1.el8",
		"requests":       "2.31.0",
		"express":        "4.18.2",
		"@scope/pkg":     "1.2.3",
		"nginx":          "1.21.6",
		"rails":          "7.1.3",
		"nokogiri":       "1.16.0",
		"ripgrep":        "14.1.0",
		"cargo-audit":    "0.20.0",
		"github.com/gin-gonic/gin": "v1.10.0",
	}
	for _, p := range pkgs {
		v, ok := want[p.Name]
		if !ok {
			t.Fatalf("出现了预期外的包: %+v", p)
		}
		if p.Version != v {
			t.Fatalf("%s 版本解析错误: %q, want %q", p.Name, p.Version, v)
		}
		if p.Source == "" {
			t.Fatalf("%s 缺少来源标记", p.Name)
		}
	}
	// docker 的 <none> 标签应被丢弃
	for _, p := range pkgs {
		if p.Name == "redis" {
			t.Fatal("docker 的 <none> 标签不应进入清单")
		}
	}
}

// 四个工具必须被登记为内置工具，否则模型看不到、授权也走不到。
func TestVulnIntelToolsRegistered(t *testing.T) {
	for _, name := range []string{
		builtin.ToolVulnIntelSearch,
		builtin.ToolVulnIntelGet,
		builtin.ToolVulnIntelMatchHost,
		builtin.ToolVulnIntelSync,
	} {
		if !builtin.IsBuiltinTool(name) {
			t.Fatalf("%s 未登记为内置工具", name)
		}
		found := false
		for _, tool := range builtin.GetAllBuiltinTools() {
			if tool == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s 不在 GetAllBuiltinTools 里", name)
		}
	}
}
