package app

import (
	"fmt"
	"testing"

	"trail/internal/database"
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

// 分页切片的边界：正常页、末页、越界、非法 offset、limit 兜底。
func TestPaginateItems(t *testing.T) {
	items := make([]database.PackageMatch, 45)
	for i := range items {
		items[i].CVEID = fmt.Sprintf("CVE-2024-%04d", i)
	}

	cases := []struct {
		name       string
		offset     int
		limit      int
		wantLen    int
		wantNext   int
		wantFirst  string
	}{
		{"first page", 0, 20, 20, 20, "CVE-2024-0000"},
		{"middle page", 20, 20, 20, 40, "CVE-2024-0020"},
		{"last partial page", 40, 20, 5, 0, "CVE-2024-0040"},
		{"offset at total", 45, 20, 0, 0, ""},
		{"offset beyond total", 999, 20, 0, 0, ""},
		{"negative offset", -5, 20, 20, 20, "CVE-2024-0000"},
		{"zero limit falls back", 0, 0, 20, 20, "CVE-2024-0000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, next := paginateItems(items, tc.offset, tc.limit)
			if len(got) != tc.wantLen {
				t.Fatalf("条数应为 %d，实际 %d", tc.wantLen, len(got))
			}
			if next != tc.wantNext {
				t.Fatalf("next_offset 应为 %d，实际 %d", tc.wantNext, next)
			}
			if tc.wantFirst != "" && got[0].CVEID != tc.wantFirst {
				t.Fatalf("首条应为 %s，实际 %s", tc.wantFirst, got[0].CVEID)
			}
			if got == nil {
				t.Fatal("空页也应是空切片而非 nil（JSON 会变成 null）")
			}
		})
	}
}

// 返回的页必须是副本：调用方改页内元素不应影响原集合（否则多次翻页会互相污染）。
func TestPaginateItemsReturnsCopy(t *testing.T) {
	items := []database.PackageMatch{{CVEID: "CVE-2024-0001"}}
	page, _ := paginateItems(items, 0, 20)
	page[0].CVEID = "MUTATED"
	if items[0].CVEID != "CVE-2024-0001" {
		t.Fatalf("paginateItems 应返回副本，原集合被改写成 %s", items[0].CVEID)
	}
}
