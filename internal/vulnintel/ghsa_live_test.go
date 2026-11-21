package vulnintel

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestGHSALiveFirstPage 对真实 GitHub API 拉一页公告并解析，用来兜住
// "字段类型和文档不一致" 这类只能在真实响应上暴露的问题
// （已踩过两次：references 从对象数组变字符串数组、first_patched_version 是字符串且可为 null）。
//
// 默认跳过，只在显式开启时打外网：
//
//	GHSA_LIVE=1 go test ./internal/vulnintel/ -run TestGHSALiveFirstPage -v
//
// 需要出网；有 GITHUB_TOKEN 时限额更宽。
func TestGHSALiveFirstPage(t *testing.T) {
	if os.Getenv("GHSA_LIVE") != "1" {
		t.Skip("设置 GHSA_LIVE=1 才访问真实 GitHub API")
	}
	base := os.Getenv("GHSA_API_BASE")
	if base == "" {
		base = "https://api.github.com"
	}
	since := time.Now().AddDate(0, 0, -30)
	c := newClient(Config{PageDelay: time.Millisecond})

	items, skipped, err := fetchGHSA(context.Background(), c, base, os.Getenv("GITHUB_TOKEN"), since, 1, 100)
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("没有返回任何公告")
	}
	if skipped > 0 {
		t.Logf("跳过 %d 条无法解析的公告（共 %d 条）", skipped, len(items)+skipped)
	}

	var parsed, ranges, patched int
	for _, a := range items {
		_, rs, ok := ghsaToIntel(a)
		if !ok {
			continue
		}
		parsed++
		ranges += len(rs)
		for _, r := range rs {
			if r.PatchedVersion != "" {
				patched++
			}
		}
	}
	t.Logf("公告=%d 可解析=%d 区间=%d 带修复版本=%d", len(items), parsed, ranges, patched)

	// 只断言"解析没炸 + 真能产出区间"，不绑定具体条数（上游数据每天在变）。
	if parsed == 0 || ranges == 0 {
		t.Fatalf("解析出 0 条可用情报（公告 %d 条）：说明字段结构与预期不符", len(items))
	}
	// 真实数据里 first_patched_version 是字符串；如果哪天它又变形状，
	// 容错解析会静默变成空串，所以这里必须断言确实取到了值。
	if patched == 0 {
		t.Fatalf("没有任何公告解析出修复版本（区间 %d 个）：first_patched_version 的解析可能已失效", ranges)
	}
}
