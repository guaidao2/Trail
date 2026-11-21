package vulnintel

import (
	"encoding/json"
	"testing"
)

// OSV 的版本区间是事件序列：[{introduced:"0"},{fixed:"3.1.3"}]。
// 这里覆盖区间构造与编号选择（有 CVE 别名就用 CVE，否则用 OSV 自己的 ID）。
func TestOSVToIntelRanges(t *testing.T) {
	raw := `{
	  "id": "GHSA-xxxx-yyyy-zzzz",
	  "aliases": ["CVE-2024-22195", "GHSA-xxxx-yyyy-zzzz"],
	  "summary": "jinja2 sandbox escape",
	  "details": "line1\nline2",
	  "published": "2024-01-11T00:00:00Z",
	  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8"}],
	  "affected": [{
	    "package": {"ecosystem": "PyPI", "name": "Jinja2"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}]
	  }],
	  "references": [{"type": "ADVISORY", "url": "https://example.com/a"}]
	}`
	var adv osvAdvisory
	if err := json.Unmarshal([]byte(raw), &adv); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	intel, ranges, ok := osvToIntel(adv, "pypi")
	if !ok {
		t.Fatal("应能映射")
	}
	if intel.CVEID != "CVE-2024-22195" {
		t.Fatalf("应优先用 CVE 别名，实际 %s", intel.CVEID)
	}
	if intel.Severity != "CRITICAL" {
		t.Fatalf("9.8 应判 CRITICAL，实际 %s", intel.Severity)
	}
	if len(ranges) != 1 {
		t.Fatalf("应产出 1 条区间，实际 %d", len(ranges))
	}
	r := ranges[0]
	// 生态名与包名都要转小写，供精确匹配使用
	if r.Vendor != "pypi" || r.Product != "jinja2" {
		t.Fatalf("生态/包名不对: vendor=%q product=%q", r.Vendor, r.Product)
	}
	if r.StartIncl != "" || r.EndExcl != "3.1.3" {
		t.Fatalf("区间不对: %+v", r)
	}
	if r.Source != "osv" {
		t.Fatalf("来源应为 osv，实际 %q", r.Source)
	}
}

// 没有 CVE 别名时退回 OSV ID；GIT 区间（commit）必须被忽略。
func TestOSVToIntelNoCVEAndGitRange(t *testing.T) {
	raw := `{
	  "id": "PYSEC-2024-1",
	  "summary": "x",
	  "affected": [{
	    "package": {"ecosystem": "PyPI", "name": "foo"},
	    "ranges": [
	      {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "deadbeef"}]},
	      {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.2"}]}
	    ]
	  }]
	}`
	var adv osvAdvisory
	if err := json.Unmarshal([]byte(raw), &adv); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	intel, ranges, ok := osvToIntel(adv, "pypi")
	if !ok {
		t.Fatal("应能映射")
	}
	if intel.CVEID != "PYSEC-2024-1" {
		t.Fatalf("无 CVE 别名时应退回 OSV ID，实际 %s", intel.CVEID)
	}
	if len(ranges) != 1 {
		t.Fatalf("GIT 区间应被忽略，只剩 1 条，实际 %d: %+v", len(ranges), ranges)
	}
	if ranges[0].StartIncl != "1.0" || ranges[0].EndIncl != "1.2" {
		t.Fatalf("last_affected 应映射到 end_including: %+v", ranges[0])
	}
}

// 一条 advisory 没有可用区间时应被丢弃，不产生空记录。
func TestOSVToIntelSkipWithoutRanges(t *testing.T) {
	raw := `{"id":"OSV-1","affected":[{"package":{"ecosystem":"PyPI","name":"bar"},"ranges":[]}]}`
	var adv osvAdvisory
	if err := json.Unmarshal([]byte(raw), &adv); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if _, _, ok := osvToIntel(adv, "pypi"); ok {
		t.Fatal("没有区间不应产出情报")
	}
}

// 一个 range 里的多个 (introduced, fixed) 对必须拆成多条区间。
// 压成一条会得到 1.4 ≤ v < 1.2 的倒置区间，真受影响的 1.1 会被判成安全。
func TestOSVEventPairsMultiSegment(t *testing.T) {
	pairs := osvEventPairs([]osvEvent{
		{Introduced: "0"},
		{Fixed: "1.2"},
		{Introduced: "1.4"},
	})
	if len(pairs) != 2 {
		t.Fatalf("应拆成 2 段，实际 %d: %+v", len(pairs), pairs)
	}
	if pairs[0].startIncl != "" || pairs[0].endExcl != "1.2" {
		t.Fatalf("第一段应为 (-∞, 1.2): %+v", pairs[0])
	}
	if pairs[1].startIncl != "1.4" || pairs[1].endExcl != "" {
		t.Fatalf("第二段应为 [1.4, +∞): %+v", pairs[1])
	}

	// last_affected 收尾 + 末尾未闭合的段
	pairs = osvEventPairs([]osvEvent{
		{Introduced: "1.0"},
		{LastAffected: "1.2"},
		{Introduced: "2.0"},
	})
	if len(pairs) != 2 {
		t.Fatalf("应拆成 2 段，实际 %d: %+v", len(pairs), pairs)
	}
	if pairs[0].endIncl != "1.2" || pairs[1].startIncl != "2.0" {
		t.Fatalf("last_affected / 未闭合段解析不对: %+v", pairs)
	}

	// 全空事件不产出区间
	if got := osvEventPairs([]osvEvent{{}}); len(got) != 0 {
		t.Fatalf("空事件不应产出区间: %+v", got)
	}
}
