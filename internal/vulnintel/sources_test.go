package vulnintel

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseCPE(t *testing.T) {
	cases := []struct {
		criteria        string
		vendor, product string
	}{
		{"cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*", "apache", "httpd"},
		{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "openbsd", "openssh"},
		{"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "linux", "linux_kernel"},
		{"cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", "", ""},
		{"cpe:2.3:a:apache:-:*:*:*:*:*:*:*:*", "apache", ""},
		{"cpe:2.3:a:vendor\\:name:prod:1.0:*:*:*:*:*:*:*", "vendor:name", "prod"},
		{"not-a-cpe", "", ""},
	}
	for _, c := range cases {
		v, p := parseCPE(c.criteria)
		if v != c.vendor || p != c.product {
			t.Fatalf("parseCPE(%q) = (%q, %q), want (%q, %q)", c.criteria, v, p, c.vendor, c.product)
		}
	}
}

func TestParseGHSAVulnerableRange(t *testing.T) {
	cases := []struct {
		raw                    string
		si, se, ei, ee         string
	}{
		{">= 1.0.0, < 1.2.3", "1.0.0", "", "", "1.2.3"},
		{"> 1.0.0, <= 2.0.0", "", "1.0.0", "2.0.0", ""},
		{"= 1.2.3", "1.2.3", "", "1.2.3", ""},
		{"< 3.0.0", "", "", "", "3.0.0"},
	}
	for _, c := range cases {
		si, se, ei, ee := parseGHSAVulnerableRange(c.raw)
		if si != c.si || se != c.se || ei != c.ei || ee != c.ee {
			t.Fatalf("parseGHSAVulnerableRange(%q) = (%q,%q,%q,%q), want (%q,%q,%q,%q)",
				c.raw, si, se, ei, ee, c.si, c.se, c.ei, c.ee)
		}
	}
}

// 用真实 NVD 2.0 响应片段验证映射（同时校验 json tag）。
func TestNVDToIntel(t *testing.T) {
	const payload = `{
	  "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2021-41773",
	      "published": "2021-10-05T00:00:00.000",
	      "lastModified": "2022-01-01T00:00:00.000",
	      "descriptions": [{"lang": "en", "value": "A path traversal in Apache HTTP Server 2.4.49. Second sentence."}],
	      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
	      "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
	      "configurations": [{"nodes": [{"cpeMatch": [{
	        "vulnerable": true,
	        "criteria": "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
	        "versionStartIncluding": "2.4.49",
	        "versionEndIncluding": "2.4.50"
	      }]}]}],
	      "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}]
	    }
	  }]
	}`
	var resp nvdResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatalf("解析 NVD 样本失败: %v", err)
	}
	if len(resp.Vulnerabilities) != 1 {
		t.Fatalf("样本应有 1 条，实际 %d", len(resp.Vulnerabilities))
	}
	intel, ranges := nvdToIntel(resp.Vulnerabilities[0].CVE)

	if intel.CVEID != "CVE-2021-41773" || intel.Severity != "HIGH" || intel.Source != "nvd" {
		t.Fatalf("映射结果不符: %+v", intel)
	}
	if intel.CVSSScore == nil || *intel.CVSSScore != 7.5 {
		t.Fatalf("CVSS 分数丢失: %+v", intel.CVSSScore)
	}
	if len(intel.CWEs) != 1 || intel.CWEs[0] != "CWE-22" {
		t.Fatalf("CWE 未解析: %+v", intel.CWEs)
	}
	if intel.Title == "" || len(intel.Title) > 200 {
		t.Fatalf("标题应由首句截断得到: %q", intel.Title)
	}
	if len(ranges) != 1 {
		t.Fatalf("版本区间应为 1 条，实际 %+v", ranges)
	}
	r := ranges[0]
	if r.Vendor != "apache" || r.Product != "httpd" || r.StartIncl != "2.4.49" || r.EndIncl != "2.4.50" || r.Source != "nvd" {
		t.Fatalf("区间映射不符: %+v", r)
	}
}

// 用真实 GHSA 响应片段验证映射与区间解析。
func TestGHSAToIntel(t *testing.T) {
	const payload = `[{
	  "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
	  "cve_id": "CVE-2023-0001",
	  "summary": "Prototype pollution in example-lib",
	  "severity": "high",
	  "references": [{"url": "https://example.com/advisory"}],
	  "vulnerabilities": [{
	    "package": {"ecosystem": "npm", "name": "Example-Lib"},
	    "vulnerable_version_range": ">= 1.0.0, < 1.2.3",
	    "first_patched_version": {"identifier": "1.2.3"}
	  }],
	  "cwes": [{"cwe_id": "CWE-1321"}]
	}]`
	var items []ghsaAdvisory
	if err := json.Unmarshal([]byte(payload), &items); err != nil {
		t.Fatalf("解析 GHSA 样本失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("样本应有 1 条，实际 %d", len(items))
	}
	intel, ranges, ok := ghsaToIntel(items[0])
	if !ok {
		t.Fatal("GHSA 应能映射")
	}
	if intel.CVEID != "CVE-2023-0001" || intel.Source != "ghsa" || intel.Severity != "HIGH" {
		t.Fatalf("映射结果不符: %+v", intel)
	}
	if len(ranges) != 1 || ranges[0].Product != "example-lib" {
		t.Fatalf("产品名应小写归一: %+v", ranges)
	}
	if ranges[0].StartIncl != "1.0.0" || ranges[0].EndExcl != "1.2.3" || ranges[0].PatchedVersion != "1.2.3" {
		t.Fatalf("区间/修复版本不符: %+v", ranges[0])
	}

	// 没有 CVE 编号的公告跳过（情报库以 CVE 为主键）
	items[0].CVEID = ""
	if _, _, ok := ghsaToIntel(items[0]); ok {
		t.Fatal("无 CVE 编号的公告应跳过")
	}
}

func TestPageDelayFor(t *testing.T) {
	if got := PageDelayFor(""); got != 6500*time.Millisecond {
		t.Fatalf("匿名间隔应为 6.5s，实际 %v", got)
	}
	if got := PageDelayFor("key-123"); got != 700*time.Millisecond {
		t.Fatalf("带 key 间隔应为 0.7s，实际 %v", got)
	}
}
