//go:build cgo

// 这两个用例需要真实 sqlite（go-sqlite3 依赖 cgo）。
// 无 cgo 的环境（如 Windows 默认构建）下跳过，避免报 sqlite 桩错误掩盖真正的失败。

package vulnintel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trail/internal/database"

	"go.uber.org/zap"
)

func newImportTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "import.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写临时文件失败: %v", err)
	}
	return path
}

// KEV 离线包：导入后不仅要有在野标记，还应该有厂商/产品/名称/修复动作等详情。
func TestImportKEVFile(t *testing.T) {
	const payload = `{
	  "catalogVersion": "2026.11.21",
	  "dateReleased": "2026-11-21T00:00:00.000Z",
	  "count": 1,
	  "vulnerabilities": [{
	    "cveID": "CVE-2021-44228",
	    "dateAdded": "2021-12-10",
	    "vendorProject": "Apache",
	    "product": "Log4j2",
	    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
	    "shortDescription": "Apache Log4j2 contains a vulnerability that allows remote code execution.",
	    "requiredAction": "Apply updates per vendor instructions.",
	    "dueDate": "2021-12-24",
	    "knownRansomwareCampaignUse": "Known"
	  }]
	}`
	path := writeTemp(t, "kev.json", payload)
	db := newImportTestDB(t)

	sum, err := ImportFile(context.Background(), db, path, "")
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if sum.KEV != 1 {
		t.Fatalf("应导入 1 条 KEV，实际 %d", sum.KEV)
	}

	rec, _, _, err := db.GetVulnIntel("CVE-2021-44228")
	if err != nil || rec == nil {
		t.Fatalf("GetVulnIntel: rec=%v err=%v", rec, err)
	}
	if !rec.KEV {
		t.Fatal("应带在野利用标记")
	}
	// KEV 目录自带的信息必须落库（NVD 未同步时也能看懂）
	for _, want := range []string{"Apache", "Log4j2", "Remote Code Execution", "Apply updates", "2021-12-24", "勒索软件"} {
		if !contains(rec.Title+rec.Description, want) {
			t.Fatalf("详情缺少 %q：title=%q desc=%q", want, rec.Title, rec.Description)
		}
	}
}

// EPSS 离线包：只更新利用概率，不覆盖 KEV 标记。
func TestImportEPSSFile(t *testing.T) {
	const payload = `{
	  "status": "OK", "total": 1, "offset": 0, "limit": 10000,
	  "data": [{"cve": "CVE-2021-44228", "epss": "0.97000", "percentile": "0.99900", "date": "2026-11-21"}]
	}`
	path := writeTemp(t, "epss.json", payload)
	db := newImportTestDB(t)
	if err := db.MarkKEV("CVE-2021-44228", time.Time{}); err != nil {
		t.Fatalf("MarkKEV: %v", err)
	}

	sum, err := ImportFile(context.Background(), db, path, "")
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if sum.EPSS != 1 {
		t.Fatalf("应导入 1 条 EPSS，实际 %d", sum.EPSS)
	}
	rec, _, _, _ := db.GetVulnIntel("CVE-2021-44228")
	if rec == nil || rec.EPSS == nil || *rec.EPSS < 0.9 {
		t.Fatalf("EPSS 未写入: %+v", rec)
	}
	if !rec.KEV {
		t.Fatal("导入 EPSS 不应清掉 KEV 标记")
	}
}

// NVD 离线包：应写入 CVE 主体与结构化版本区间。
func TestImportNVDFile(t *testing.T) {
	const payload = `{
	  "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
	  "vulnerabilities": [{"cve": {
	    "id": "CVE-2021-41773",
	    "published": "2021-10-05T00:00:00.000",
	    "lastModified": "2022-01-01T00:00:00.000",
	    "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49."}],
	    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
	    "configurations": [{"nodes": [{"cpeMatch": [{
	      "vulnerable": true,
	      "criteria": "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
	      "versionStartIncluding": "2.4.49",
	      "versionEndIncluding": "2.4.50"
	    }]}]}],
	    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}]
	  }}]
	}`
	path := writeTemp(t, "nvd.json", payload)
	db := newImportTestDB(t)

	sum, err := ImportFile(context.Background(), db, path, "")
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if sum.NVD != 1 {
		t.Fatalf("应导入 1 条 NVD，实际 %d", sum.NVD)
	}
	if in, ok := db.VersionInVulnIntelRange("CVE-2021-41773", "httpd", "2.4.49"); !ok || !in {
		t.Fatalf("版本区间应判定受影响: in=%v comparable=%v", in, ok)
	}
}

// 无法识别的内容要报错，而不是静默导入 0 条。
func TestImportRejectsUnknownFormat(t *testing.T) {
	path := writeTemp(t, "weird.json", `{"hello":"world"}`)
	db := newImportTestDB(t)
	if _, err := ImportFile(context.Background(), db, path, ""); err == nil {
		t.Fatal("无法识别的文件应返回错误")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
