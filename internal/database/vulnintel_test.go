package database

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newVulnIntelTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "vulnintel.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// 情报记录 + 结构化区间能写入并读回，KEV/EPSS 不被 NVD 回填覆盖。
func TestVulnIntelUpsertAndGet(t *testing.T) {
	db := newVulnIntelTestDB(t)

	err := db.UpsertVulnIntel(VulnIntel{
		CVEID:    "cve-2021-44228",
		Title:    "Log4Shell",
		Severity: "critical",
		Source:   "nvd",
		Refs:     []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		CWEs:     []string{"CWE-502"},
	}, []VulnIntelRange{{
		Vendor: "apache", Product: "log4j", Criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
		StartIncl: "2.0", EndIncl: "2.14.1", Source: "nvd",
	}})
	if err != nil {
		t.Fatalf("UpsertVulnIntel: %v", err)
	}

	// KEV 与 EPSS 由各自同步源维护
	if err := db.MarkKEV("CVE-2021-44228", time.Now()); err != nil {
		t.Fatalf("MarkKEV: %v", err)
	}
	if err := db.UpdateEPSS("CVE-2021-44228", 0.97, 0.99, time.Now()); err != nil {
		t.Fatalf("UpdateEPSS: %v", err)
	}

	// NVD 后续回填不应把 kev/epss 清掉
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2021-44228", Title: "Log4Shell (updated)", Severity: "critical", Source: "nvd"}, nil); err != nil {
		t.Fatalf("再次 Upsert: %v", err)
	}

	rec, ranges, pocs, err := db.GetVulnIntel("cve-2021-44228")
	if err != nil || rec == nil {
		t.Fatalf("GetVulnIntel: rec=%v err=%v", rec, err)
	}
	if rec.CVEID != "CVE-2021-44228" {
		t.Fatalf("CVE 编号应大写归一，实际 %q", rec.CVEID)
	}
	if !rec.KEV {
		t.Fatal("KEV 标记不应被 NVD 回填清掉")
	}
	if rec.EPSS == nil || *rec.EPSS < 0.9 {
		t.Fatalf("EPSS 不应被覆盖，实际 %v", rec.EPSS)
	}
	if len(ranges) != 1 || ranges[0].Product != "log4j" {
		t.Fatalf("版本区间丢失: %+v", ranges)
	}
	if len(pocs) != 0 {
		t.Fatalf("不应有 PoC，实际 %+v", pocs)
	}

	total, kev, err := db.CountVulnIntel()
	if err != nil || total != 1 || kev != 1 {
		t.Fatalf("统计不符: total=%d kev=%d err=%v", total, kev, err)
	}
}

// 版本判定三态：命中 / 未命中 / 无区间（不可判断）。
func TestVulnIntelVersionThreeState(t *testing.T) {
	db := newVulnIntelTestDB(t)

	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2021-0001", Severity: "high", Source: "nvd"}, []VulnIntelRange{{
		Vendor: "apache", Product: "httpd",
		Criteria:  "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
		StartIncl: "2.4.0", EndExcl: "2.4.50", Source: "nvd",
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// 没有区间的一条
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2021-0002", Severity: "high", Source: "nvd"}, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if in, ok := db.VersionInVulnIntelRange("CVE-2021-0001", "httpd", "2.4.49"); !ok || !in {
		t.Fatalf("2.4.49 应判定为受影响: in=%v comparable=%v", in, ok)
	}
	if in, ok := db.VersionInVulnIntelRange("CVE-2021-0001", "httpd", "2.4.50"); !ok || in {
		t.Fatalf("2.4.50 应判定为不受影响（EndExcl）: in=%v comparable=%v", in, ok)
	}
	if _, ok := db.VersionInVulnIntelRange("CVE-2021-0002", "httpd", "2.4.49"); ok {
		t.Fatal("没有结构化区间时必须返回 comparable=false")
	}

	hits, total, err := db.SearchVulnIntel(VulnIntelFilter{Product: "httpd", Version: "2.4.49"})
	if err != nil {
		t.Fatalf("SearchVulnIntel: %v", err)
	}
	if total != 1 || len(hits) != 1 {
		t.Fatalf("按产品检索应有 1 条，实际 total=%d len=%d", total, len(hits))
	}
	if hits[0].VersionInRange == nil || !*hits[0].VersionInRange {
		t.Fatalf("检索结果应带三态判定: %+v", hits[0].VersionInRange)
	}
	if !hits[0].VersionSeen {
		t.Fatal("版本号出现在区间里，version_seen_in_criteria 应为 true")
	}
}

// 主机包匹配：受影响 / 不受影响 / 发行版需人工核对补丁。
func TestVulnIntelMatchPackages(t *testing.T) {
	db := newVulnIntelTestDB(t)

	// 两条区间：libssl 与 openssh
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2022-0778", Severity: "high", Source: "nvd"}, []VulnIntelRange{{
		Vendor: "openssl", Product: "openssl",
		StartIncl: "1.1.1", EndIncl: "1.1.1m",
	}}); err != nil {
		t.Fatalf("Upsert openssl: %v", err)
	}
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2023-38408", Severity: "critical", Source: "nvd"}, []VulnIntelRange{{
		Vendor: "openbsd", Product: "openssh",
		StartIncl: "8.0", EndExcl: "9.3p2",
	}}); err != nil {
		t.Fatalf("Upsert openssh: %v", err)
	}
	if err := db.MarkKEV("CVE-2023-38408", time.Now()); err != nil {
		t.Fatalf("MarkKEV: %v", err)
	}

	matches, err := db.MatchPackages([]Package{
		{Name: "openssl", Version: "1.1.1n", Source: "dpkg"},          // 高于 EndIncl → not_affected
		{Name: "openssh-client", Version: "9.0p1", Source: "dpkg"},    // 落在区间 → affected
		{Name: "openssl", Version: "1.1.1f-1ubuntu2.16", Source: "dpkg"}, // 区间内但带发行版后缀 → unknown + 需核对补丁
		{Name: "nginx", Version: "1.18.0", Source: "dpkg"},            // 无区间 → 无结果
	})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}

	byStatus := map[string][]PackageMatch{}
	for _, m := range matches {
		byStatus[m.Status] = append(byStatus[m.Status], m)
	}
	if len(byStatus["affected"]) == 0 {
		t.Fatalf("openssh 9.0p1 应判 affected，实际 %+v", matches)
	}
	foundKEV := false
	for _, m := range byStatus["affected"] {
		if m.CVEID == "CVE-2023-38408" && m.KEV {
			foundKEV = true
		}
	}
	if !foundKEV {
		t.Fatal("命中项应带 KEV 标记")
	}
	if len(byStatus["not_affected"]) == 0 {
		t.Fatalf("openssl 1.1.1n 应判 not_affected，实际 %+v", matches)
	}
	patchCheck := false
	for _, m := range byStatus["needs_manual"] {
		if m.Package.Version == "1.1.1f-1ubuntu2.16" && m.NeedsPatchCheck {
			patchCheck = true
		}
	}
	if !patchCheck {
		t.Fatalf("发行版版本应落 needs_manual 且 NeedsPatchCheck=true，实际 %+v", matches)
	}
	for _, m := range matches {
		if m.Package.Name == "nginx" {
			t.Fatal("没有区间的包不应产生匹配结果")
		}
	}
}

// 同步状态可读可写，缺省为启用。
func TestVulnIntelSyncState(t *testing.T) {
	db := newVulnIntelTestDB(t)

	st, err := db.GetVulnIntelSync("nvd")
	if err != nil || st.Source != "nvd" || !st.Enabled {
		t.Fatalf("缺省状态不符: %+v err=%v", st, err)
	}
	st.Cursor = "2026-11-20T00:00:00Z"
	st.TotalSynced = 42
	st.LastSyncAt = time.Now().Format(time.RFC3339)
	st.LastError = ""
	if err := db.SaveVulnIntelSync(st); err != nil {
		t.Fatalf("SaveVulnIntelSync: %v", err)
	}
	got, err := db.GetVulnIntelSync("NVD")
	if err != nil {
		t.Fatalf("GetVulnIntelSync: %v", err)
	}
	if got.Cursor != st.Cursor || got.TotalSynced != 42 {
		t.Fatalf("同步状态未持久化: %+v", got)
	}
	all, err := db.ListVulnIntelSync()
	if err != nil || len(all) != 1 {
		t.Fatalf("ListVulnIntelSync: %+v err=%v", all, err)
	}
}

// 版本比较：数字段、缺段补零、预发布后缀。
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"1.2.4", "1.2.3", 1},
		{"2.4.49", "2.4.50", -1},
		// OpenSSL 风格字母补丁级：1.1.1f 晚于 1.1.1
		{"1.1.1", "1.1.1f", -1},
		{"1.1.1f", "1.0", 1},
		// 显式预发布低于正式版
		{"1.0rc1", "1.0", -1},
		{"1.0", "1.0b3", -1},
		{"v1.1.1", "1.1.1", 0},
		// 发行版修订后缀不参与上游比较
		{"1.1.1f-1ubuntu2.16", "1.1.1f", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Fatalf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// 同一个 CVE 有多条区间、且一个包命中多条时，不能因为去重把后续 CVE 的扫描截断。
func TestVulnIntelMatchPackagesMultiRange(t *testing.T) {
	db := newVulnIntelTestDB(t)

	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2020-1111", Severity: "HIGH", Source: "nvd"}, []VulnIntelRange{
		{Vendor: "gnu", Product: "openssl", StartIncl: "1.0.0", EndIncl: "1.0.2", Source: "nvd"},
		{Vendor: "gnu", Product: "openssl", StartIncl: "1.1.0", EndIncl: "1.1.1", Source: "nvd"},
	}); err != nil {
		t.Fatalf("Upsert 第一条: %v", err)
	}
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2020-2222", Severity: "CRITICAL", Source: "nvd"}, []VulnIntelRange{
		{Vendor: "gnu", Product: "openssl", StartIncl: "1.1.0", EndIncl: "1.1.1", Source: "nvd"},
	}); err != nil {
		t.Fatalf("Upsert 第二条: %v", err)
	}

	matches, err := db.MatchPackages([]Package{{Name: "openssl", Version: "1.1.0", Source: "dpkg"}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	found := map[string]bool{}
	for _, m := range matches {
		if m.Status == "affected" {
			found[m.CVEID] = true
		}
	}
	if !found["CVE-2020-1111"] || !found["CVE-2020-2222"] {
		t.Fatalf("两条 CVE 都应命中（去重不得截断扫描），实际 %+v", found)
	}
}

// 包名与产品名只允许"精确"或"产品名 + 分隔符"匹配，避免 zip↔7-zip、git↔gitlab 这类误报。
func TestVulnIntelMatchPackagesNameBoundary(t *testing.T) {
	db := newVulnIntelTestDB(t)
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2019-0001", Severity: "HIGH", Source: "nvd"}, []VulnIntelRange{
		{Vendor: "igor", Product: "git", StartIncl: "1.0", EndIncl: "9.9", Source: "nvd"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	matches, err := db.MatchPackages([]Package{
		{Name: "git", Version: "2.0"},
		{Name: "gitlab", Version: "2.0"},
		{Name: "git-core", Version: "2.0"},
	})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	got := map[string]string{}
	for _, m := range matches {
		got[m.Package.Name] = m.Status
	}
	if got["gitlab"] != "" {
		t.Fatalf("gitlab 不应匹配产品 git，实际 %q", got["gitlab"])
	}
	if got["git"] == "" {
		t.Fatal("git 应匹配")
	}
	if got["git-core"] == "" {
		t.Fatal("git-core 应匹配（产品名 + 分隔符）")
	}
}

// 诊断：走完整 DB 路径，把实际参与判定的值打出来。
func TestMatchDBDiagnostic(t *testing.T) {
	db := newVulnIntelTestDB(t)
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2023-38408", Severity: "critical", Source: "nvd"}, []VulnIntelRange{{
		Vendor: "openbsd", Product: "openssh", StartIncl: "8.0", EndExcl: "9.3p2", Source: "nvd",
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := db.MarkKEV("CVE-2023-38408", time.Now()); err != nil {
		t.Fatalf("MarkKEV: %v", err)
	}
	var published, product string
	var si, ee string
	if err := db.QueryRow(`SELECT v.published_at, r.product, r.start_incl, r.end_excl
		FROM vuln_intel_range r JOIN vuln_intel v ON v.cve_id = r.cve_id
		WHERE v.cve_id = ?`, "CVE-2023-38408").Scan(&published, &product, &si, &ee); err != nil {
		t.Fatalf("读取行失败: %v", err)
	}
	t.Logf("行值: published=%q product=%q start=%q endExcl=%q", published, product, si, ee)
	bounds := rangeBounds{startIncl: si, endExcl: ee}
	t.Logf("判定: fuzzy=%v distro=%v era=%v up=%v rev=%v",
		packageNeedsManual("openssh-client", product), hasDistroSuffix("9.0p1"),
		cveEraTooOld(published),
		matchRangeDual("9.0p1", bounds, compareUpstream),
		matchRangeDual("9.0p1", bounds, compareRevision))

	matches, err := db.MatchPackages([]Package{{Name: "openssh-client", Version: "9.0p1"}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	for _, m := range matches {
		t.Logf("结果: %s %s → %s (patch=%v)", m.Package.Name, m.Package.Version, m.Status, m.NeedsPatchCheck)
	}
}

// 诊断：把四态判定用到的几个输入打出来，便于确认是哪个条件触发了降级。
func TestMatchInputsDiagnostic(t *testing.T) {
	bounds := rangeBounds{startIncl: "8.0", endExcl: "9.3p2"}
	up := matchRangeDual("9.0p1", bounds, compareUpstream)
	rev := matchRangeDual("9.0p1", bounds, compareRevision)
	t.Logf("openssh-client 9.0p1: fuzzy=%v distro=%v era=%v up=%v rev=%v",
		packageNeedsManual("openssh-client", "openssh"),
		hasDistroSuffix("9.0p1"),
		cveEraTooOld(""),
		up, rev)
	if packageNeedsManual("openssh-client", "openssh") || hasDistroSuffix("9.0p1") || !up || !rev {
		t.Fatalf("9.0p1 应落在区间内且无不确定因素: fuzzy/distro/up/rev = %v/%v/%v/%v",
			packageNeedsManual("openssh-client", "openssh"), hasDistroSuffix("9.0p1"), up, rev)
	}
}

// 包名与产品名对不上时必须降级，而不是报 affected：
// linux-base 是内核配置辅助包、python-debian 是打包库，都不是本体。
func TestMatchPackagesDenyAliasNeedsManual(t *testing.T) {
	db := newVulnIntelTestDB(t)
	// 内核与 CPython 各一条"覆盖一切版本"的区间，专门用来抓错误映射。
	// 发布时间设为近期，避免年代规则先一步把结果降级，从而掩盖映射问题。
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2023-1001", Severity: "HIGH", Source: "nvd", PublishedAt: "2023-05-01T00:00:00.000"}, []VulnIntelRange{
		{Vendor: "linux", Product: "linux", StartIncl: "0.1", EndIncl: "99.9", Source: "nvd"},
	}); err != nil {
		t.Fatalf("Upsert linux: %v", err)
	}
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2023-1002", Severity: "MEDIUM", Source: "nvd", PublishedAt: "2023-05-01T00:00:00.000"}, []VulnIntelRange{
		{Vendor: "python", Product: "python", StartIncl: "0.1", EndIncl: "99.9", Source: "nvd"},
	}); err != nil {
		t.Fatalf("Upsert python: %v", err)
	}

	matches, err := db.MatchPackages([]Package{
		{Name: "linux-base", Version: "4.12.1"},
		{Name: "python-debian", Version: "1.0.1"},
		{Name: "python3-requests", Version: "2.31.0"},
	})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	// 排除表生效后，这三个包不应产生任何匹配（候选产品被删空），
	// 至少绝不能出现 affected。
	for _, m := range matches {
		switch m.Package.Name {
		case "linux-base", "python-debian", "python3-requests":
			t.Fatalf("%s 不应匹配到内核/CPython 产品: %+v", m.Package.Name, m)
		}
	}
}

// 带 Debian 修订的版本必须置 needs_patch_check，且不直接判 affected。
func TestMatchPackagesDistroSuffixNeedsPatchCheck(t *testing.T) {
	db := newVulnIntelTestDB(t)
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2023-38408", Severity: "CRITICAL", Source: "nvd", PublishedAt: "2023-07-19T00:00:00.000"}, []VulnIntelRange{
		{Vendor: "openbsd", Product: "openssh", StartIncl: "8.0", EndExcl: "11.0", Source: "nvd"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	matches, err := db.MatchPackages([]Package{{Name: "openssh-client", Version: "10.0p1-7+deb13u4"}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("应命中 1 条（版本落在区间内），实际 %d: %+v", len(matches), matches)
	}
	m := matches[0]
	if m.Status != "needs_manual" {
		t.Fatalf("带 deb 修订的版本应判 needs_manual，实际 %s", m.Status)
	}
	if !m.NeedsPatchCheck {
		t.Fatalf("带 deb 修订的版本必须置 needs_patch_check: %+v", m)
	}
}

// 年代久远的 CVE 落在区间内时降级为 needs_manual，不直接给 affected。
func TestMatchPackagesOldEraNeedsManual(t *testing.T) {
	db := newVulnIntelTestDB(t)
	if err := db.UpsertVulnIntel(VulnIntel{CVEID: "CVE-2001-0886", Severity: "HIGH", Source: "nvd", PublishedAt: "2001-12-31T00:00:00.000"}, []VulnIntelRange{
		{Vendor: "linux", Product: "linux", StartIncl: "0.1", EndIncl: "99.9", Source: "nvd"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	matches, err := db.MatchPackages([]Package{{Name: "linux-image-6.12.113", Version: "6.12.113"}})
	if err != nil {
		t.Fatalf("MatchPackages: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("应命中 1 条，实际 %d: %+v", len(matches), matches)
	}
	// 版本不带修订、包名走别名映射，因此这里唯一能触发降级的就是"年代久远"
	if matches[0].Status != "needs_manual" {
		t.Fatalf("2001 年的 CVE 应降级为 needs_manual，实际 %s: %+v", matches[0].Status, matches[0])
	}
}
