package threatintel

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 订阅源的解析直接决定入库质量：解析错一位，页面上就是一条假情报。
// 这里用各源的真实响应形状做夹具，不用随手编的样例。

func TestSpamhausDropParse(t *testing.T) {
	// 真实响应前几行（取自 spamhaus.org/drop/drop.txt）。
	body := `; Spamhaus DROP List 2026/11/21 - (c) 2026 The Spamhaus Project SLU
; https://www.spamhaus.org/drop/drop.txt
1.10.16.0/20 ; SBL256894
1.19.0.0/16 ; SBL434604
2.26.75.0/24 ; SBL698389
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	p := NewSpamhausDROP(NewHTTPDoer("", 5*time.Second), srv.URL)
	entries, err := p.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("应解析出 3 条，实际 %d", len(entries))
	}
	if entries[0].Normalized != "1.10.16.0/20" {
		t.Errorf("CIDR 解析错: %q", entries[0].Normalized)
	}
	if entries[0].Tags != "SBL256894" {
		t.Errorf("SBL 编号应进 tags: %q", entries[0].Tags)
	}
	if entries[0].IndicatorType != "cidr" || entries[0].Category != "cidr" {
		t.Errorf("类型/类别不符: %+v", entries[0])
	}
}

func TestSpamhausDropEmptyIsError(t *testing.T) {
	// 全空响应多半意味着格式变了或拿到了登录页，不能当成"今天没有情报"。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("; only comments\n"))
	}))
	defer srv.Close()
	p := NewSpamhausDROP(NewHTTPDoer("", 5*time.Second), srv.URL)
	if _, err := p.Fetch(context.Background(), ""); err == nil {
		t.Error("空列表应当报错")
	}
}

func TestFeodoParse(t *testing.T) {
	body := `################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)     #
################################################################
#
# DstIP
162.243.103.246
178.62.3.223
not-an-ip
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	p := NewFeodoTracker(NewHTTPDoer("", 5*time.Second), srv.URL)
	entries, err := p.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("应只保留 2 个合法 IP，实际 %d", len(entries))
	}
	if entries[0].Normalized != "162.243.103.246" || entries[0].Category != "c2" {
		t.Errorf("条目不符: %+v", entries[0])
	}
	if entries[0].Confidence != 95 {
		t.Errorf("Feodo 应为高置信度，实际 %d", entries[0].Confidence)
	}
}

func TestFeodoEmptyIsOK(t *testing.T) {
	// 当天没有在线 C2 时列表为空是合法状态。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# no entries today\n"))
	}))
	defer srv.Close()
	p := NewFeodoTracker(NewHTTPDoer("", 5*time.Second), srv.URL)
	entries, err := p.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("空列表不应报错: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("应为空，实际 %d", len(entries))
	}
}

func TestURLhausRequiresKey(t *testing.T) {
	p := NewURLhaus(NewHTTPDoer("", time.Second), "")
	if _, err := p.Fetch(context.Background(), ""); err == nil {
		t.Fatal("没配 key 应当返回错误，而不是去打网络")
	}
}

func TestURLhausParseByHeader(t *testing.T) {
	// 列顺序故意和旧版不同，验证解析走表头而不是位置。
	csvBody := `# comment line
"id","dateadded","url","url_status","threat","tags","last_online"
"1","2026-11-20 10:00:00","http://evil.example/a","online","malware_download","emotet","2026-11-21 09:00:00"
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(csvBody))
	}))
	defer srv.Close()

	p := NewURLhaus(NewHTTPDoer("", 5*time.Second), srv.URL)
	entries, err := p.Fetch(context.Background(), "dummy-key")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("应解析 1 条，实际 %d", len(entries))
	}
	e := entries[0]
	if e.Normalized != "http://evil.example/a" {
		t.Errorf("URL 解析错: %q", e.Normalized)
	}
	if e.Malware != "malware_download" {
		t.Errorf("threat 列应映射到 Malware: %q", e.Malware)
	}
	if e.FirstSeen != "2026-11-20 10:00:00" {
		t.Errorf("dateadded 应映射到 FirstSeen: %q", e.FirstSeen)
	}
	if e.Tags != "emotet" {
		t.Errorf("tags 解析错: %q", e.Tags)
	}
}

func TestThreatFoxParseZipByHeader(t *testing.T) {
	csvBody := `"first_seen","ioc_id","ioc","ioc_type","threat_type","malware","malware_printable","last_seen","confidence_level"
"2026-11-20 01:02:03","42","203.0.113.9:443","ip:port","botnet_cc","win.emotet","Emotet","2026-11-21 04:05:06","90"
`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create("full.csv")
	if err != nil {
		t.Fatalf("建 zip 失败: %v", err)
	}
	if _, err := fw.Write([]byte(csvBody)); err != nil {
		t.Fatalf("写 zip 失败: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("收尾 zip 失败: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	p := NewThreatFox(NewHTTPDoer("", 5*time.Second), srv.URL)
	entries, err := p.Fetch(context.Background(), "dummy-key")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("应解析 1 条，实际 %d", len(entries))
	}
	e := entries[0]
	if e.IndicatorType != "ip" {
		t.Errorf("ip:port 应收敛为 ip，实际 %q", e.IndicatorType)
	}
	if e.Normalized != "203.0.113.9" {
		t.Errorf("ip:port 入库前应剥掉端口，实际 %q", e.Normalized)
	}
	if e.Category != "botnet_cc" {
		t.Errorf("类别解析错: %q", e.Category)
	}
	if e.Malware != "Emotet" {
		t.Errorf("家族应优先取 malware_printable: %q", e.Malware)
	}
	if e.Confidence != 90 {
		t.Errorf("置信度解析错: %d", e.Confidence)
	}
}

func TestUnzipFirstCSVRejectsNonZip(t *testing.T) {
	if _, err := unzipFirstCSV([]byte("not a zip")); err == nil {
		t.Error("非 zip 内容应报错")
	}
}

func TestParseCSVSkipsCommentLines(t *testing.T) {
	records, err := parseCSVRecords([]byte("# comment\n\"a\",\"b\"\n\"1\",\"2\"\n"))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("注释应被剔除，实际 %d 行", len(records))
	}
	if records[1][0] != "1" {
		t.Errorf("数据行不符: %v", records[1])
	}
}

func TestConfidenceFrom(t *testing.T) {
	cases := map[string]int{"": 70, "90": 90, "0": 0, "150": 100, "abc": 70}
	for in, want := range cases {
		if got := confidenceFrom(in, 70); got != want {
			t.Errorf("confidenceFrom(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestNormalizeThreatFoxType(t *testing.T) {
	cases := map[string]string{
		"ip:port": "ip", "IPv4": "ip", "domain": "domain",
		"sha256_hash": "sha256", "md5_hash": "md5", "sha1": "sha1",
		"URL": "url", "weird": "weird",
	}
	for in, want := range cases {
		if got := normalizeThreatFoxType(in); got != want {
			t.Errorf("normalizeThreatFoxType(%q) = %q, want %q", in, got, want)
		}
	}
}

// 真实网络测试：拉两个免 key 的订阅源，确认解析器对着线上格式仍然成立。
func TestLiveFeedsParseRealData(t *testing.T) {
	liveEnabled(t)
	doer := NewHTTPDoer("", 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	drop := NewSpamhausDROP(doer, "")
	entries, err := drop.Fetch(ctx, "")
	if err != nil {
		t.Fatalf("真实拉取 spamhaus 失败: %v", err)
	}
	if len(entries) < 100 {
		t.Errorf("DROP 列表条数异常偏少：%d", len(entries))
	}
	for _, e := range entries[:3] {
		if !strings.Contains(e.Normalized, "/") {
			t.Errorf("条目不像是 CIDR: %q", e.Normalized)
		}
	}
	t.Logf("spamhaus 条目数: %d，首条 %s", len(entries), entries[0].Normalized)

	feodo := NewFeodoTracker(doer, "")
	fEntries, err := feodo.Fetch(ctx, "")
	if err != nil {
		t.Fatalf("真实拉取 feodo 失败: %v", err)
	}
	t.Logf("feodo 条目数: %d", len(fEntries))
}
