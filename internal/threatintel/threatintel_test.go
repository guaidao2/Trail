package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trail/internal/database"
)

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		why  string
	}{
		{"192.168.1.10", true, "RFC1918"},
		{"10.0.0.1", true, "RFC1918"},
		{"172.16.5.4", true, "RFC1918"},
		{"127.0.0.1", true, "回环"},
		{"169.254.1.1", true, "链路本地"},
		{"100.64.0.1", true, "CGNAT"},
		{"192.0.2.10", true, "文档保留段"},
		{"198.18.0.1", true, "测试保留段"},
		{"0.0.0.0", true, "未指定"},
		{"8.8.8.8", false, "公网"},
		{"1.1.1.1", false, "公网"},
		{"2606:4700:4700::1111", false, "公网 IPv6"},
		{"", false, "空值不当作私网"},
		{"not-an-ip", false, "非法值不当作私网"},
	}
	for _, c := range cases {
		if got := isPrivateIP(c.ip); got != c.want {
			t.Errorf("isPrivateIP(%q) = %v, want %v (%s)", c.ip, got, c.want, c.why)
		}
	}
}

func TestOverallVerdict(t *testing.T) {
	mk := func(v string) *Result { return &Result{Verdict: v} }
	cases := []struct {
		name  string
		res   []*Result
		feeds []*database.ThreatIntelFeedEntry
		want  string
	}{
		{"空结果算未知", nil, nil, database.ThreatVerdictUnknown},
		{"恶意优先于其它", []*Result{mk(database.ThreatVerdictClean), mk(database.ThreatVerdictMalicious)}, nil, database.ThreatVerdictMalicious},
		{"可疑优先于干净", []*Result{mk(database.ThreatVerdictClean), mk(database.ThreatVerdictSuspicious)}, nil, database.ThreatVerdictSuspicious},
		{"暴露面优先于干净", []*Result{mk(database.ThreatVerdictClean), mk(VerdictExposure)}, nil, VerdictExposure},
		{"feed 命中直接算恶意", []*Result{mk(database.ThreatVerdictClean)}, []*database.ThreatIntelFeedEntry{{Source: "urlhaus"}}, database.ThreatVerdictMalicious},
		{"未知不压过干净", []*Result{mk(database.ThreatVerdictUnknown), mk(database.ThreatVerdictClean)}, nil, database.ThreatVerdictClean},
	}
	for _, c := range cases {
		if got := overallVerdict(c.res, c.feeds); got != c.want {
			t.Errorf("%s: overallVerdict = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestSummarizeInternetDB(t *testing.T) {
	// 真实响应形状，取自 internetdb.shodan.io/60.205.92.121。
	raw := `{"cpes":["cpe:/a:f5:nginx:1.20.1"],"hostnames":["cesuan888.cn"],"ip":"60.205.92.121","ports":[80,443],"tags":["eol-product"],"vulns":["CVE-2025-23419","CVE-2021-3618"]}`
	var d internetDBResponse
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("解析真实响应失败: %v", err)
	}
	got := summarizeInternetDB(d)
	for _, want := range []string{"80/443", "CVE-2025-23419", "nginx", "eol-product"} {
		if !strings.Contains(got, want) {
			t.Errorf("摘要缺少 %q，实际: %s", want, got)
		}
	}
}

func TestSummarizeInternetDBEmpty(t *testing.T) {
	got := summarizeInternetDB(internetDBResponse{})
	if !strings.Contains(got, "未发现") {
		t.Errorf("空白响应应给出明确说明，实际: %s", got)
	}
}

// TestInternetDBQuery 用 httptest 起一个假源，验证三种真实响应形状的处理：
// 200 有数据、404 无记录、500 故障。
func TestInternetDBQuery(t *testing.T) {
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "ok":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"cpes":[],"hostnames":["dns.google"],"ip":"8.8.8.8","ports":[53,443],"tags":["pqc"],"vulns":[]}`))
		case "notfound":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"No information available"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	p := NewInternetDB(NewHTTPDoer("", 5*time.Second), srv.URL)
	ctx := context.Background()
	ind := Indicator{Type: "ip", Value: "8.8.8.8", Normalized: "8.8.8.8"}

	mode = "ok"
	res, err := p.Query(ctx, ind, "")
	if err != nil {
		t.Fatalf("200 响应不应报错: %v", err)
	}
	if res.Verdict != VerdictExposure {
		t.Errorf("暴露面源的 verdict 应为 %q，实际 %q", VerdictExposure, res.Verdict)
	}
	if res.Category != database.ThreatCategoryExposure {
		t.Errorf("category 应为 exposure，实际 %q", res.Category)
	}
	if !strings.Contains(res.Summary, "53/443") {
		t.Errorf("摘要应含端口，实际: %s", res.Summary)
	}
	if res.ExpiresAt == nil || res.ExpiresAt.IsZero() {
		t.Error("成功结果必须带过期时间，否则缓存永不过期")
	}

	mode = "notfound"
	res, err = p.Query(ctx, ind, "")
	if err != nil {
		t.Fatalf("404 应作为负缓存结果而非错误: %v", err)
	}
	if res.Verdict != database.ThreatVerdictUnknown {
		t.Errorf("404 的 verdict 应为 unknown，实际 %q", res.Verdict)
	}

	mode = "error"
	if _, err = p.Query(ctx, ind, ""); err == nil {
		t.Error("5xx 应当返回错误")
	}
}

// TestInternetDBQueryRejectsNonIP 确认非 IP 输入会被挡下，而不是拼进 URL。
func TestInternetDBQueryRejectsNonIP(t *testing.T) {
	p := NewInternetDB(NewHTTPDoer("", time.Second), "http://127.0.0.1:1")
	_, err := p.Query(context.Background(), Indicator{Type: "domain", Value: "evil.example.com", Normalized: "evil.example.com"}, "")
	if err == nil {
		t.Fatal("域名输入应被拒绝")
	}
	if !strings.Contains(err.Error(), "只接受 IP") {
		t.Errorf("错误信息应说明只接受 IP，实际: %v", err)
	}
}

func TestTruncatePayload(t *testing.T) {
	small := []byte("hello")
	if got := truncatePayload(small); got != "hello" {
		t.Errorf("小响应不应被截断，实际 %q", got)
	}
	big := make([]byte, 20*1024)
	for i := range big {
		big[i] = 'x'
	}
	if got := truncatePayload(big); len(got) != 16*1024 {
		t.Errorf("大响应应截断到 16KB，实际 %d", len(got))
	}
}
