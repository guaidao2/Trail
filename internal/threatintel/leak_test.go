package threatintel

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 情报源的密钥常放在 URL 路径里（abuse.ch 就是 /v2/files/exports/<KEY>/...）。
// 一次网络失败如果把原始 URL 带进错误，这个 Key 就会被写进
// threat_intel_source.last_error、日志、REST 响应和 MCP 输出。
func TestHTTPErrorDoesNotLeakKeyInURL(t *testing.T) {
	doer := NewHTTPDoer("", 2*time.Second)
	const key = "SECRET-AUTH-KEY-9f3a"
	_, _, err := doer.getRaw(context.Background(),
		"http://127.0.0.1:1/v2/files/exports/"+key+"/recent.csv", nil)
	if err == nil {
		t.Fatal("连接必然失败，应返回错误")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("错误信息泄漏了认证密钥: %v", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("应保留主机以便定位，实际: %v", err)
	}
}

func TestURLhausFetchErrorHidesKey(t *testing.T) {
	// 与上面同一条链路，但从 provider 入口进，确认脱敏在真实调用路径上生效。
	p := NewURLhaus(NewHTTPDoer("", 2*time.Second), "http://127.0.0.1:1")
	const key = "SECRET-AUTH-KEY-9f3a"
	_, err := p.Fetch(context.Background(), key)
	if err == nil {
		t.Fatal("应返回错误")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("provider 的错误路径也泄漏了密钥: %v", err)
	}
}

// 这条覆盖的是另一条独立路径：URL 本身解析失败时，
// http.NewRequest 返回的 *url.Error 同样带着原始 URL 字符串。
func TestMalformedURLDoesNotLeakKey(t *testing.T) {
	doer := NewHTTPDoer("", 2*time.Second)
	const key = "SECRET-AUTH-KEY-9f3a"
	// 不闭合的 IPv6 字面量会让 url.Parse 直接失败。
	_, _, err := doer.getRaw(context.Background(),
		"http://[::1/v2/files/exports/"+key+"/recent.csv", nil)
	if err == nil {
		t.Fatal("非法 URL 应返回错误")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("解析失败分支泄漏了认证密钥: %v", err)
	}
}
