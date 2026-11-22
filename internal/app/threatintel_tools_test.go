package app

import (
	"testing"

	"trail/internal/config"
)

// 签名是「配置变了就重建服务」的唯一判据，两条性质都不能破：
// 同样的配置必须得到同样的签名（map 迭代顺序不能影响结果），
// 影响行为的配置必须进签名（否则改了不生效）。

func TestThreatIntelConfigSignatureStableAcrossMapOrder(t *testing.T) {
	// Endpoints 仍是 map，迭代顺序不能影响签名；Key 已改成固定字段。
	a := config.ThreatIntelConfig{
		VirusTotalKey: "k1",
		AbuseIPDBKey:  "k2",
		Endpoints:     map[string]string{"internetdb": "https://a", "otx": "https://b"},
	}
	b := config.ThreatIntelConfig{
		AbuseIPDBKey:  "k2",
		VirusTotalKey: "k1",
		Endpoints:     map[string]string{"otx": "https://b", "internetdb": "https://a"},
	}
	if threatIntelConfigSignature(a) != threatIntelConfigSignature(b) {
		t.Fatal("map 迭代顺序不同不应改变签名，否则服务会被反复重建")
	}
}

func TestThreatIntelConfigSignatureDetectsChanges(t *testing.T) {
	base := config.ThreatIntelConfig{Proxy: "http://127.0.0.1:7890", Timeout: "30s"}
	baseSig := threatIntelConfigSignature(base)

	cases := map[string]config.ThreatIntelConfig{
		"代理变了":            {Proxy: "http://127.0.0.1:7891", Timeout: "30s"},
		"超时变了":            {Proxy: "http://127.0.0.1:7890", Timeout: "60s"},
		"多了一个 key":        {Proxy: "http://127.0.0.1:7890", Timeout: "30s", VirusTotalKey: "k"},
		"换了 abuse.ch key": {Proxy: "http://127.0.0.1:7890", Timeout: "30s", URLhausKey: "abc"},
		"停用名单变了":          {Proxy: "http://127.0.0.1:7890", Timeout: "30s", DisabledSources: []string{"otx"}},
	}
	for name, cfg := range cases {
		if threatIntelConfigSignature(cfg) == baseSig {
			t.Errorf("%s 应改变签名，否则改配置不会触发服务重建", name)
		}
	}
}

func TestThreatIntelConfigSignatureIncludesDisabledSources(t *testing.T) {
	a := config.ThreatIntelConfig{DisabledSources: []string{"otx"}}
	b := config.ThreatIntelConfig{DisabledSources: []string{"otx", "feodo"}}
	if threatIntelConfigSignature(a) == threatIntelConfigSignature(b) {
		t.Fatal("停用名单必须进签名，否则改完不生效")
	}
}

func TestDBIdentityHandlesNil(t *testing.T) {
	if got := dbIdentity(nil); got != "nil" {
		t.Errorf("nil DB 应返回固定标识，实际 %q", got)
	}
}
