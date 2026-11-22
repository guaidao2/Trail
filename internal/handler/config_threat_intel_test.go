package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"trail/internal/config"
)

// 威胁情报的四个 Key 用固定字段而不是 map，就是为了让掩码机制认得出来。
// 这两条测试守住两端：读配置时不能明文回显，保存时掩码要能还原成原值。

func TestThreatIntelKeysAreMaskedInConfigResponse(t *testing.T) {
	cfg := &config.Config{}
	cfg.ThreatIntel.AbuseIPDBKey = "real-abuseipdb-key"
	cfg.ThreatIntel.VirusTotalKey = "real-virustotal-key"
	cfg.ThreatIntel.URLhausKey = "real-urlhaus-key"
	cfg.ThreatIntel.ThreatFoxKey = "real-threatfox-key"

	masked, err := maskedConfigResponse(configSecretSnapshot(cfg))
	if err != nil {
		t.Fatalf("掩码失败: %v", err)
	}
	raw, err := json.Marshal(masked)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var parsed struct {
		ThreatIntel map[string]interface{} `json:"threat_intel"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if parsed.ThreatIntel == nil {
		t.Fatal("配置响应里没有 threat_intel 段")
	}
	for _, field := range []string{"abuseipdb_key", "virustotal_key", "urlhaus_key", "threatfox_key"} {
		got, _ := parsed.ThreatIntel[field].(string)
		if got != maskedSecret {
			t.Errorf("%s 应被掩码，实际 %q", field, got)
		}
	}
}

func TestThreatIntelMaskedKeyIsRestoredOnSave(t *testing.T) {
	cfg := &config.Config{}
	cfg.ThreatIntel.VirusTotalKey = "real-virustotal-key"

	masked := maskedSecret
	req := &UpdateConfigRequest{
		ThreatIntel: &ThreatIntelConfigUpdate{
			// 前端回填的就是掩码；用户没改，保存时必须还原成原值。
			VirusTotalKey: &masked,
		},
	}
	if err := restoreConfigRequestSecrets(req, cfg); err != nil {
		t.Fatalf("还原失败: %v", err)
	}
	if req.ThreatIntel.VirusTotalKey == nil || *req.ThreatIntel.VirusTotalKey != "real-virustotal-key" {
		t.Fatalf("掩码应还原为原值，实际 %v", req.ThreatIntel.VirusTotalKey)
	}
}

// 从没存过 Key 却提交掩码，说明前端状态不对，应当明确报错而不是写入空值。
func TestThreatIntelMaskedKeyWithoutStoredValueFails(t *testing.T) {
	cfg := &config.Config{}
	masked := maskedSecret
	req := &UpdateConfigRequest{
		ThreatIntel: &ThreatIntelConfigUpdate{URLhausKey: &masked},
	}
	if err := restoreConfigRequestSecrets(req, cfg); err == nil {
		t.Fatal("没有已保存凭据时应报错")
	}
}

// 停用名单是整体替换语义：提交空数组表示全部恢复启用。
func TestThreatIntelDisabledSourcesReplace(t *testing.T) {
	cfg := &config.Config{}
	cfg.ThreatIntel.DisabledSources = []string{"otx", "virustotal"}
	empty := []string{}
	req := &UpdateConfigRequest{
		ThreatIntel: &ThreatIntelConfigUpdate{DisabledSources: &empty},
	}
	if err := restoreConfigRequestSecrets(req, cfg); err != nil {
		t.Fatalf("还原失败: %v", err)
	}
	// 还原只处理密钥，不改变切片语义；这里确认空数组没被误当成"未提交"。
	if req.ThreatIntel.DisabledSources == nil {
		t.Fatal("空数组应保持非 nil，才能表达「全部启用」")
	}
	if len(*req.ThreatIntel.DisabledSources) != 0 {
		t.Errorf("应为空列表，实际 %v", *req.ThreatIntel.DisabledSources)
	}
}

// 设置页保存必须落到 config.yaml，否则重启就回到旧值——而且不会有任何报错。
// 这条测试走完整的「改内存 → saveConfig → 重新 Load」路径，不只看内存。
func TestThreatIntelConfigPersistsToYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	initial := "server:\n  port: 8080\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatalf("写初始配置失败: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("加载初始配置失败: %v", err)
	}

	cfg.ThreatIntel = config.ThreatIntelConfig{
		Enabled:          true,
		Proxy:            "http://127.0.0.1:7890",
		Timeout:          "45s",
		FeedSyncInterval: "3h",
		FeedTTLDays:      45,
		CacheTTLSeconds:  1800,
		AbuseIPDBKey:     "abuse-key",
		VirusTotalKey:    "vt-key",
		URLhausKey:       "urlhaus-key",
		ThreatFoxKey:     "threatfox-key",
		DisabledSources:  []string{"otx", "virustotal"},
	}

	h := &ConfigHandler{config: cfg, configPath: path, logger: zap.NewNop()}
	if err := h.saveConfig(); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	// 重新从磁盘加载，等价于进程重启。
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	got := reloaded.ThreatIntel
	if !got.Enabled {
		t.Error("enabled 未落盘")
	}
	if got.Proxy != "http://127.0.0.1:7890" {
		t.Errorf("proxy 未落盘: %q", got.Proxy)
	}
	if got.Timeout != "45s" {
		t.Errorf("timeout 未落盘: %q", got.Timeout)
	}
	if got.FeedSyncInterval != "3h" {
		t.Errorf("feed_sync_interval 未落盘: %q", got.FeedSyncInterval)
	}
	if got.FeedTTLDays != 45 || got.CacheTTLSeconds != 1800 {
		t.Errorf("数字字段未落盘: ttl=%d cache=%d", got.FeedTTLDays, got.CacheTTLSeconds)
	}
	if got.AbuseIPDBKey != "abuse-key" || got.VirusTotalKey != "vt-key" ||
		got.URLhausKey != "urlhaus-key" || got.ThreatFoxKey != "threatfox-key" {
		t.Errorf("Key 未落盘: %+v", got)
	}
	if len(got.DisabledSources) != 2 || got.DisabledSources[0] != "otx" {
		t.Errorf("disabled_sources 未落盘: %v", got.DisabledSources)
	}
}

// 停用名单清空后也要能落盘成空列表，而不是被省略成「没配过」。
func TestThreatIntelDisabledSourcesPersistsAsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 8080\n"), 0o600); err != nil {
		t.Fatalf("写初始配置失败: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	cfg.ThreatIntel.DisabledSources = []string{"otx"}
	h := &ConfigHandler{config: cfg, configPath: path, logger: zap.NewNop()}
	if err := h.saveConfig(); err != nil {
		t.Fatalf("首次保存失败: %v", err)
	}

	cfg.ThreatIntel.DisabledSources = nil
	if err := h.saveConfig(); err != nil {
		t.Fatalf("二次保存失败: %v", err)
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if len(reloaded.ThreatIntel.DisabledSources) != 0 {
		t.Errorf("清空后应落盘为空列表，实际 %v", reloaded.ThreatIntel.DisabledSources)
	}
}

// 保存后旧版的 keys 节点必须被清掉，否则兼容逻辑会在下次加载时
// 用它把用户刚清空的 Key 填回来。
func TestSaveConfigRemovesLegacyKeysNode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	legacy := `threat_intel:
  enabled: true
  keys:
    abuseipdb: old-abuse
    virustotal: old-vt
`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("写初始配置失败: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	// 用户在设置页把 Key 清空
	cfg.ThreatIntel.AbuseIPDBKey = ""
	cfg.ThreatIntel.VirusTotalKey = ""

	h := &ConfigHandler{config: cfg, configPath: path, logger: zap.NewNop()}
	if err := h.saveConfig(); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取保存后的文件失败: %v", err)
	}
	if strings.Contains(string(raw), "keys:") {
		t.Errorf("保存后不应再有旧的 keys 节点，实际内容:\n%s", string(raw))
	}

	// 重新加载确认 Key 没有被旧值复活
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if reloaded.ThreatIntel.AbuseIPDBKey != "" || reloaded.ThreatIntel.VirusTotalKey != "" {
		t.Errorf("清空后的 Key 被旧 keys 复活了: %+v", reloaded.ThreatIntel)
	}
}
