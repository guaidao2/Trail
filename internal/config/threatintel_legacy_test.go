package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestThreatIntelLegacyKeysMapIsMigrated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `server:
  port: 8080
threat_intel:
  enabled: true
  keys:
    abuseipdb: legacy-abuse
    virustotal: legacy-vt
    urlhaus: legacy-urlhaus
    threatfox: legacy-threatfox
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	ti := cfg.ThreatIntel
	got := ti.SourceKeys()
	for source, want := range map[string]string{
		"abuseipdb":  "legacy-abuse",
		"virustotal": "legacy-vt",
		"urlhaus":    "legacy-urlhaus",
		"threatfox":  "legacy-threatfox",
	} {
		if got[source] != want {
			t.Errorf("旧 keys 未迁移：%s=%q，期望 %q", source, got[source], want)
		}
	}
}

func TestThreatIntelFixedFieldsWinOverLegacyKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `threat_intel:
  abuseipdb_key: new-value
  keys:
    abuseipdb: old-value
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got := cfg.ThreatIntel.AbuseIPDBKey; got != "new-value" {
		t.Errorf("固定字段应优先，实际 %q", got)
	}
}

// 显式写成空的固定字段必须压住旧 map：否则用户在设置页清空 Key 之后，
// 重启又会被旧的 keys 里的值填回去，等于永远清不掉。
func TestThreatIntelExplicitEmptyBeatsLegacyKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `threat_intel:
  abuseipdb_key: ""
  virustotal_key: ""
  keys:
    abuseipdb: old-abuse
    virustotal: old-vt
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got := cfg.ThreatIntel.AbuseIPDBKey; got != "" {
		t.Errorf("显式空值应压住旧 keys，实际 %q", got)
	}
	if got := cfg.ThreatIntel.VirusTotalKey; got != "" {
		t.Errorf("显式空值应压住旧 keys，实际 %q", got)
	}
}

// 旧 map 的键大小写不一致也要能迁移。
func TestThreatIntelLegacyKeysCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `threat_intel:
  keys:
    AbuseIPDB: legacy-abuse
    VirusTotal: legacy-vt
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got := cfg.ThreatIntel.AbuseIPDBKey; got != "legacy-abuse" {
		t.Errorf("大小写不同的旧键未迁移，实际 %q", got)
	}
	if got := cfg.ThreatIntel.VirusTotalKey; got != "legacy-vt" {
		t.Errorf("大小写不同的旧键未迁移，实际 %q", got)
	}
}

// 显式写 null / ~ 也算「字段出现过」：否则用户手写清空后，
// 旧 keys 里残留的值又会被填回来。
func TestThreatIntelExplicitNullBeatsLegacyKeys(t *testing.T) {
	for name, body := range map[string]string{
		"null": `threat_intel:
  abuseipdb_key: null
  keys:
    abuseipdb: old-abuse
`,
		"tilde": `threat_intel:
  abuseipdb_key: ~
  keys:
    abuseipdb: old-abuse
`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("写配置失败: %v", err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("加载失败: %v", err)
			}
			if got := cfg.ThreatIntel.AbuseIPDBKey; got != "" {
				t.Errorf("显式 %s 应压住旧 keys，实际 %q", name, got)
			}
		})
	}
}
