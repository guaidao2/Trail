package app

import (
	"path/filepath"
	"strings"
	"testing"

	"trail/internal/database"
	"trail/internal/security"
)

func TestBuildInspectScriptAllChecks(t *testing.T) {
	script := buildInspectScript(nil)
	for _, key := range []string{"[system]", "[load]", "[disk]", "[users]", "[ports]", "[logins]", "[cron]", "[suid]", "[last]"} {
		if !strings.Contains(script, key) {
			t.Fatalf("default inspection script is missing %s:\n%s", key, script)
		}
	}
}

func TestBuildInspectScriptSubset(t *testing.T) {
	script := buildInspectScript([]string{"disk", " Users ", ""})
	if !strings.Contains(script, "[disk]") || !strings.Contains(script, "[users]") {
		t.Fatalf("requested checks missing:\n%s", script)
	}
	for _, unwanted := range []string{"[system]", "[ports]", "[cron]", "[suid]"} {
		if strings.Contains(script, unwanted) {
			t.Fatalf("unrequested check %s leaked into script:\n%s", unwanted, script)
		}
	}
}

func TestBuildInspectScriptUnknownChecksIgnored(t *testing.T) {
	script := buildInspectScript([]string{"nope"})
	if strings.TrimSpace(script) != "" {
		t.Fatalf("unknown check should produce an empty script, got:\n%s", script)
	}
}

func TestHostStringSliceArg(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want int
	}{
		{"missing", map[string]interface{}{}, 0},
		{"string list", map[string]interface{}{"checks": "disk,users"}, 2},
		{"interface list", map[string]interface{}{"checks": []interface{}{"disk", "ports"}}, 2},
		{"typed list", map[string]interface{}{"checks": []string{"a", "b", "c"}}, 3},
	}
	for _, tc := range cases {
		if got := len(hostStringSliceArg(tc.args, "checks")); got != tc.want {
			t.Fatalf("%s: got %d items, want %d", tc.name, got, tc.want)
		}
	}
}

// Agent 侧的主机工具也必须带指纹固定，否则落库凭据会被发给未校验的主机。
func TestHostOptionsFromRecordCarriesHostKeyPin(t *testing.T) {
	box, err := security.LoadSecretBox(filepath.Join(t.TempDir(), "k.key"))
	if err != nil {
		t.Fatalf("LoadSecretBox: %v", err)
	}
	cipher, err := box.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	opts, err := hostOptionsFromRecord(box, &database.Host{
		Protocol:     "ssh",
		Address:      "10.0.0.9",
		Port:         22,
		Username:     "root",
		AuthType:     "password",
		SecretCipher: cipher,
		HostKey:      "SHA256:pinned",
	})
	if err != nil {
		t.Fatalf("hostOptionsFromRecord: %v", err)
	}
	if opts.HostKeyPin != "SHA256:pinned" {
		t.Fatalf("HostKeyPin = %q, want the stored fingerprint", opts.HostKeyPin)
	}
}
