package hostclient

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestStripTelnetIAC(t *testing.T) {
	// IAC WILL ECHO + "login: " + IAC DO NAWS
	raw := []byte{telnetIAC, telnetWILL, 1}
	raw = append(raw, []byte("login: ")...)
	raw = append(raw, telnetIAC, telnetDO, 31)
	raw = append(raw, []byte("root\r\n")...)

	got := stripTelnetIAC(raw)
	if strings.ContainsRune(got, rune(telnetIAC)) {
		t.Fatalf("IAC bytes leaked into output: %q", got)
	}
	if !strings.Contains(got, "login: ") || !strings.Contains(got, "root") {
		t.Fatalf("readable text lost: %q", got)
	}
	if strings.Contains(got, "\r") {
		t.Fatalf("carriage returns should be stripped: %q", got)
	}
}

func TestStripTelnetIACSubnegotiation(t *testing.T) {
	raw := []byte{telnetIAC, telnetSB, 24, 1, 2, 3, telnetIAC, telnetSE}
	raw = append(raw, []byte("TERM=dumb\n")...)
	if got := stripTelnetIAC(raw); got != "TERM=dumb\n" {
		t.Fatalf("subnegotiation not stripped: %q", got)
	}
}

func TestTelnetNegotiationReply(t *testing.T) {
	raw := []byte{telnetIAC, telnetDO, 3, telnetIAC, telnetWILL, 1}
	reply := telnetNegotiationReply(raw)
	want := []byte{telnetIAC, telnetWONT, 3, telnetIAC, telnetDONT, 1}
	if string(reply) != string(want) {
		t.Fatalf("reply = %v, want %v", reply, want)
	}
	if got := telnetNegotiationReply([]byte("plain text")); len(got) != 0 {
		t.Fatalf("plain text should not produce a reply: %v", got)
	}
}

func TestCleanTelnetOutput(t *testing.T) {
	in := "echo __CSAI_BEGIN_1__\nreboot required\n__CSAI_END_1__\n\n"
	out := cleanTelnetOutput(in)
	if strings.Contains(out, "__CSAI_") || strings.Contains(out, "echo ") {
		t.Fatalf("echoed markers should be removed: %q", out)
	}
	if !strings.Contains(out, "reboot required") {
		t.Fatalf("payload line lost: %q", out)
	}
}

func TestParseProbeOutput(t *testing.T) {
	stdout := "welcome banner\n__CSAI_OS__Linux 6.1.0-18-amd64\n__CSAI_OSREL__PRETTY_NAME=\"Debian GNU/Linux 12\"\n__CSAI_USER__root\n__CSAI_HOST__web-01\n"
	fields := parseProbeOutput(stdout)
	if fields["OS"] != "Linux 6.1.0-18-amd64" {
		t.Fatalf("OS = %q", fields["OS"])
	}
	if fields["USER"] != "root" || fields["HOST"] != "web-01" {
		t.Fatalf("user/host = %q / %q", fields["USER"], fields["HOST"])
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/etc/nginx/nginx.conf": "'/etc/nginx/nginx.conf'",
		"/tmp/it's here":        `'/tmp/it'\''s here'`,
		"":                      "''",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Fatalf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildUploadScript(t *testing.T) {
	content := []byte("server { listen 80; }\n")
	script := buildUploadScript("/etc/nginx/conf.d/site.conf", content, "644")

	if !strings.Contains(script, "mkdir -p '/etc/nginx/conf.d'") {
		t.Fatalf("parent directory not created: %s", script)
	}
	if !strings.Contains(script, "chmod '644' '/etc/nginx/conf.d/site.conf'") {
		t.Fatalf("mode not applied: %s", script)
	}
	encoded := base64.StdEncoding.EncodeToString(content)
	if !strings.Contains(script, encoded) {
		t.Fatalf("payload missing from script: %s", script)
	}
}

func TestOptionsValidate(t *testing.T) {
	if err := (Options{Address: ""}).Validate(); err == nil {
		t.Fatal("empty address must fail")
	}
	if err := (Options{Address: "10.0.0.1", Protocol: "rdp"}).Validate(); err == nil {
		t.Fatal("unsupported protocol must fail")
	}
	if err := (Options{Address: "10.0.0.1", Protocol: "ssh"}).Validate(); err == nil {
		t.Fatal("ssh without user/credentials must fail")
	}
	if err := (Options{Address: "10.0.0.1", Protocol: "ssh", Username: "root", Password: "x"}).Validate(); err != nil {
		t.Fatalf("valid ssh options rejected: %v", err)
	}
	if err := (Options{Address: "10.0.0.1", Protocol: "telnet"}).Validate(); err != nil {
		t.Fatalf("telnet without credentials should pass validation: %v", err)
	}
}

func TestJoinHostPort(t *testing.T) {
	if got := joinHostPort("10.0.0.1", 22); got != "10.0.0.1:22" {
		t.Fatalf("ipv4 = %q", got)
	}
	if got := joinHostPort("2001:db8::1", 22); got != "[2001:db8::1]:22" {
		t.Fatalf("ipv6 = %q", got)
	}
}

func TestNormalizedDefaults(t *testing.T) {
	ssh := Options{Protocol: "ssh", Address: " 10.0.0.1 "}.normalized()
	if ssh.Port != 22 || ssh.Timeout <= 0 || ssh.Address != "10.0.0.1" {
		t.Fatalf("ssh defaults = %#v", ssh)
	}
	telnet := Options{Protocol: "telnet", Address: "10.0.0.2"}.normalized()
	if telnet.Port != 23 {
		t.Fatalf("telnet default port = %d, want 23", telnet.Port)
	}
}

func TestVerifyHostKeyPin(t *testing.T) {
	const pinned = "SHA256:abcdef"
	if err := verifyHostKeyPin("", pinned); err != nil {
		t.Fatalf("未固定指纹时应接受任意主机密钥: %v", err)
	}
	if err := verifyHostKeyPin(pinned, pinned); err != nil {
		t.Fatalf("指纹一致时应放行: %v", err)
	}
	if err := verifyHostKeyPin("  "+pinned+"  ", pinned); err != nil {
		t.Fatalf("固定值两侧空白应被忽略: %v", err)
	}
	err := verifyHostKeyPin(pinned, "SHA256:deadbeef")
	if err == nil {
		t.Fatal("指纹不一致必须拒绝连接（否则凭据会发给被替换的主机）")
	}
	if !strings.Contains(err.Error(), "主机密钥不匹配") {
		t.Fatalf("错误信息应说明密钥不匹配, got %v", err)
	}
}
