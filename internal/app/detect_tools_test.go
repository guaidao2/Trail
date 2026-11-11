package app

import (
	"testing"

	"trail/internal/detect/logscan"
)

// 这些纯函数是安全边界上的判断，之前只有实现没有测试：
// 归一错一个词表，auth 日志就会静默扫出 0 条；路径白名单漏一个前缀，
// 只读权限就能读任意文件；链名不校验就是命令注入。
func TestNormalizeLogKind(t *testing.T) {
	cases := map[string]string{
		"web":     logscan.KindWeb,
		"WEB":     logscan.KindWeb,
		"auth":    logscan.KindSystem,
		"system":  logscan.KindSystem,
		"other":   "",
		"all":     "",
		"":        "",
		"unknown": "",
	}
	for in, want := range cases {
		if got := normalizeLogKind(in); got != want {
			t.Errorf("normalizeLogKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAllowedLogPath(t *testing.T) {
	allowed := []string{
		"/var/log/auth.log",
		"/var/log/nginx/access.log",
		"/var/adm/messages",
	}
	for _, p := range allowed {
		if !allowedLogPath(p) {
			t.Errorf("allowedLogPath(%q) 应放行", p)
		}
	}
	denied := []string{
		"",
		"/root/.ssh/id_rsa",
		"/etc/passwd",
		"/var/log/../../root/.ssh/id_rsa",
		"/var/logx/a.log",
		"/var/log",
	}
	for _, p := range denied {
		if allowedLogPath(p) {
			t.Errorf("allowedLogPath(%q) 应拒绝", p)
		}
	}
}

func TestValidIPTablesChain(t *testing.T) {
	ok := []string{"INPUT", "DOCKER-USER", "chain_1"}
	for _, c := range ok {
		if !validIPTablesChain(c) {
			t.Errorf("validIPTablesChain(%q) 应放行", c)
		}
	}
	bad := []string{"", "INPUT; rm -rf /", "INPUT -j ACCEPT", "a b", "INPUT\nDROP", string(make([]byte, 64))}
	for _, c := range bad {
		if validIPTablesChain(c) {
			t.Errorf("validIPTablesChain(%q) 应拒绝", c)
		}
	}
}
