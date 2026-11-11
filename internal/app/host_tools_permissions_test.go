package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"trail/internal/authctx"
	"trail/internal/database"
	"trail/internal/mcp/builtin"

	"go.uber.org/zap"
)

// 主机工具的权限边界必须三层一致：只读工具要 host:read，执行/传输类要 host:exec。
// 之前这里是反复回归的地方（probe 一度要求 host:exec），用表驱动锁死。
func TestHostToolAuthorizationPermissions(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "host-tools-authz.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	authorize := mcpToolAuthorizer(db)

	principal := func(perms ...string) authctx.Principal {
		granted := map[string]bool{}
		for _, p := range perms {
			granted[p] = true
		}
		return authctx.NewPrincipal("u1", "u1", database.RBACScopeAll, granted)
	}
	args := map[string]interface{}{"id": "host-missing", "host_id": "host-missing"}

	cases := []struct {
		tool       string
		granted    string
		wantDenied string // 空串表示应当放行
	}{
		{builtin.ToolHostList, "host:read", ""},
		{builtin.ToolHostGet, "host:read", ""},
		{builtin.ToolHostProbe, "host:read", ""},
		{builtin.ToolHostInspect, "host:read", ""},
		{builtin.ToolHostList, "host:exec", "host:read"},
		{builtin.ToolHostGet, "host:exec", "host:read"},
		{builtin.ToolHostProbe, "host:exec", "host:read"},
		{builtin.ToolHostExec, "host:exec", ""},
		{builtin.ToolHostUpload, "host:exec", ""},
		{builtin.ToolHostDownload, "host:exec", ""},
		{builtin.ToolHostExec, "host:read", "host:exec"},
		{builtin.ToolHostDownload, "host:read", "host:exec"},
	}
	for _, tc := range cases {
		ctx := authctx.WithPrincipal(context.Background(), principal(tc.granted))
		err := authorize(ctx, tc.tool, args)
		if tc.wantDenied == "" {
			// 放行路径可能因资源不存在等其它原因失败，只要不是缺权限即可。
			if err != nil && strings.Contains(err.Error(), "missing permission") {
				t.Errorf("%s with %s should not be denied for permission: %v", tc.tool, tc.granted, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantDenied) {
			t.Errorf("%s with %s = %v, want denial mentioning %s", tc.tool, tc.granted, err, tc.wantDenied)
		}
	}
}
