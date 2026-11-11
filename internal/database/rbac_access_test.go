package database

import (
	"path/filepath"
	"testing"
	"time"

	"trail/internal/mcp"

	"go.uber.org/zap"
)

func newRBACTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "rbac.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRBACToolExecutionOwnershipAccess(t *testing.T) {
	db := newRBACTestDB(t)
	for _, exec := range []*mcp.ToolExecution{
		{ID: "exec-u1", ToolName: "one", Status: "completed", StartTime: time.Now(), OwnerUserID: "u1"},
		{ID: "exec-u2", ToolName: "two", Status: "completed", StartTime: time.Now(), OwnerUserID: "u2"},
		{ID: "exec-legacy", ToolName: "legacy", Status: "completed", StartTime: time.Now()},
	} {
		if err := db.SaveToolExecution(exec); err != nil {
			t.Fatal(err)
		}
	}
	access := RBACListAccess{UserID: "u1", Scope: RBACScopeAssigned}
	rows, err := db.LoadToolExecutionListPageForAccess(0, 20, "", "", access)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "exec-u1" {
		t.Fatalf("rows = %#v, want only exec-u1", rows)
	}
	summary, err := db.LoadToolStatsSummaryForAccess(10, access)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Summary.TotalCalls != 1 || summary.Summary.ToolCount != 1 || len(summary.TopTools) != 1 || summary.TopTools[0].ToolName != "one" {
		t.Fatalf("scoped summary = %#v", summary)
	}
	if !db.UserCanAccessToolExecution("u1", RBACScopeAssigned, "exec-u1") {
		t.Fatal("owner could not access execution")
	}
	if db.UserCanAccessToolExecution("u1", RBACScopeAssigned, "exec-u2") {
		t.Fatal("foreign execution was accessible")
	}
	if db.UserCanAccessToolExecution("u1", RBACScopeAssigned, "exec-legacy") {
		t.Fatal("ownerless legacy execution did not fail closed")
	}
}

func TestRBACUploadOwnership(t *testing.T) {
	db := newRBACTestDB(t)
	conversation, err := db.CreateConversation("upload", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertChatUploadArtifact("2026-07-10/"+conversation.ID+"/a.txt", conversation.ID, "u1"); err != nil {
		t.Fatal(err)
	}
	if conv, owner, ok := db.GetChatUploadArtifact("2026-07-10/" + conversation.ID + "/a.txt"); !ok || conv != conversation.ID || owner != "u1" {
		t.Fatalf("artifact = conv=%q owner=%q ok=%v", conv, owner, ok)
	}
	if err := db.RenameChatUploadArtifactPath("2026-07-10/"+conversation.ID+"/a.txt", "2026-07-10/"+conversation.ID+"/b.txt"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := db.GetChatUploadArtifact("2026-07-10/" + conversation.ID + "/b.txt"); !ok {
		t.Fatal("renamed artifact metadata missing")
	}
}

func TestSystemRoleBootstrapDoesNotLeakManagementReadPermissions(t *testing.T) {
	db := newRBACTestDB(t)
	catalog := map[string]string{
		"auth:self": "self", "host:read": "hosts", "host:write": "host writes",
		"agent:local-execute": "local tools",
		"rbac:read":           "rbac", "config:read": "config", "audit:read": "audit", "terminal:execute": "terminal",
		"mcp:execute": "invoke", "mcp:write": "manage", "mcp:external:execute": "external invoke",
		"workflow:execute": "run", "workflow:write": "manage definitions", "knowledge:write": "manage knowledge",
	}
	if err := db.BootstrapRBAC("hash", catalog); err != nil {
		t.Fatal(err)
	}
	viewer, err := db.CreateRBACUser("viewer-policy", "Viewer", "hash", true, []string{RBACSystemRoleViewer})
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess, err := db.ResolveRBACAccess(viewer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !viewerAccess.Permissions["host:read"] || viewerAccess.Permissions["rbac:read"] || viewerAccess.Permissions["config:read"] || viewerAccess.Permissions["audit:read"] {
		t.Fatalf("unexpected viewer permissions: %#v", viewerAccess.Permissions)
	}
	auditor, err := db.CreateRBACUser("auditor-policy", "Auditor", "hash", true, []string{RBACSystemRoleAuditor})
	if err != nil {
		t.Fatal(err)
	}
	auditorAccess, err := db.ResolveRBACAccess(auditor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !auditorAccess.Permissions["audit:read"] || auditorAccess.Permissions["config:read"] || auditorAccess.Permissions["rbac:read"] {
		t.Fatalf("unexpected auditor permissions: %#v", auditorAccess.Permissions)
	}
	operator, err := db.CreateRBACUser("operator-policy", "Operator", "hash", true, []string{RBACSystemRoleOperator})
	if err != nil {
		t.Fatal(err)
	}
	operatorAccess, err := db.ResolveRBACAccess(operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !operatorAccess.Permissions["mcp:execute"] || operatorAccess.Permissions["mcp:write"] || operatorAccess.Permissions["mcp:external:execute"] {
		t.Fatalf("unexpected operator MCP permissions: %#v", operatorAccess.Permissions)
	}
	if !operatorAccess.Permissions["workflow:execute"] || operatorAccess.Permissions["workflow:write"] || operatorAccess.Permissions["knowledge:write"] {
		t.Fatalf("operator received global definition mutation permissions: %#v", operatorAccess.Permissions)
	}
	if !operatorAccess.Permissions["agent:local-execute"] {
		t.Fatalf("operator is missing explicit local tool permission: %#v", operatorAccess.Permissions)
	}
}

func TestPermissionScopeDoesNotWidenAcrossUnrelatedRoles(t *testing.T) {
	db := newRBACTestDB(t)
	catalog := map[string]string{"auth:self": "self", "host:read": "read", "host:write": "write", "audit:read": "audit"}
	if err := db.BootstrapRBAC("hash", catalog); err != nil {
		t.Fatal(err)
	}
	ownWrite, err := db.UpsertRBACRole("", "own-writer", "", RBACScopeOwn, []string{"host:write"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateRBACUser("mixed-scope", "Mixed", "hash", true, []string{RBACSystemRoleAuditor, ownWrite.ID})
	if err != nil {
		t.Fatal(err)
	}
	access, err := db.ResolveRBACAccess(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if access.Scope != RBACScopeAll {
		t.Fatalf("compatibility scope = %q, want all", access.Scope)
	}
	if got := access.PermissionScopes["host:read"]; got != RBACScopeAll {
		t.Fatalf("host:read scope = %q, want all", got)
	}
	if got := access.PermissionScopes["host:write"]; got != RBACScopeOwn {
		t.Fatalf("host:write scope widened to %q, want own", got)
	}
}

func TestRoleRejectsUnknownPermission(t *testing.T) {
	db := newRBACTestDB(t)
	if err := db.BootstrapRBAC("hash", map[string]string{"auth:self": "self"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertRBACRole("", "future-role", "", RBACScopeAssigned, []string{"future:permission"}); err == nil {
		t.Fatal("unknown permission was persisted")
	}
	if _, err := db.Exec(`INSERT INTO rbac_permissions (key, description, created_at) VALUES ('stale:permission', '', ?)`, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.BootstrapRBAC("hash", map[string]string{"auth:self": "self"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM rbac_permissions WHERE key = 'stale:permission'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale permission survived bootstrap: count=%d err=%v", count, err)
	}
}




