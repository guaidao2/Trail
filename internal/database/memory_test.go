package database

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// 三级记忆的永久性规则是这块的核心约定：
// critical / long_term 永不自动过期，short_term 才写过期时间；
// 同一个键重复写入是更新而不是新增；作用域 host 必须带 host_id。
func TestMemoryTiersPersistenceAndDedupe(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "memory.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	critical, created, err := db.UpsertMemory(MemoryUpsert{
		Tier: MemoryTierCritical, Key: "prod-db-no-restart",
		Content: "生产库 db-01 禁止重启，变更需走窗口",
	})
	if err != nil || !created {
		t.Fatalf("写入关键记忆失败: created=%v err=%v", created, err)
	}
	if critical.ExpiresAt != "" {
		t.Fatalf("关键记忆不应有过期时间，实际 %q", critical.ExpiresAt)
	}

	longTerm, _, err := db.UpsertMemory(MemoryUpsert{
		Tier: MemoryTierLongTerm, Key: "office-subnet",
		Content: "办公网段 10.10.0.0/16，禁止封禁",
	})
	if err != nil {
		t.Fatalf("写入长期记忆失败: %v", err)
	}
	if longTerm.ExpiresAt != "" {
		t.Fatalf("长期记忆不应有过期时间，实际 %q", longTerm.ExpiresAt)
	}

	shortTerm, _, err := db.UpsertMemory(MemoryUpsert{
		Tier: MemoryTierShortTerm, Key: "this-week-alert",
		Content: "本周在排查 host-a 的异常登录",
	})
	if err != nil {
		t.Fatalf("写入短期记忆失败: %v", err)
	}
	if shortTerm.ExpiresAt == "" {
		t.Fatal("短期记忆必须有过期时间")
	}

	// 同键更新：不新增行，内容被覆盖，等级不变。
	updated, created, err := db.UpsertMemory(MemoryUpsert{
		Tier: MemoryTierCritical, Key: "prod-db-no-restart",
		Content: "生产库 db-01 禁止重启（含只读实例），变更需走窗口",
	})
	if err != nil {
		t.Fatalf("更新记忆失败: %v", err)
	}
	if created {
		t.Fatal("同键写入不应新建记录")
	}
	if updated.ID != critical.ID {
		t.Fatalf("去重失败：%s != %s", updated.ID, critical.ID)
	}
	if updated.Content == critical.Content {
		t.Fatal("内容应被覆盖")
	}
	if updated.ExpiresAt != "" {
		t.Fatalf("更新后关键记忆仍不应过期，实际 %q", updated.ExpiresAt)
	}

	// 作用域校验：host 必须带 host_id。
	if _, _, err := db.UpsertMemory(MemoryUpsert{
		Tier: MemoryTierLongTerm, Scope: MemoryScopeHost, Key: "k", Content: "c",
	}); err == nil {
		t.Fatal("scope=host 缺 host_id 应被拒绝")
	}
	if _, _, err := db.UpsertMemory(MemoryUpsert{
		Tier: "unknown", Key: "k", Content: "c",
	}); err == nil {
		t.Fatal("非法等级应被拒绝")
	}

	// 列表默认排除过期短期记忆。
	items, total, err := db.ListMemories(MemoryFilter{}, 100, 0)
	if err != nil {
		t.Fatalf("列出记忆失败: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("应有 3 条记忆，实际 total=%d len=%d", total, len(items))
	}
	if items[0].Tier != MemoryTierCritical {
		t.Fatalf("关键记忆应排在最前，实际 %s", items[0].Tier)
	}

	// 手动把短期记忆改成已过期，再验证：列表排除 + 清理只删短期。
	if _, err := db.Exec(`UPDATE agent_memory SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-time.Hour), shortTerm.ID); err != nil {
		t.Fatalf("构造过期数据失败: %v", err)
	}
	_, total, _ = db.ListMemories(MemoryFilter{}, 100, 0)
	if total != 2 {
		t.Fatalf("过期短期记忆应被排除，实际 total=%d", total)
	}
	if _, totalAll, _ := db.ListMemories(MemoryFilter{IncludeExpired: true}, 100, 0); totalAll != 3 {
		t.Fatalf("include_expired 应看到 3 条，实际 %d", totalAll)
	}
	n, err := db.PruneExpiredMemories(time.Now())
	if err != nil {
		t.Fatalf("清理过期记忆失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应清理 1 条短期记忆，实际 %d", n)
	}
	if counts, _ := db.CountMemoriesByTier(""); counts[MemoryTierCritical] != 1 || counts[MemoryTierLongTerm] != 1 {
		t.Fatalf("关键/长期记忆不应被清理: %+v", counts)
	}

	// 命中计数与删除。
	if err := db.TouchMemory([]string{critical.ID}); err != nil {
		t.Fatalf("更新命中失败: %v", err)
	}
	rec, _ := db.GetMemory(critical.ID)
	if rec == nil || rec.HitCount != 1 {
		t.Fatalf("命中次数应为 1，实际 %+v", rec)
	}
	if err := db.DeleteMemory(critical.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if rec, _ := db.GetMemory(critical.ID); rec != nil {
		t.Fatal("删除后不应再读到")
	}
}

// user 作用域的记忆属于个人：别人的读不到；global / host 不受 owner 影响。
func TestMemoryUserScopeIsolation(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "memory-scope.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, _, err := db.UpsertMemory(MemoryUpsert{
		Tier: MemoryTierLongTerm, Scope: MemoryScopeUser, OwnerID: "user-a",
		Key: "my-preference", Content: "报告先给结论",
	}); err != nil {
		t.Fatalf("写入 user 级记忆失败: %v", err)
	}
	if _, _, err := db.UpsertMemory(MemoryUpsert{
		Tier: MemoryTierLongTerm, Scope: MemoryScopeGlobal,
		Key: "office-subnet", Content: "办公网段 10.10.0.0/16",
	}); err != nil {
		t.Fatalf("写入全局记忆失败: %v", err)
	}

	// A 能看到自己的 + 全局的。
	items, total, err := db.ListMemories(MemoryFilter{OwnerID: "user-a"}, 100, 0)
	if err != nil {
		t.Fatalf("列出记忆失败: %v", err)
	}
	if total != 2 {
		t.Fatalf("user-a 应看到 2 条，实际 %d", total)
	}

	// B 只能看到全局的，看不到 A 的私有记忆。
	items, total, err = db.ListMemories(MemoryFilter{OwnerID: "user-b"}, 100, 0)
	if err != nil {
		t.Fatalf("列出记忆失败: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Key != "office-subnet" {
		t.Fatalf("user-b 只应看到全局记忆，实际 total=%d items=%+v", total, items)
	}

	// 计数口径与列表一致。
	counts, _ := db.CountMemoriesByTier("user-b")
	if counts[MemoryTierLongTerm] != 1 {
		t.Fatalf("user-b 的计数应只含全局记忆，实际 %+v", counts)
	}

	// 不带 owner 的查询（后台维护路径）仍能看到全部。
	if _, totalAll, _ := db.ListMemories(MemoryFilter{}, 100, 0); totalAll != 2 {
		t.Fatalf("无 owner 过滤应看到 2 条，实际 %d", totalAll)
	}
}
