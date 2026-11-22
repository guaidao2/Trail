//go:build cgo

package threatintel

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"trail/internal/database"
)

func newServiceTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "svc.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// 配置是启停的唯一权威。关闭方向好理解，容易漏的是**恢复方向**：
// 名单里删掉某个源之后，它必须重新变成启用，否则这个源就再也起不来了
// （页面上没有手动开关，库里也改不回去）。
func TestEnsureSourcesDisableAndRestore(t *testing.T) {
	db := newServiceTestDB(t)

	// 第一轮：把 virustotal 放进停用名单。
	svc := NewService(db, Config{DisabledSources: []string{"virustotal"}}, zap.NewNop())
	if err := svc.EnsureSources(context.Background()); err != nil {
		t.Fatalf("注册源失败: %v", err)
	}
	src, err := db.GetThreatIntelSource("virustotal")
	if err != nil || src == nil {
		t.Fatalf("读取源失败: %v", err)
	}
	if src.Enabled {
		t.Fatal("disabled_sources 里的源应被停用")
	}

	// 第二轮：名单里删掉它，重新构造服务（模拟改完配置重启）。
	svc2 := NewService(db, Config{}, zap.NewNop())
	if err := svc2.EnsureSources(context.Background()); err != nil {
		t.Fatalf("再次注册源失败: %v", err)
	}
	src2, err := db.GetThreatIntelSource("virustotal")
	if err != nil || src2 == nil {
		t.Fatalf("再次读取源失败: %v", err)
	}
	if !src2.Enabled {
		t.Fatal("从停用名单移除后，源应恢复启用")
	}
}

// 停用名单匹配要大小写不敏感，否则写错大小写会静默失效。
func TestEnsureSourcesDisabledMatchingIsCaseInsensitive(t *testing.T) {
	db := newServiceTestDB(t)
	svc := NewService(db, Config{DisabledSources: []string{"VirusTotal"}}, zap.NewNop())
	if err := svc.EnsureSources(context.Background()); err != nil {
		t.Fatalf("注册源失败: %v", err)
	}
	src, _ := db.GetThreatIntelSource("virustotal")
	if src == nil || src.Enabled {
		t.Fatal("大小写不同也应命中停用名单")
	}
}

// CacheTTL 要有可观察效果：配置里给了就按配置写进源的 ttl_seconds，
// 否则这个配置项等于没用。
func TestEnsureSourcesAppliesCacheTTL(t *testing.T) {
	db := newServiceTestDB(t)
	svc := NewService(db, Config{CacheTTL: 15 * time.Minute}, zap.NewNop())
	if err := svc.EnsureSources(context.Background()); err != nil {
		t.Fatalf("注册源失败: %v", err)
	}
	src, _ := db.GetThreatIntelSource("internetdb")
	if src == nil {
		t.Fatal("应注册 internetdb")
	}
	if src.TTLSeconds != 900 {
		t.Errorf("ttl_seconds 应为 900，实际 %d", src.TTLSeconds)
	}
}

// 已有同步在跑时，第二个入口必须立刻拿到 ErrSyncInProgress，而不是排队。
func TestSyncFeedRejectsWhenAnotherSyncRunning(t *testing.T) {
	db := newServiceTestDB(t)
	svc := NewService(db, Config{}, zap.NewNop())

	feedSyncMu.Lock()
	_, err := svc.SyncFeed(context.Background(), "feodo")
	feedSyncMu.Unlock()

	if !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("应返回 ErrSyncInProgress，实际 %v", err)
	}

	// 全量入口同样要通过 started=false 表达"没启动"，而不是伪装成失败。
	feedSyncMu.Lock()
	results, errs, started := svc.SyncAllFeeds(context.Background())
	feedSyncMu.Unlock()
	if started {
		t.Error("已有同步在跑时 started 应为 false")
	}
	if len(results) != 0 || len(errs) != 0 {
		t.Errorf("未启动时不应产生结果或错误：results=%v errs=%v", results, errs)
	}
}
