//go:build cgo

// 实网导入测试：需要真实 sqlite（cgo）与外网，默认跳过。
// 用法：
//   OSV_LIVE=1 OSV_ARCHIVE=NuGet go test ./internal/vulnintel/ -run TestOSVLiveImport -v -timeout 30m

package vulnintel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trail/internal/database"

	"go.uber.org/zap"
)

func TestOSVLiveImport(t *testing.T) {
	if os.Getenv("OSV_LIVE") != "1" {
		t.Skip("设置 OSV_LIVE=1 才真实下载 OSV 转储")
	}
	archive := os.Getenv("OSV_ARCHIVE")
	if archive == "" {
		archive = "NuGet"
	}
	var eco osvEcosystem
	found := false
	for _, e := range osvEcosystems {
		if e.Archive == archive {
			eco, found = e, true
			break
		}
	}
	if !found {
		t.Fatalf("未知生态 %q", archive)
	}

	dir := t.TempDir()
	db, err := database.NewDB(filepath.Join(dir, "test.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	defer db.Close()

	s := New(db, Config{
		OSVEnabled: true,
		OSVBaseURL: os.Getenv("OSV_BASE"),
		MaxRuntime: 30 * time.Minute,
	}, t.Logf)

	imported, skipped, err := s.importOSVArchive(context.Background(), eco)
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if imported == 0 {
		t.Fatalf("没有导入任何 advisory（跳过 %d）", skipped)
	}

	var intelCount, rangeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_intel WHERE source='osv'`).Scan(&intelCount); err != nil {
		t.Fatalf("统计情报失败: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_intel_range WHERE source='osv'`).Scan(&rangeCount); err != nil {
		t.Fatalf("统计区间失败: %v", err)
	}
	t.Logf("%s 导入=%d 跳过=%d 入库情报=%d 区间=%d", eco.Label, imported, skipped, intelCount, rangeCount)
	if intelCount == 0 || rangeCount == 0 {
		t.Fatal("入库为空：解析或写库链路断了")
	}

	// 生态名要落到 vendor 上，否则语言包的精确匹配取不到。
	var ecoRanges int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_intel_range WHERE source='osv' AND LOWER(vendor)=?`, eco.Key).Scan(&ecoRanges); err != nil {
		t.Fatalf("统计生态区间失败: %v", err)
	}
	if ecoRanges == 0 {
		t.Fatalf("vendor 未写入生态名 %q", eco.Key)
	}
}
