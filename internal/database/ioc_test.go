package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// IOC 的去重、状态机与主机关联是这个功能的地基：
// 同一个指标写成不同形式不能变成两条记录，命中同一对 IOC+主机不能无限建行，
// 封禁必须留下可撤销的命令。
func TestIOCNormalizeDedupeAndHostHits(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "ioc.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// 同一个 IP 的不同写法（含前导零）应归一到同一条记录。
	first, created, err := db.UpsertIOC(IOCUpsert{Type: "ip", Value: "1.2.3.4", Source: "manual"})
	if err != nil || !created {
		t.Fatalf("首次写入失败: created=%v err=%v", created, err)
	}
	second, created, err := db.UpsertIOC(IOCUpsert{Type: "ip", Value: "1.2.3.004", Source: "log_scan"})
	if err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	if created {
		t.Fatal("同一个 IP 的等价写法不应该新建记录")
	}
	if first.ID != second.ID {
		t.Fatalf("去重失败：%s != %s", first.ID, second.ID)
	}
	if second.Status != IOCStatusObserved {
		t.Fatalf("默认状态应为 observed，实际 %q", second.Status)
	}

	// 主机命中：同一对只累加次数。
	for i := 0; i < 3; i++ {
		if err := db.RecordIOCHit(first.ID, "host-a", "log_scan", "SQLI-4001", "union select ..."); err != nil {
			t.Fatalf("记录命中失败: %v", err)
		}
	}
	if err := db.RecordIOCHit(first.ID, "host-b", "log_scan", "SQLI-4001", "union select ..."); err != nil {
		t.Fatalf("记录命中失败: %v", err)
	}
	hits, err := db.ListIOCHits(first.ID, 10)
	if err != nil {
		t.Fatalf("读取命中失败: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("应有 2 台主机，实际 %d", len(hits))
	}
	for _, h := range hits {
		if h.HostID == "host-a" && h.HitCount != 3 {
			t.Fatalf("host-a 命中次数应为 3，实际 %d", h.HitCount)
		}
	}

	// 封禁留痕要能撤销。
	if err := db.MarkIOCHostBlocked(first.ID, "host-a", "iptables -I INPUT -s 1.2.3.4 -j DROP",
		"iptables -D INPUT -s 1.2.3.4 -j DROP"); err != nil {
		t.Fatalf("记录封禁失败: %v", err)
	}
	hits, _ = db.ListIOCHits(first.ID, 10)
	for _, h := range hits {
		if h.HostID == "host-a" {
			if h.BlockedAt == "" || h.UnblockCommand == "" {
				t.Fatalf("封禁留痕不完整: %+v", h)
			}
		}
	}
	if err := db.MarkIOCHostUnblocked(first.ID, "host-a"); err != nil {
		t.Fatalf("记录解封失败: %v", err)
	}

	// 状态机：非法状态必须拒绝。
	if err := db.SetIOCStatus(first.ID, "whatever"); err == nil {
		t.Fatal("非法状态应被拒绝")
	}
	if err := db.SetIOCStatus(first.ID, IOCStatusConfirmed); err != nil {
		t.Fatalf("改状态失败: %v", err)
	}
	rec, err := db.GetIOC(first.ID)
	if err != nil || rec == nil {
		t.Fatalf("读取 IOC 失败: %v", err)
	}
	if rec.Status != IOCStatusConfirmed {
		t.Fatalf("状态应为 confirmed，实际 %q", rec.Status)
	}
	if rec.HostCount != 2 {
		t.Fatalf("关联主机数应为 2，实际 %d", rec.HostCount)
	}

	// 类型过滤与按主机关联过滤。
	if _, total, err := db.ListIOCs(IOCFilter{HostID: "host-a"}, 10, 0); err != nil || total != 1 {
		t.Fatalf("按主机关联过滤失败: total=%d err=%v", total, err)
	}
	if _, _, err := db.UpsertIOC(IOCUpsert{Type: "not-a-type", Value: "x"}); err == nil {
		t.Fatal("非法类型应被拒绝")
	}
}

// 状态只升不降：自动扫描每次都以 observed 写入，不能把人工确认或已封禁打回去。
func TestIOCStatusOnlyUpgrades(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "ioc-status.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rec, _, err := db.UpsertIOC(IOCUpsert{Type: "ip", Value: "9.9.9.9", Status: IOCStatusConfirmed})
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if rec.Status != IOCStatusConfirmed {
		t.Fatalf("初始状态应为 confirmed，实际 %s", rec.Status)
	}

	// 扫描再次命中（observed）不能降级
	rec, _, err = db.UpsertIOC(IOCUpsert{Type: "ip", Value: "9.9.9.9", Status: IOCStatusObserved})
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if rec.Status != IOCStatusConfirmed {
		t.Fatalf("observed 不应覆盖 confirmed，实际 %s", rec.Status)
	}

	// blocked 更高，应升级
	rec, _, err = db.UpsertIOC(IOCUpsert{Type: "ip", Value: "9.9.9.9", Status: IOCStatusBlocked})
	if err != nil {
		t.Fatalf("写入 blocked 失败: %v", err)
	}
	if rec.Status != IOCStatusBlocked {
		t.Fatalf("应升级为 blocked，实际 %s", rec.Status)
	}

	// blocked 不能被 observed/confirmed 降级
	rec, _, err = db.UpsertIOC(IOCUpsert{Type: "ip", Value: "9.9.9.9", Status: IOCStatusObserved})
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if rec.Status != IOCStatusBlocked {
		t.Fatalf("observed 不应把 blocked 降级，实际 %s", rec.Status)
	}

	// 误报是终态：自动写入也覆盖不了
	if err := db.SetIOCStatus(rec.ID, IOCStatusFalsePositive); err != nil {
		t.Fatalf("标记误报失败: %v", err)
	}
	rec, _, err = db.UpsertIOC(IOCUpsert{Type: "ip", Value: "9.9.9.9", Status: IOCStatusObserved})
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if rec.Status != IOCStatusFalsePositive {
		t.Fatalf("误报状态不应被覆盖，实际 %s", rec.Status)
	}
}
