package database

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// 检测发现的去重、累加与"消失判定"是主机态势的地基：
// 同一台主机 + 同一条规则 + 同一个主体只能有一行；重复命中累加次数；
// 本轮没再出现的老问题要能被标记为 resolved，而不是永远挂着。
func TestFindingUpsertDedupeAndStaleResolve(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "findings.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	first, err := db.UpsertFinding(FindingUpsert{
		HostID: "host-a", Source: "log_scan", Kind: "log",
		RuleID: "SQLI-4001", Title: "UNION SELECT", Category: "sqli",
		Severity: "critical", Subject: "1.2.3.4", Evidence: "GET /x?id=1 union select ...",
	})
	if err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if first.Status != FindingStatusOpen || first.HitCount != 1 {
		t.Fatalf("初始状态不对: status=%s hit=%d", first.Status, first.HitCount)
	}

	// 同一规则 + 同一来源 IP：应累加而不是新建。
	second, err := db.UpsertFinding(FindingUpsert{
		HostID: "host-a", Source: "log_scan", Kind: "log",
		RuleID: "SQLI-4001", Title: "UNION SELECT", Category: "sqli",
		Severity: "critical", Subject: "1.2.3.4", Evidence: "another line",
	})
	if err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("去重失败：%s != %s", second.ID, first.ID)
	}
	if second.HitCount != 2 {
		t.Fatalf("命中次数应为 2，实际 %d", second.HitCount)
	}

	// 不同来源 IP 是另一条发现（同一个攻击者打不同入口要分开看）。
	other, err := db.UpsertFinding(FindingUpsert{
		HostID: "host-a", Source: "log_scan", Kind: "log",
		RuleID: "SQLI-4001", Severity: "critical", Subject: "5.6.7.8",
	})
	if err != nil {
		t.Fatalf("写入不同主体失败: %v", err)
	}
	if other.ID == first.ID {
		t.Fatal("不同来源 IP 不应并成同一条发现")
	}

	// 基线不符合项走同一条表，来源区分开。
	if _, err := db.UpsertFinding(FindingUpsert{
		HostID: "host-a", Source: "baseline_audit", Kind: "baseline",
		RuleID: "CHK-ID-001", Title: "禁止 root 直接 SSH 登录", Category: "身份鉴别",
		Severity: "high", Evidence: "PermitRootLogin yes",
	}); err != nil {
		t.Fatalf("写入基线发现失败: %v", err)
	}

	bySeverity, total, lastSeen, err := db.HostFindingSummary("host-a")
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if total != 3 {
		t.Fatalf("应有 3 条发现，实际 %d", total)
	}
	if bySeverity["critical"] != 2 || bySeverity["high"] != 1 {
		t.Fatalf("严重度分布不对: %+v", bySeverity)
	}
	if lastSeen == "" {
		t.Fatal("最近出现时间不应为空")
	}

	// 把"本轮没再出现"的日志发现标为已解决（基线来源不受影响）。
	cutoff := time.Now().Add(time.Second)
	n, err := db.ResolveStaleFindings("host-a", "log_scan", nil, cutoff)
	if err != nil {
		t.Fatalf("标记过期失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("应标记 2 条日志发现，实际 %d", n)
	}
	_, totalAfter, _, _ := db.HostFindingSummary("host-a")
	if totalAfter != 1 {
		t.Fatalf("解决后应只剩 1 条基线发现，实际 %d", totalAfter)
	}

	// 非法状态必须拒绝。
	if err := db.SetFindingStatus(first.ID, "whatever"); err == nil {
		t.Fatal("非法状态应被拒绝")
	}
	if err := db.SetFindingStatus(first.ID, FindingStatusAcked); err != nil {
		t.Fatalf("流转状态失败: %v", err)
	}
	rec, err := db.GetFinding(first.ID)
	if err != nil || rec == nil {
		t.Fatalf("读取失败: %v", err)
	}
	if rec.Status != FindingStatusAcked {
		t.Fatalf("状态应为 acked，实际 %s", rec.Status)
	}
}
