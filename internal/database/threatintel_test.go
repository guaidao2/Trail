//go:build cgo

package database

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// 威胁情报三张表的地基：源的注册与健康度、查询缓存（含负缓存）、订阅条目。
// 这几条如果错了，上层页面会把"没查到"显示成"干净"，或者把配额扣乱。

func newThreatTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "threat.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestThreatSourceUpsertAndHealth(t *testing.T) {
	db := newThreatTestDB(t)

	if err := db.UpsertThreatIntelSource(ThreatIntelSource{
		Source: "internetdb", Mode: ThreatModeLookup, Enabled: true, RequiresKey: false, TTLSeconds: 600,
	}); err != nil {
		t.Fatalf("注册源失败: %v", err)
	}
	src, err := db.GetThreatIntelSource("internetdb")
	if err != nil || src == nil {
		t.Fatalf("读取源失败: %v, src=%v", err, src)
	}
	if src.Mode != ThreatModeLookup || !src.Enabled || src.TTLSeconds != 600 {
		t.Fatalf("源字段不符: %+v", src)
	}

	// 重新注册不应把运行期的健康度重置掉。
	if err := db.RecordThreatSourceResult("internetdb", nil); err != nil {
		t.Fatalf("记录成功状态失败: %v", err)
	}
	before, _ := db.GetThreatIntelSource("internetdb")
	if before.LastOKAt == "" {
		t.Fatal("成功后 last_ok_at 应被写入")
	}
	if err := db.UpsertThreatIntelSource(ThreatIntelSource{
		Source: "internetdb", Mode: ThreatModeLookup, Enabled: true, TTLSeconds: 1200,
	}); err != nil {
		t.Fatalf("再次注册失败: %v", err)
	}
	after, _ := db.GetThreatIntelSource("internetdb")
	if after.LastOKAt != before.LastOKAt {
		t.Error("重新注册不应清空 last_ok_at")
	}
	if after.TTLSeconds != 1200 {
		t.Errorf("TTL 应更新为 1200，实际 %d", after.TTLSeconds)
	}

	// 失败只写 last_error，保留上一次成功时间。
	if err := db.RecordThreatSourceResult("internetdb", errTestThreat("boom")); err != nil {
		t.Fatalf("记录错误状态失败: %v", err)
	}
	failed, _ := db.GetThreatIntelSource("internetdb")
	if failed.LastError != "boom" {
		t.Errorf("last_error 应记录失败原因，实际 %q", failed.LastError)
	}
	if failed.LastOKAt != before.LastOKAt {
		t.Error("失败不应清空上一次成功时间")
	}
}

type errTestThreat string

func (e errTestThreat) Error() string { return string(e) }

func TestThreatQuotaWindow(t *testing.T) {
	db := newThreatTestDB(t)
	if err := db.UpsertThreatIntelSource(ThreatIntelSource{
		Source: "vt", Mode: ThreatModeLookup, Enabled: true, RequiresKey: true, DailyQuota: 2,
	}); err != nil {
		t.Fatalf("注册源失败: %v", err)
	}

	for i := 0; i < 2; i++ {
		ok, err := db.ConsumeThreatQuota("vt")
		if err != nil {
			t.Fatalf("第 %d 次扣配额失败: %v", i+1, err)
		}
		if !ok {
			t.Fatalf("第 %d 次扣配额应成功", i+1)
		}
	}
	ok, err := db.ConsumeThreatQuota("vt")
	if err != nil {
		t.Fatalf("超额扣配额返回错误: %v", err)
	}
	if ok {
		t.Error("配额用尽后第 3 次应被拒绝")
	}

	// 把窗口起点拨回 25 小时前，模拟跨日：应重置为可用。
	old := time.Now().Add(-25 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	if _, err := db.Exec(`UPDATE threat_intel_source SET quota_reset_at = ? WHERE source = 'vt'`, old); err != nil {
		t.Fatalf("调整窗口起点失败: %v", err)
	}
	ok, err = db.ConsumeThreatQuota("vt")
	if err != nil {
		t.Fatalf("跨日扣配额失败: %v", err)
	}
	if !ok {
		t.Error("超过 24 小时后配额应重置")
	}
}

func TestThreatCacheTTLAndNegative(t *testing.T) {
	db := newThreatTestDB(t)

	// 正缓存：未过期能读到。
	if err := db.PutThreatIntelCache(ThreatIntelCacheEntry{
		Source: "internetdb", IndicatorType: "ip", Normalized: "8.8.8.8",
		Category: ThreatCategoryExposure, Verdict: ThreatVerdictExposure, Payload: `{"ports":[53]}`,
		HTTPStatus: 200,
		ExpiresAt:  time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}); err != nil {
		t.Fatalf("写缓存失败: %v", err)
	}
	got, err := db.GetThreatIntelCache("internetdb", "ip", "8.8.8.8")
	if err != nil || got == nil {
		t.Fatalf("应读到未过期缓存: %v, %v", err, got)
	}
	if got.Category != ThreatCategoryExposure {
		t.Errorf("category 不符: %q", got.Category)
	}

	// 负缓存：同样要落库，否则同一个指标会被反复打到源上。
	if err := db.PutThreatIntelCache(ThreatIntelCacheEntry{
		Source: "internetdb", IndicatorType: "ip", Normalized: "45.33.32.1",
		Category: ThreatCategoryExposure, Verdict: ThreatVerdictUnknown, HTTPStatus: 404,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}); err != nil {
		t.Fatalf("写负缓存失败: %v", err)
	}
	neg, err := db.GetThreatIntelCache("internetdb", "ip", "45.33.32.1")
	if err != nil || neg == nil {
		t.Fatalf("负缓存应可读: %v", err)
	}
	if neg.Verdict != ThreatVerdictUnknown {
		t.Errorf("负缓存 verdict 应为 unknown，实际 %q", neg.Verdict)
	}

	// 过期缓存按"没查到"处理。
	if err := db.PutThreatIntelCache(ThreatIntelCacheEntry{
		Source: "internetdb", IndicatorType: "ip", Normalized: "9.9.9.9",
		Category: ThreatCategoryExposure, Verdict: ThreatVerdictExposure,
		ExpiresAt: time.Now().Add(-time.Minute).UTC().Format("2006-01-02 15:04:05"),
	}); err != nil {
		t.Fatalf("写过期缓存失败: %v", err)
	}
	expired, err := db.GetThreatIntelCache("internetdb", "ip", "9.9.9.9")
	if err != nil {
		t.Fatalf("读过期缓存报错: %v", err)
	}
	if expired != nil {
		t.Error("过期缓存不应返回")
	}

	n, err := db.PurgeExpiredThreatIntelCache(time.Now())
	if err != nil {
		t.Fatalf("清理过期缓存失败: %v", err)
	}
	if n < 1 {
		t.Errorf("应清掉至少 1 条过期缓存，实际 %d", n)
	}
}

func TestThreatFeedUpsertAndFilter(t *testing.T) {
	db := newThreatTestDB(t)

	entries := []ThreatIntelFeedEntry{
		{Source: "urlhaus", IndicatorType: "url", Normalized: "http://evil.example/a", Category: "malware_url", Confidence: 80},
		{Source: "urlhaus", IndicatorType: "url", Normalized: "http://evil.example/b", Category: "malware_url", Confidence: 80},
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.9", Category: "c2", Malware: "Emotet", Confidence: 90},
	}
	n, err := db.UpsertThreatIntelFeed(entries)
	if err != nil {
		t.Fatalf("写入订阅条目失败: %v", err)
	}
	if n != 3 {
		t.Fatalf("应写入 3 条，实际 %d", n)
	}

	// 重复写入同一键应覆盖而不是新增。
	n, err = db.UpsertThreatIntelFeed([]ThreatIntelFeedEntry{
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.9", Category: "c2", Malware: "QakBot", Confidence: 95},
	})
	if err != nil || n != 1 {
		t.Fatalf("覆盖写入失败: %v, n=%d", err, n)
	}
	hits, err := db.GetThreatIntelFeedByIndicator("ip", "203.0.113.9")
	if err != nil || len(hits) != 1 {
		t.Fatalf("反查应命中 1 条: %v, len=%d", err, len(hits))
	}
	if hits[0].Malware != "QakBot" {
		t.Errorf("冲突时应覆盖为新内容，实际 %q", hits[0].Malware)
	}

	// 按源筛选与关键词筛选。
	items, total, err := db.ListThreatIntelFeed(ThreatIntelFeedFilter{Source: "urlhaus"}, 10, 0)
	if err != nil {
		t.Fatalf("按源查询失败: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Errorf("urlhaus 应有 2 条，实际 total=%d len=%d", total, len(items))
	}
	_, kwTotal, err := db.ListThreatIntelFeed(ThreatIntelFeedFilter{Keyword: "Emotet"}, 10, 0)
	if err != nil {
		t.Fatalf("关键词查询失败: %v", err)
	}
	if kwTotal != 0 {
		t.Errorf("Emotet 已被覆盖为 QakBot，关键词不应再命中，实际 %d", kwTotal)
	}

	// 按源清空只影响该源。
	removed, err := db.DeleteThreatIntelFeedBySource("urlhaus")
	if err != nil {
		t.Fatalf("清空源失败: %v", err)
	}
	if removed != 2 {
		t.Errorf("应清掉 2 条，实际 %d", removed)
	}
	_, rest, err := db.ListThreatIntelFeed(ThreatIntelFeedFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("清空后查询失败: %v", err)
	}
	if rest != 1 {
		t.Errorf("应剩 1 条，实际 %d", rest)
	}

	// 统计接口。
	stats, err := db.CountThreatIntelFeedBySource()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if len(stats) != 1 || stats[0].Source != "feodo" || stats[0].Count != 1 {
		t.Errorf("统计结果不符: %+v", stats)
	}
}

// ReplaceThreatIntelFeed 是同步的落库动作，两条语义必须成立：
// 正常时整源替换、空集合时保留旧数据。后者是防线——上游格式变化或临时
// 5xx 都会表现为空列表，不能因为一次异常拉取把本地情报清空。
func TestReplaceThreatIntelFeedSemantics(t *testing.T) {
	db := newThreatTestDB(t)

	if _, err := db.UpsertThreatIntelFeed([]ThreatIntelFeedEntry{
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.1", Category: "c2"},
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.2", Category: "c2"},
		{Source: "urlhaus", IndicatorType: "url", Normalized: "http://evil.example/a", Category: "malware_url"},
	}); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	// 正常替换：只动目标源。
	n, err := db.ReplaceThreatIntelFeed("feodo", []ThreatIntelFeedEntry{
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.9", Category: "c2"},
	})
	if err != nil {
		t.Fatalf("替换失败: %v", err)
	}
	if n != 1 {
		t.Errorf("应写入 1 条，实际 %d", n)
	}
	feodo, total, err := db.ListThreatIntelFeed(ThreatIntelFeedFilter{Source: "feodo"}, 10, 0)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 1 || feodo[0].Normalized != "203.0.113.9" {
		t.Errorf("feodo 应被整源替换为 1 条新数据，实际 total=%d", total)
	}
	if _, otherTotal, _ := db.ListThreatIntelFeed(ThreatIntelFeedFilter{Source: "urlhaus"}, 10, 0); otherTotal != 1 {
		t.Errorf("替换不应影响其它源，urlhaus 实际 %d 条", otherTotal)
	}

	// 空集合：必须保留旧数据。
	if n, err := db.ReplaceThreatIntelFeed("feodo", nil); err != nil || n != 0 {
		t.Fatalf("空集合应成功返回 0，实际 n=%d err=%v", n, err)
	}
	if _, kept, _ := db.ListThreatIntelFeed(ThreatIntelFeedFilter{Source: "feodo"}, 10, 0); kept != 1 {
		t.Errorf("空集合不应清空旧数据，feodo 实际剩 %d 条", kept)
	}
}

func TestPruneThreatIntelFeed(t *testing.T) {
	db := newThreatTestDB(t)
	if _, err := db.UpsertThreatIntelFeed([]ThreatIntelFeedEntry{
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.1", FetchedAt: "2020-01-01 00:00:00"},
	}); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	n, err := db.PruneThreatIntelFeed(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n != 1 {
		t.Errorf("应清掉 1 条过期条目，实际 %d", n)
	}
}

// 传了非空 entries 但一条都写不进去时，必须回滚而不是提交：
// 提交会把旧数据删掉却什么都没补上，等于把整源清空。
func TestReplaceThreatIntelFeedRollsBackWhenNothingWritable(t *testing.T) {
	db := newThreatTestDB(t)
	if _, err := db.ReplaceThreatIntelFeed("feodo", []ThreatIntelFeedEntry{
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.1", Category: "c2"},
	}); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	_, err := db.ReplaceThreatIntelFeed("feodo", []ThreatIntelFeedEntry{
		{Source: "feodo", IndicatorType: "ip", Normalized: "   "},
		{Source: "feodo", IndicatorType: "ip", Normalized: ""},
	})
	if err == nil {
		t.Fatal("全部指标值为空时应报错")
	}
	if _, kept, _ := db.ListThreatIntelFeed(ThreatIntelFeedFilter{Source: "feodo"}, 10, 0); kept != 1 {
		t.Errorf("回滚后旧数据应保留 1 条，实际 %d", kept)
	}
}

// 缓存行要能存下标签，否则缓存命中时 CPE / eol-product 这类内容会整块消失。
func TestThreatCachePersistsTags(t *testing.T) {
	db := newThreatTestDB(t)
	if err := db.PutThreatIntelCache(ThreatIntelCacheEntry{
		Source: "internetdb", IndicatorType: "ip", Normalized: "8.8.8.8",
		Category: ThreatCategoryExposure, Verdict: ThreatVerdictExposure,
		Tags:      `["pqc","eol-product"]`,
		Payload:   `{"ports":[53]}`,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}); err != nil {
		t.Fatalf("写缓存失败: %v", err)
	}
	got, err := db.GetThreatIntelCache("internetdb", "ip", "8.8.8.8")
	if err != nil || got == nil {
		t.Fatalf("应读到缓存: %v", err)
	}
	if got.Tags != `["pqc","eol-product"]` {
		t.Errorf("标签未持久化，实际 %q", got.Tags)
	}
}
