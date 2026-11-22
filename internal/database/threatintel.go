package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 威胁情报与 IOC 的分界（写在这里，是因为后面每个读写方法都要守住它）：
//
//	IOC 表       = 人（或人确认过的引擎）对某个指标下的结论，带状态机，可封禁。
//	威胁情报表   = 外部源对某个指标的观测事实，只读、有 TTL、永不自动封禁。
//
// 两者之间唯一的桥是「采纳」：把一条外部观测显式写成 observed IOC。
// 任何自动流程都不得跨过这座桥，否则 IOC 的状态机会被外部源稀释掉。

// 判定值：外部源对某个指标的结论口径。
const (
	ThreatVerdictMalicious  = "malicious"
	ThreatVerdictSuspicious = "suspicious"
	ThreatVerdictClean      = "clean"
	ThreatVerdictUnknown    = "unknown"
	// ThreatVerdictExposure 不是恶意判定，而是"只报了暴露面"。
	// 单独一档，免得把"开着 80 端口"渲染成"可疑"。
	ThreatVerdictExposure = "exposure"
)

// 源的接入模式。两条链路的调度、限流、落地表都不同，不能混用。
const (
	ThreatModeLookup = "lookup" // 按需查询：拿一个指标去问一次
	ThreatModeFeed   = "feed"   // 订阅落地：定期拉全量集合
)

// 情报类别。暴露面不等于恶意：一个开着 80 端口的 IP 只是"可被看见"，
// 不能据此判它有问题。页面上这两类必须分栏展示，否则等于制造误报。
const (
	ThreatCategoryReputation = "reputation" // 信誉 / 恶意判定
	ThreatCategoryExposure   = "exposure"   // 暴露面观测（端口、CPE、已知漏洞）
)

// ThreatIntelSource 是一个情报源的注册信息与健康度。
// 密钥不在库里，只记 requires_key；实际 key 走配置与环境变量。
type ThreatIntelSource struct {
	Source             string `json:"source"`
	Mode               string `json:"mode"`
	Enabled            bool   `json:"enabled"`
	RequiresKey        bool   `json:"requires_key"`
	Endpoint           string `json:"endpoint,omitempty"`
	TTLSeconds         int    `json:"ttl_seconds"`
	RateLimitPerMinute int    `json:"rate_limit_per_minute"`
	DailyQuota         int    `json:"daily_quota"`
	QuotaUsed          int    `json:"quota_used"`
	QuotaResetAt       string `json:"quota_reset_at,omitempty"`
	LastOKAt           string `json:"last_ok_at,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	UpdatedAt          string `json:"updated_at,omitempty"`
}

// ThreatIntelCacheEntry 是一条按需查询的缓存（含 negative cache）。
// negative cache 与正样本同表：查过但没有情报也要落一行，verdict 记 unknown，
// 靠 expires_at 控制何时重新查，避免同一个指标把配额反复打光。
type ThreatIntelCacheEntry struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	IndicatorType string `json:"indicator_type"`
	Normalized    string `json:"normalized"`
	Category      string `json:"category"`
	Verdict       string `json:"verdict"`
	// Tags 是 JSON 数组字符串。缓存命中时要靠它还原标签，
	// 只从 payload 重算会漏掉 provider 自己加工过的内容。
	Tags       string `json:"tags,omitempty"`
	Payload    string `json:"payload,omitempty"`
	HTTPStatus int    `json:"http_status"`
	FetchedAt  string `json:"fetched_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// ThreatIntelFeedEntry 是一条订阅 feed 落地的指标。
type ThreatIntelFeedEntry struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	IndicatorType string `json:"indicator_type"`
	Normalized    string `json:"normalized"`
	Category      string `json:"category,omitempty"`
	Malware       string `json:"malware,omitempty"`
	Confidence    int    `json:"confidence"`
	FirstSeen     string `json:"first_seen,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
	Tags          string `json:"tags,omitempty"`
	Payload       string `json:"payload,omitempty"`
	FetchedAt     string `json:"fetched_at"`
}

// ThreatIntelFeedFilter 是订阅条目的列表筛选条件。
type ThreatIntelFeedFilter struct {
	Source        string
	IndicatorType string
	Category      string
	Keyword       string
}

const threatSourceColumns = `source, mode, enabled, requires_key, endpoint, ttl_seconds,
	rate_limit_per_minute, daily_quota, quota_used, quota_reset_at, last_ok_at, last_error, updated_at`

const threatCacheColumns = `id, source, indicator_type, normalized, category, verdict, tags, payload,
	http_status, fetched_at, expires_at`

const threatFeedColumns = `id, source, indicator_type, normalized, category, malware,
	confidence, first_seen, last_seen, tags, payload, fetched_at`

func formatThreatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func threatTimeOrNull(s string) interface{} {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return s
}

func scanThreatSource(row interface{ Scan(...interface{}) error }) (*ThreatIntelSource, error) {
	var (
		src        ThreatIntelSource
		quotaReset sql.NullString
		lastOK     sql.NullString
		updatedAt  sql.NullString
	)
	if err := row.Scan(&src.Source, &src.Mode, &src.Enabled, &src.RequiresKey, &src.Endpoint,
		&src.TTLSeconds, &src.RateLimitPerMinute, &src.DailyQuota, &src.QuotaUsed,
		&quotaReset, &lastOK, &src.LastError, &updatedAt); err != nil {
		return nil, err
	}
	src.QuotaResetAt = quotaReset.String
	src.LastOKAt = lastOK.String
	if updatedAt.Valid {
		src.UpdatedAt = updatedAt.String
	}
	return &src, nil
}

// ListThreatIntelSources 返回所有已注册的源，按模式与名字排序，供页面健康带使用。
func (db *DB) ListThreatIntelSources() ([]*ThreatIntelSource, error) {
	rows, err := db.Query(`SELECT ` + threatSourceColumns + ` FROM threat_intel_source ORDER BY mode, source`)
	if err != nil {
		return nil, fmt.Errorf("查询威胁情报源失败: %w", err)
	}
	defer rows.Close()
	var out []*ThreatIntelSource
	for rows.Next() {
		src, err := scanThreatSource(rows)
		if err != nil {
			return nil, fmt.Errorf("读取威胁情报源失败: %w", err)
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// GetThreatIntelSource 按源标识读取一条注册信息。
func (db *DB) GetThreatIntelSource(source string) (*ThreatIntelSource, error) {
	row := db.QueryRow(`SELECT `+threatSourceColumns+` FROM threat_intel_source WHERE source = ?`, source)
	src, err := scanThreatSource(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询威胁情报源失败: %w", err)
	}
	return src, nil
}

// UpsertThreatIntelSource 注册或更新一个源。健康度字段（last_ok_at / last_error /
// quota_used）不在这里覆盖，避免每次启动重置掉运行期状态。
func (db *DB) UpsertThreatIntelSource(src ThreatIntelSource) error {
	mode := strings.ToLower(strings.TrimSpace(src.Mode))
	if mode == "" {
		mode = ThreatModeLookup
	}
	if mode != ThreatModeLookup && mode != ThreatModeFeed {
		return fmt.Errorf("不支持的威胁情报源模式: %s", mode)
	}
	if strings.TrimSpace(src.Source) == "" {
		return fmt.Errorf("威胁情报源标识不能为空")
	}
	ttl := src.TTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	now := formatThreatTime(time.Now())
	_, err := db.Exec(`INSERT INTO threat_intel_source
		(source, mode, enabled, requires_key, endpoint, ttl_seconds, rate_limit_per_minute,
		 daily_quota, quota_used, quota_reset_at, last_ok_at, last_error, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, '', ?)
		ON CONFLICT(source) DO UPDATE SET
			mode = excluded.mode,
			enabled = excluded.enabled,
			requires_key = excluded.requires_key,
			endpoint = excluded.endpoint,
			ttl_seconds = excluded.ttl_seconds,
			rate_limit_per_minute = excluded.rate_limit_per_minute,
			daily_quota = excluded.daily_quota,
			updated_at = excluded.updated_at`,
		strings.TrimSpace(src.Source), mode, src.Enabled, src.RequiresKey,
		strings.TrimSpace(src.Endpoint), ttl, src.RateLimitPerMinute, src.DailyQuota,
		threatTimeOrNull(now), now)
	if err != nil {
		return fmt.Errorf("写入威胁情报源失败: %w", err)
	}
	return nil
}

// RecordThreatSourceResult 记录一次调用结果：成功刷新 last_ok_at 并清空错误，
// 失败只写 last_error，保留上一次成功时间，方便页面区分"一直没好过"和"刚坏"。
func (db *DB) RecordThreatSourceResult(source string, callErr error) error {
	now := formatThreatTime(time.Now())
	if callErr == nil {
		_, err := db.Exec(`UPDATE threat_intel_source SET last_ok_at = ?, last_error = '', updated_at = ? WHERE source = ?`,
			now, now, source)
		if err != nil {
			return fmt.Errorf("更新威胁情报源状态失败: %w", err)
		}
		return nil
	}
	msg := callErr.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := db.Exec(`UPDATE threat_intel_source SET last_error = ?, updated_at = ? WHERE source = ?`,
		msg, now, source)
	if err != nil {
		return fmt.Errorf("更新威胁情报源错误失败: %w", err)
	}
	return nil
}

// ConsumeThreatQuota 原子占用一次配额。
//
// 额度按 24 小时窗口计，quota_reset_at 记窗口起点。整个"判断 + 扣减 + 重置"
// 放在一条 UPDATE 里做，靠 RowsAffected 判断是否放行：
//   - 并发的两个查询不会各自读到旧计数后都放行；
//   - 时间比较交给 SQLite 的字符串比较，库里的时间一律是 UTC 同格式，
//     不在 Go 侧解析，避免本地时区与 UTC 差几个小时后算错窗口。
//
// daily_quota 为 0 表示不限量，但仍累计用量供页面展示。
func (db *DB) ConsumeThreatQuota(source string) (bool, error) {
	nowStr := formatThreatTime(time.Now())
	// 窗口过期分界：起点早于或等于 24 小时前，就认为进入新窗口。
	staleBefore := formatThreatTime(time.Now().Add(-24 * time.Hour))

	res, err := db.Exec(`UPDATE threat_intel_source
		SET quota_used = CASE WHEN quota_reset_at IS NULL OR quota_reset_at <= ? THEN 1 ELSE quota_used + 1 END,
		    quota_reset_at = CASE WHEN quota_reset_at IS NULL OR quota_reset_at <= ? THEN ? ELSE quota_reset_at END,
		    updated_at = ?
		WHERE source = ?
		  AND (daily_quota = 0 OR quota_reset_at IS NULL OR quota_reset_at <= ? OR quota_used < daily_quota)`,
		staleBefore, staleBefore, nowStr, nowStr, source, staleBefore)
	if err != nil {
		return false, fmt.Errorf("占用配额失败: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("读取配额占用结果失败: %w", err)
	}
	return n > 0, nil
}

// GetThreatIntelCache 读取一条未过期的缓存。过期按"没查到"处理，
// 让上层重新请求，而不是拿到旧结论。
func (db *DB) GetThreatIntelCache(source, indicatorType, normalized string) (*ThreatIntelCacheEntry, error) {
	row := db.QueryRow(`SELECT `+threatCacheColumns+` FROM threat_intel_cache
		WHERE source = ? AND indicator_type = ? AND normalized = ?
		  AND (expires_at IS NULL OR expires_at > ?)`,
		source, indicatorType, normalized, formatThreatTime(time.Now()))
	entry, err := scanThreatCache(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询威胁情报缓存失败: %w", err)
	}
	return entry, nil
}

// ListThreatIntelCacheByIndicator 返回某个指标在所有源上的未过期缓存。
//
// 当前生产路径没有调用方（聚合页走 Service.Query 逐源取），保留它是为了
// 让"一次查完某指标在各源的缓存"这件事有现成入口，测试也直接覆盖了它。
func (db *DB) ListThreatIntelCacheByIndicator(indicatorType, normalized string) ([]*ThreatIntelCacheEntry, error) {
	rows, err := db.Query(`SELECT `+threatCacheColumns+` FROM threat_intel_cache
		WHERE indicator_type = ? AND normalized = ? AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY source`, indicatorType, normalized, formatThreatTime(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("查询威胁情报缓存失败: %w", err)
	}
	defer rows.Close()
	var out []*ThreatIntelCacheEntry
	for rows.Next() {
		entry, err := scanThreatCache(rows)
		if err != nil {
			return nil, fmt.Errorf("读取威胁情报缓存失败: %w", err)
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func scanThreatCache(row interface{ Scan(...interface{}) error }) (*ThreatIntelCacheEntry, error) {
	var (
		e         ThreatIntelCacheEntry
		fetchedAt sql.NullString
		expiresAt sql.NullString
	)
	if err := row.Scan(&e.ID, &e.Source, &e.IndicatorType, &e.Normalized, &e.Category, &e.Verdict,
		&e.Tags, &e.Payload, &e.HTTPStatus, &fetchedAt, &expiresAt); err != nil {
		return nil, err
	}
	e.FetchedAt = fetchedAt.String
	e.ExpiresAt = expiresAt.String
	return &e, nil
}

// PutThreatIntelCache 写入或覆盖一条缓存。同一 (source, type, normalized) 只留最新一条。
func (db *DB) PutThreatIntelCache(entry ThreatIntelCacheEntry) error {
	if strings.TrimSpace(entry.Source) == "" || strings.TrimSpace(entry.IndicatorType) == "" || strings.TrimSpace(entry.Normalized) == "" {
		return fmt.Errorf("威胁情报缓存缺少必要字段")
	}
	if entry.ID == "" {
		entry.ID = "tic_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16]
	}
	if entry.FetchedAt == "" {
		entry.FetchedAt = formatThreatTime(time.Now())
	}
	category := strings.TrimSpace(entry.Category)
	if category == "" {
		category = ThreatCategoryReputation
	}
	tags := strings.TrimSpace(entry.Tags)
	if tags == "" {
		tags = "[]"
	}
	_, err := db.Exec(`INSERT INTO threat_intel_cache
		(id, source, indicator_type, normalized, category, verdict, tags, payload, http_status, fetched_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source, indicator_type, normalized) DO UPDATE SET
			category = excluded.category,
			verdict = excluded.verdict,
			tags = excluded.tags,
			payload = excluded.payload,
			http_status = excluded.http_status,
			fetched_at = excluded.fetched_at,
			expires_at = excluded.expires_at`,
		entry.ID, entry.Source, entry.IndicatorType, entry.Normalized, category, entry.Verdict,
		tags, entry.Payload, entry.HTTPStatus, entry.FetchedAt, threatTimeOrNull(entry.ExpiresAt))
	if err != nil {
		return fmt.Errorf("写入威胁情报缓存失败: %w", err)
	}
	return nil
}

// PurgeExpiredThreatIntelCache 清掉过期缓存。返回删除条数。
func (db *DB) PurgeExpiredThreatIntelCache(before time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM threat_intel_cache WHERE expires_at IS NOT NULL AND expires_at <= ?`, formatThreatTime(before))
	if err != nil {
		return 0, fmt.Errorf("清理威胁情报缓存失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// UpsertThreatIntelFeed 批量写入订阅条目，单事务，整批失败即整批回滚。
// 同一 (source, type, normalized) 冲突时覆盖为最新一次拉取的内容。
//
// 生产路径已改用 ReplaceThreatIntelFeed（整源替换），这里保留是因为它是
// "只增不删"的底层写入，测试直接覆盖其冲突语义，也便于以后做增量 feed。
func (db *DB) UpsertThreatIntelFeed(entries []ThreatIntelFeedEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("开启订阅写入事务失败: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO threat_intel_feed
		(id, source, indicator_type, normalized, category, malware, confidence,
		 first_seen, last_seen, tags, payload, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source, indicator_type, normalized) DO UPDATE SET
			category = excluded.category,
			malware = excluded.malware,
			confidence = excluded.confidence,
			first_seen = COALESCE(excluded.first_seen, threat_intel_feed.first_seen),
			last_seen = COALESCE(excluded.last_seen, threat_intel_feed.last_seen),
			tags = excluded.tags,
			payload = excluded.payload,
			fetched_at = excluded.fetched_at`)
	if err != nil {
		return 0, fmt.Errorf("准备订阅写入语句失败: %w", err)
	}
	defer stmt.Close()

	now := formatThreatTime(time.Now())
	written := 0
	for _, e := range entries {
		if strings.TrimSpace(e.Source) == "" || strings.TrimSpace(e.Normalized) == "" {
			continue
		}
		if e.ID == "" {
			e.ID = "tif_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16]
		}
		if e.FetchedAt == "" {
			e.FetchedAt = now
		}
		if _, err := stmt.Exec(e.ID, e.Source, e.IndicatorType, e.Normalized, e.Category,
			e.Malware, e.Confidence, threatTimeOrNull(e.FirstSeen), threatTimeOrNull(e.LastSeen),
			e.Tags, e.Payload, e.FetchedAt); err != nil {
			return written, fmt.Errorf("写入订阅条目失败(%s/%s): %w", e.Source, e.Normalized, err)
		}
		written++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("提交订阅写入事务失败: %w", err)
	}
	return written, nil
}

// ReplaceThreatIntelFeed 在同一事务里替换某个源的全部订阅条目。
//
// 为什么必须是事务：先删后写分两次提交的话，写库失败或进程被中断会留下
// "源被清空"的状态，本地少一整份 C2 情报而页面上还显示最近同步成功。
//
// 空集合不清空旧数据：上游格式变化、临时 5xx、当天确实没有条目，都表现为
// 空列表，分不清是哪一种；宁可保留上一轮内容（下一次同步会覆盖），
// 也不要因为一次异常拉取把情报抹掉。
func (db *DB) ReplaceThreatIntelFeed(source string, entries []ThreatIntelFeedEntry) (int, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return 0, fmt.Errorf("订阅源标识不能为空")
	}
	if len(entries) == 0 {
		return 0, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("开启订阅替换事务失败: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM threat_intel_feed WHERE source = ?`, source); err != nil {
		return 0, fmt.Errorf("清空旧订阅条目失败: %w", err)
	}

	stmt, err := tx.Prepare(`INSERT INTO threat_intel_feed
		(id, source, indicator_type, normalized, category, malware, confidence,
		 first_seen, last_seen, tags, payload, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source, indicator_type, normalized) DO UPDATE SET
			category = excluded.category,
			malware = excluded.malware,
			confidence = excluded.confidence,
			first_seen = COALESCE(excluded.first_seen, threat_intel_feed.first_seen),
			last_seen = COALESCE(excluded.last_seen, threat_intel_feed.last_seen),
			tags = excluded.tags,
			payload = excluded.payload,
			fetched_at = excluded.fetched_at`)
	if err != nil {
		return 0, fmt.Errorf("准备订阅写入语句失败: %w", err)
	}
	defer stmt.Close()

	now := formatThreatTime(time.Now())
	written := 0
	for _, e := range entries {
		if strings.TrimSpace(e.Normalized) == "" {
			continue
		}
		if e.ID == "" {
			e.ID = "tif_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16]
		}
		if e.FetchedAt == "" {
			e.FetchedAt = now
		}
		if _, err := stmt.Exec(e.ID, source, e.IndicatorType, e.Normalized, e.Category,
			e.Malware, e.Confidence, threatTimeOrNull(e.FirstSeen), threatTimeOrNull(e.LastSeen),
			e.Tags, e.Payload, e.FetchedAt); err != nil {
			return 0, fmt.Errorf("写入订阅条目失败(%s/%s): %w", source, e.Normalized, err)
		}
		written++
	}
	// 传了非空 entries 却一条都没写进去，说明调用方给的指针全都不可用。
	// 这时不能提交——提交会把旧数据删掉却什么都没补上，返回错误让事务回滚。
	if written == 0 {
		return 0, fmt.Errorf("订阅源 %s 的 %d 条数据全部缺少指标值，已回滚", source, len(entries))
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("提交订阅替换事务失败: %w", err)
	}
	return written, nil
}

// DeleteThreatIntelFeedBySource 清空某个源的全部订阅条目。
//
// 生产路径已改用 ReplaceThreatIntelFeed（删除与写入在同一事务里），
// 这个方法保留给需要"只清不写"的场景与测试；单独调用它会留下空表，
// 不要在同步流程里再直接用它。
func (db *DB) DeleteThreatIntelFeedBySource(source string) (int64, error) {
	res, err := db.Exec(`DELETE FROM threat_intel_feed WHERE source = ?`, source)
	if err != nil {
		return 0, fmt.Errorf("清空订阅条目失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// escapeLike 转义 LIKE 的通配符。用户搜 "%" 时应当匹配字面百分号，
// 否则一个字符就能让查询扫全表。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "!", "!!")
	s = strings.ReplaceAll(s, "%", "!%")
	s = strings.ReplaceAll(s, "_", "!_")
	return s
}

// PruneThreatIntelFeed 删除早于 cutoff 的订阅条目，返回删除条数。
// 订阅数据是快照，超过保留期的条目既占空间又可能误导（上游早撤了它还留着）。
func (db *DB) PruneThreatIntelFeed(cutoff time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM threat_intel_feed WHERE fetched_at < ?`, formatThreatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("清理过期订阅条目失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListThreatIntelFeed 分页查询订阅条目。
func (db *DB) ListThreatIntelFeed(filter ThreatIntelFeedFilter, limit, offset int) ([]*ThreatIntelFeedEntry, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	where := []string{"1=1"}
	args := []interface{}{}
	if v := strings.TrimSpace(filter.Source); v != "" {
		where = append(where, "source = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.IndicatorType); v != "" {
		// "hash" 是页面上的聚合选项：入库时哈希保留具体算法（md5/sha1/sha256），
		// 直接等值匹配会让选 hash 永远筛不出东西。这里把它展开成三个算法。
		if strings.EqualFold(v, "hash") {
			where = append(where, "indicator_type IN (?, ?, ?)")
			args = append(args, "md5", "sha1", "sha256")
		} else {
			where = append(where, "indicator_type = ?")
			args = append(args, v)
		}
	}
	if v := strings.TrimSpace(filter.Category); v != "" {
		where = append(where, "category = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.Keyword); v != "" {
		where = append(where, "(normalized LIKE ? ESCAPE '!' OR malware LIKE ? ESCAPE '!' OR tags LIKE ? ESCAPE '!')")
		like := "%" + escapeLike(v) + "%"
		args = append(args, like, like, like)
	}
	clause := strings.Join(where, " AND ")

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM threat_intel_feed WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计订阅条目失败: %w", err)
	}

	query := `SELECT ` + threatFeedColumns + ` FROM threat_intel_feed WHERE ` + clause +
		` ORDER BY last_seen DESC, fetched_at DESC LIMIT ? OFFSET ?`
	rows, err := db.Query(query, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询订阅条目失败: %w", err)
	}
	defer rows.Close()

	var out []*ThreatIntelFeedEntry
	for rows.Next() {
		e, err := scanThreatFeed(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("读取订阅条目失败: %w", err)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// GetThreatIntelFeedByIndicator 按指标反查订阅条目，聚合视图用它提示
// "这个地址在某个 feed 里出现过"。
func (db *DB) GetThreatIntelFeedByIndicator(indicatorType, normalized string) ([]*ThreatIntelFeedEntry, error) {
	rows, err := db.Query(`SELECT `+threatFeedColumns+` FROM threat_intel_feed
		WHERE indicator_type = ? AND normalized = ? ORDER BY source`, indicatorType, normalized)
	if err != nil {
		return nil, fmt.Errorf("查询订阅条目失败: %w", err)
	}
	defer rows.Close()
	var out []*ThreatIntelFeedEntry
	for rows.Next() {
		e, err := scanThreatFeed(rows)
		if err != nil {
			return nil, fmt.Errorf("读取订阅条目失败: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanThreatFeed(row interface{ Scan(...interface{}) error }) (*ThreatIntelFeedEntry, error) {
	var (
		e         ThreatIntelFeedEntry
		firstSeen sql.NullString
		lastSeen  sql.NullString
	)
	if err := row.Scan(&e.ID, &e.Source, &e.IndicatorType, &e.Normalized, &e.Category,
		&e.Malware, &e.Confidence, &firstSeen, &lastSeen, &e.Tags, &e.Payload, &e.FetchedAt); err != nil {
		return nil, err
	}
	e.FirstSeen = firstSeen.String
	e.LastSeen = lastSeen.String
	return &e, nil
}

// ThreatIntelFeedStats 是各源的条目数，用于页面上的源健康带。
type ThreatIntelFeedStats struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

// CountThreatIntelFeedBySource 统计每个源的订阅条目数。
func (db *DB) CountThreatIntelFeedBySource() ([]*ThreatIntelFeedStats, error) {
	rows, err := db.Query(`SELECT source, COUNT(*) FROM threat_intel_feed GROUP BY source ORDER BY source`)
	if err != nil {
		return nil, fmt.Errorf("统计订阅源条目失败: %w", err)
	}
	defer rows.Close()
	var out []*ThreatIntelFeedStats
	for rows.Next() {
		var s ThreatIntelFeedStats
		if err := rows.Scan(&s.Source, &s.Count); err != nil {
			return nil, err
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}
