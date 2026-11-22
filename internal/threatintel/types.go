// Package threatintel 对接「外部威胁情报源」。
//
// 与 internal/database 里的 IOC 表是两回事：
//   - IOC 表是「我研判出的结论」，带状态机、可封禁；
//   - 这里拿回来的是「外部源观测到的事实」，只读、有 TTL、永不自动封禁。
//
// 两边的唯一通道是显式的「采纳」动作，由 handler 层完成，本包不碰 IOC 表。
//
// 源分两种接入模式，接口也分开，不要合并：
//   - LookupProvider：按需查询，拿一个指标问一次（Shodan InternetDB / GreyNoise / VT…）
//   - FeedProvider：订阅落地，定期拉全量集合（URLhaus / ThreatFox / Feodo / Spamhaus）
package threatintel

import (
	"context"
	"errors"
	"time"

	"trail/internal/database"
)

var (
	// ErrMissingKey 表示源已启用但没配 key，调用方应跳过而不是当成故障。
	ErrMissingKey = errors.New("该情报源需要 API Key，但未配置")
	// ErrUnsupported 表示源不覆盖这类指标。
	ErrUnsupported = errors.New("该情报源不支持此指标类型")
	// ErrQuotaExceeded 表示当日配额已用尽。
	ErrQuotaExceeded = errors.New("该情报源今日配额已用尽")
	// ErrSourceDisabled 表示源被配置关闭。
	ErrSourceDisabled = errors.New("该情报源未启用")
	// ErrSyncInProgress 表示已有同步在跑。同步是整源替换，并发跑会互相覆盖，
	// 所以第二个请求直接拒绝而不是排队——排队会让 REST 请求卡住十分钟。
	ErrSyncInProgress = errors.New("已有同步任务在进行中，请稍后重试")
)

// Indicator 是送去查询的指标。Normalized 一律由上层用 database.NormalizeIOCValue 生成，
// 各 provider 不再自己归一化，避免同一指标在不同源上落到不同键。
type Indicator struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Normalized string `json:"normalized"`
}

// Result 是一个源对某指标的一次观测结果。
type Result struct {
	Source        string     `json:"source"`
	IndicatorType string     `json:"indicator_type"`
	Normalized    string     `json:"normalized"`
	Category      string     `json:"category"` // reputation / exposure
	Verdict       string     `json:"verdict"`  // malicious / suspicious / clean / unknown / exposure
	HTTPStatus    int        `json:"http_status"`
	Payload       string     `json:"payload,omitempty"` // 原始响应（已截断），排查与溯源用
	Summary       string     `json:"summary"`           // 一句人读结论
	Tags          []string   `json:"tags,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	// Cached 表示这条来自缓存而非本次真实请求，页面上据此标注"缓存"。
	Cached bool `json:"cached"`
}

// LookupProvider 是按需查询式情报源。
type LookupProvider interface {
	// Name 是源标识，与 threat_intel_source.source 一致。
	Name() string
	// Category 返回 reputation 或 exposure，决定页面上归到哪一栏。
	Category() string
	// RequiresKey 表示是否必须配置 API Key。
	RequiresKey() bool
	// Supports 判断该源是否覆盖这类指标。
	Supports(indicatorType string) bool
	// Query 查询单个指标。key 为空而 RequiresKey 为真时应返回 ErrMissingKey。
	Query(ctx context.Context, ind Indicator, key string) (*Result, error)
}

// QuotaHint 是可选接口：源自己知道自己的免费额度时实现它，
// 让 EnsureSources 能把合理默认值写进 threat_intel_source，
// 避免一上来就用 0（不限量）把客户的配额打光。
type QuotaHint interface {
	DefaultDailyQuota() int
	DefaultRateLimitPerMinute() int
}

// FeedProvider 是订阅落地式情报源。
//
// 约定：Fetch 必须要么返回完整集合，要么返回错误；不允许返回半截数据。
// 上层用单事务整源替换（ReplaceThreatIntelFeed），写失败会回滚保留旧数据；
// 返回空集合则视为"这一轮没有数据"，同样保留旧数据而不是清空。
type FeedProvider interface {
	Name() string
	RequiresKey() bool
	Fetch(ctx context.Context, key string) ([]database.ThreatIntelFeedEntry, error)
}

// VerdictExposure 直接复用 database 里的定义，避免两个包各写一份字符串后漂移。
const VerdictExposure = database.ThreatVerdictExposure

// expiryIn 返回从现在起 d 之后的过期时刻指针。
// 用指针是为了让"没有过期时间"在 JSON 里被省略，而不是输出 0001-01-01T00:00:00Z。
func expiryIn(d time.Duration) *time.Time {
	t := time.Now().Add(d)
	return &t
}

// truncatePayload 限制原始响应入库大小，避免一个 banner 撑爆单行。
func truncatePayload(b []byte) string {
	const max = 16 * 1024
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max])
}
