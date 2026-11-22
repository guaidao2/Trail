package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"trail/internal/database"
)

// Config 是服务的运行参数。
type Config struct {
	// Proxy 是出口代理，内网部署常用。
	Proxy string
	// Keys 按源标识存 API Key。没有 key 的源不会发起查询。
	Keys map[string]string
	// Endpoints 覆盖各源默认入口，便于内网镜像或测试。
	Endpoints map[string]string
	// Timeout 是单次 HTTP 请求超时。
	Timeout time.Duration
	// FeedTTL 是订阅条目的保留天数，超期条目在同步后清理。
	FeedTTL time.Duration
	// CacheTTL 是查询结果的兜底缓存时长：provider 没给出过期时间时用它，
	// 同时作为源注册时 ttl_seconds 的默认值。
	CacheTTL time.Duration
	// DisabledSources 是显式停用的源标识，优先级高于库里的 enabled 状态。
	DisabledSources []string
}

// AggregateResult 是"一个指标在所有源上的观测"的聚合视图。
type AggregateResult struct {
	Type           string                           `json:"type"`
	Value          string                           `json:"value"`
	Normalized     string                           `json:"normalized"`
	OverallVerdict string                           `json:"overall_verdict"`
	Results        []*Result                        `json:"results"`
	FeedHits       []*database.ThreatIntelFeedEntry `json:"feed_hits,omitempty"`
	Note           string                           `json:"note,omitempty"`
	Skipped        []string                         `json:"skipped,omitempty"`
}

// feedSyncMu 串行化所有订阅同步入口（定时任务 / REST / MCP 工具）。
//
// 放在包级而不是 Service 上：Service 会随配置变化重建，锁挂在实例上等于
// 每次重建都换一把新锁，互斥就失效了。同步本身是"整源替换"，
// 两个入口并发跑会互相覆盖对方刚写进去的条目。
var feedSyncMu sync.Mutex

// Service 是威胁情报的编排层：负责缓存、配额、源健康、私网短路与聚合。
type Service struct {
	db     *database.DB
	doer   *HTTPDoer
	logger *zap.Logger
	cfg    Config

	// disabledSources 从 cfg 复制一份，配置热更新后仍保持构造时的判断口径。
	disabledSources []string

	mu      sync.RWMutex
	lookups []LookupProvider
	feeds   []FeedProvider

	limMu    sync.Mutex
	limiters map[string]*rateLimiter
}

// NewService 构造服务并注册默认源。
func NewService(db *database.DB, cfg Config, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	// 配置会热更新，快照里的 map 仍是共享引用，这里复制一份避免并发读写。
	cfg.Keys = copyStringMap(cfg.Keys)
	cfg.Endpoints = copyStringMap(cfg.Endpoints)
	cfg.DisabledSources = append([]string(nil), cfg.DisabledSources...)
	doer := NewHTTPDoer(cfg.Proxy, cfg.Timeout)
	s := &Service{
		db:              db,
		doer:            doer,
		logger:          logger,
		cfg:             cfg,
		disabledSources: cfg.DisabledSources,
	}
	// 免 Key 的三源先上：客户一个 key 都不配也有可用情报。
	s.RegisterLookup(NewInternetDB(doer, cfg.Endpoints["internetdb"]))
	s.RegisterLookup(NewGreyNoise(doer, cfg.Endpoints["greynoise"]))
	s.RegisterLookup(NewOTX(doer, cfg.Endpoints["otx"]))
	// 需要 Key 的两源默认关闭，客户配了 key 才会真的发请求。
	s.RegisterLookup(NewAbuseIPDB(doer, cfg.Endpoints["abuseipdb"]))
	s.RegisterLookup(NewVirusTotal(doer, cfg.Endpoints["virustotal"]))

	// 订阅式源：两个免 Key（Spamhaus / Feodo），两个要 abuse.ch Auth-Key。
	s.RegisterFeed(NewSpamhausDROP(doer, cfg.Endpoints["spamhaus_drop"]))
	s.RegisterFeed(NewFeodoTracker(doer, cfg.Endpoints["feodo"]))
	s.RegisterFeed(NewURLhaus(doer, cfg.Endpoints["urlhaus"]))
	s.RegisterFeed(NewThreatFox(doer, cfg.Endpoints["threatfox"]))
	return s
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// RegisterLookup 注册一个查询式源。重复注册同名源时后者覆盖前者。
func (s *Service) RegisterLookup(p LookupProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.lookups {
		if existing.Name() == p.Name() {
			s.lookups[i] = p
			return
		}
	}
	s.lookups = append(s.lookups, p)
}

// RegisterFeed 注册一个订阅式源。
func (s *Service) RegisterFeed(p FeedProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.feeds {
		if existing.Name() == p.Name() {
			s.feeds[i] = p
			return
		}
	}
	s.feeds = append(s.feeds, p)
}

func (s *Service) lookupByName(name string) LookupProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.lookups {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func (s *Service) feedByName(name string) FeedProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.feeds {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// EnsureSources 把已注册的源写进 threat_intel_source，启动时调用一次。
//
// 它是配置到库的**投影**：除了健康度与配额用量，其余字段都以这里为准，
// 包括是否启用（由 disabled_sources 派生）与 ttl_seconds（由 CacheTTL 派生）。
// 换句话说，库里的 enabled / ttl_seconds 不是第二个配置入口——手工改 DB
// 会在下次启动或配置变更时被覆盖回去，这是有意的。
func (s *Service) EnsureSources(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	s.mu.RLock()
	lookups := append([]LookupProvider(nil), s.lookups...)
	feeds := append([]FeedProvider(nil), s.feeds...)
	s.mu.RUnlock()

	for _, p := range lookups {
		existing, err := s.db.GetThreatIntelSource(p.Name())
		if err != nil {
			return err
		}
		// 配置是启停的**唯一**权威：名单里有就关，没有就开。
		// 不能"关了写进库、库里又反过来盖住配置"——那样把源从名单里删掉
		// 永远恢复不了，而页面上又没有手动开关。
		disabled := s.sourceDisabled(p.Name())
		ttlSeconds := 3600
		if s.cfg.CacheTTL > 0 {
			ttlSeconds = int(s.cfg.CacheTTL.Seconds())
		}
		src := database.ThreatIntelSource{
			Source:      p.Name(),
			Mode:        database.ThreatModeLookup,
			Enabled:     !disabled,
			RequiresKey: p.RequiresKey(),
			Endpoint:    s.cfg.Endpoints[p.Name()],
			TTLSeconds:  ttlSeconds,
		}
		if hint, ok := p.(QuotaHint); ok {
			src.DailyQuota = hint.DefaultDailyQuota()
			src.RateLimitPerMinute = hint.DefaultRateLimitPerMinute()
		}
		if existing != nil {
			// TTL 同理：配置里给了就按配置，没给才沿用库里手工调过的值，
			// 否则 cache_ttl_seconds 改了也永远落不到已有源上。
			if s.cfg.CacheTTL <= 0 && existing.TTLSeconds > 0 {
				src.TTLSeconds = existing.TTLSeconds
			}
			// 配额没有对应的配置项，库里调过就以库为准。
			if existing.DailyQuota > 0 {
				src.DailyQuota = existing.DailyQuota
			}
			if existing.RateLimitPerMinute > 0 {
				src.RateLimitPerMinute = existing.RateLimitPerMinute
			}
			if src.Endpoint == "" {
				src.Endpoint = existing.Endpoint
			}
		}
		if err := s.db.UpsertThreatIntelSource(src); err != nil {
			return err
		}
	}
	for _, p := range feeds {
		existing, err := s.db.GetThreatIntelSource(p.Name())
		if err != nil {
			return err
		}
		disabled := s.sourceDisabled(p.Name())
		src := database.ThreatIntelSource{
			Source:      p.Name(),
			Mode:        database.ThreatModeFeed,
			Enabled:     !disabled,
			RequiresKey: p.RequiresKey(),
			Endpoint:    s.cfg.Endpoints[p.Name()],
			TTLSeconds:  int((24 * time.Hour).Seconds()),
		}
		if existing != nil {
			src.DailyQuota = existing.DailyQuota
			src.RateLimitPerMinute = existing.RateLimitPerMinute
			if existing.TTLSeconds > 0 {
				src.TTLSeconds = existing.TTLSeconds
			}
			if src.Endpoint == "" {
				src.Endpoint = existing.Endpoint
			}
		}
		if err := s.db.UpsertThreatIntelSource(src); err != nil {
			return err
		}
	}
	return nil
}

// sourceDisabled 判断某个源是否在配置的停用名单里。
func (s *Service) sourceDisabled(name string) bool {
	for _, d := range s.disabledSources {
		if strings.EqualFold(strings.TrimSpace(d), name) {
			return true
		}
	}
	return false
}

// Sources 返回源清单与各源 feed 条目数，供页面健康带使用。
func (s *Service) Sources() ([]*database.ThreatIntelSource, []*database.ThreatIntelFeedStats, error) {
	if s.db == nil {
		return nil, nil, nil
	}
	list, err := s.db.ListThreatIntelSources()
	if err != nil {
		return nil, nil, err
	}
	stats, err := s.db.CountThreatIntelFeedBySource()
	if err != nil {
		// 统计失败不影响源清单展示，降级为无计数。
		stats = nil
	}
	return list, stats, nil
}

// Query 查询一个指标在全部可用源上的观测。
//
// 这里刻意串行：源通常只有几个，并行带来的收益抵不上配额竞争与日志交错的麻烦。
func (s *Service) Query(ctx context.Context, indicatorType, value string) (*AggregateResult, error) {
	indType := strings.ToLower(strings.TrimSpace(indicatorType))
	if indType == "" {
		indType = "ip"
	}
	normalized := database.NormalizeIOCValue(indType, value)
	if normalized == "" {
		return nil, errors.New("指标值为空")
	}

	agg := &AggregateResult{
		Type:       indType,
		Value:      strings.TrimSpace(value),
		Normalized: normalized,
		Results:    []*Result{},
	}

	// 私网地址在公开情报库里必然查不到，直接短路，省配额也省日志噪音。
	if indType == "ip" && isPrivateIP(normalized) {
		agg.OverallVerdict = database.ThreatVerdictUnknown
		agg.Note = "内网地址，公开威胁情报不覆盖，跳过外部查询"
		return agg, nil
	}

	s.mu.RLock()
	providers := append([]LookupProvider(nil), s.lookups...)
	s.mu.RUnlock()

	for _, p := range providers {
		if !p.Supports(indType) {
			continue
		}
		res, err := s.queryOne(ctx, p, Indicator{Type: indType, Value: value, Normalized: normalized})
		if err != nil {
			switch {
			case errors.Is(err, ErrMissingKey):
				agg.Skipped = append(agg.Skipped, p.Name()+"（未配置 Key）")
				continue
			case errors.Is(err, ErrSourceDisabled):
				// 和缺 Key 分开写：让人去补 Key 是白忙，这个是配置里主动关掉的。
				agg.Skipped = append(agg.Skipped, p.Name()+"（已在配置中停用）")
				continue
			case errors.Is(err, ErrQuotaExceeded):
				agg.Skipped = append(agg.Skipped, p.Name()+"（配额用尽）")
				continue
			default:
				// 单源失败不影响其它源，但要让调用方看见。
				agg.Skipped = append(agg.Skipped, p.Name()+"（查询失败："+err.Error()+"）")
				continue
			}
		}
		agg.Results = append(agg.Results, res)
	}

	if s.db != nil {
		hits, err := s.db.GetThreatIntelFeedByIndicator(indType, normalized)
		if err == nil {
			agg.FeedHits = hits
		}
	}

	agg.OverallVerdict = overallVerdict(agg.Results, agg.FeedHits)
	return agg, nil
}

// queryOne 处理单个源的缓存、配额与健康度。
func (s *Service) queryOne(ctx context.Context, p LookupProvider, ind Indicator) (*Result, error) {
	source := p.Name()

	// 这两项从源记录里一次取出，后面写缓存和节流都复用，不再重复查同一张表。
	var sourceTTL, rateLimitPerMinute int

	// 顺序有讲究：启用检查 → Key 检查 → 缓存 → 配额 → 节流 → 请求。
	// Key 放在配额之前，是因为没 Key 的源根本发不出请求，
	// 先扣配额会让页面上出现"没配 Key 却一直在耗额度"的假象。
	key := strings.TrimSpace(s.cfg.Keys[source])
	if p.RequiresKey() && key == "" {
		return nil, ErrMissingKey
	}

	if s.db != nil {
		src, err := s.db.GetThreatIntelSource(source)
		if err != nil {
			return nil, err
		}
		if src != nil && !src.Enabled {
			return nil, ErrSourceDisabled
		}
		// 顺带记住 TTL 与限速，下面写缓存和节流都复用这一行，避免同表重复查三次。
		if src != nil {
			sourceTTL = src.TTLSeconds
			rateLimitPerMinute = src.RateLimitPerMinute
		}
		// 再看缓存，命中就不花配额。
		entry, err := s.db.GetThreatIntelCache(source, ind.Type, ind.Normalized)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			return cacheEntryToResult(entry), nil
		}
		allowed, err := s.db.ConsumeThreatQuota(source)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrQuotaExceeded
		}
	}

	// 节流只拦真实请求：缓存命中不该消耗等待时间，也不该占限速名额。
	if lim := s.limiterFor(source, rateLimitPerMinute); lim != nil {
		if err := lim.wait(ctx); err != nil {
			return nil, err
		}
	}

	res, err := p.Query(ctx, ind, key)
	if s.db != nil {
		recordErr := err
		if perr := s.db.RecordThreatSourceResult(source, recordErr); perr != nil {
			s.logger.Warn("记录威胁情报源状态失败", zap.String("source", source), zap.Error(perr))
		}
	}
	if err != nil {
		return nil, err
	}

	if s.db != nil && res != nil {
		entry := database.ThreatIntelCacheEntry{
			Source:        res.Source,
			IndicatorType: res.IndicatorType,
			Normalized:    res.Normalized,
			Category:      res.Category,
			Verdict:       res.Verdict,
			Payload:       res.Payload,
			HTTPStatus:    res.HTTPStatus,
			FetchedAt:     time.Now().UTC().Format("2006-01-02 15:04:05"),
		}
		// 标签也要落库：缓存命中时只从 payload 重算会丢掉 provider 加工过的内容，
		// 表现为第二次查询 CPE / eol-product 这类标签整块消失。
		if len(res.Tags) > 0 {
			if b, err := json.Marshal(res.Tags); err == nil {
				entry.Tags = string(b)
			}
		}
		if res.ExpiresAt != nil {
			entry.ExpiresAt = res.ExpiresAt.UTC().Format("2006-01-02 15:04:05")
		} else if fallback := s.fallbackTTL(sourceTTL); fallback > 0 {
			// provider 没给过期时间时用兜底 TTL：没有过期时间的缓存行会永不过期，
			// 一个老旧结论会一直覆盖真实情况。
			entry.ExpiresAt = time.Now().Add(fallback).UTC().Format("2006-01-02 15:04:05")
		}
		if err := s.db.PutThreatIntelCache(entry); err != nil {
			s.logger.Warn("写入威胁情报缓存失败", zap.String("source", source), zap.Error(err))
		}
	}
	return res, nil
}

// fallbackTTL 取兜底缓存时长：优先用源记录里的 ttl_seconds（调用方已查好传进来），
// 没配就退回全局的 CacheTTL。不再自己查库，避免同一个请求里第三次查同一张表。
func (s *Service) fallbackTTL(sourceTTLSeconds int) time.Duration {
	if sourceTTLSeconds > 0 {
		return time.Duration(sourceTTLSeconds) * time.Second
	}
	return s.cfg.CacheTTL
}

func cacheEntryToResult(e *database.ThreatIntelCacheEntry) *Result {
	var expires *time.Time
	if t := parseThreatTime(e.ExpiresAt); !t.IsZero() {
		expires = &t
	}
	var tags []string
	if strings.TrimSpace(e.Tags) != "" {
		_ = json.Unmarshal([]byte(e.Tags), &tags)
	}
	return &Result{
		Source:        e.Source,
		IndicatorType: e.IndicatorType,
		Normalized:    e.Normalized,
		Category:      e.Category,
		Verdict:       e.Verdict,
		HTTPStatus:    e.HTTPStatus,
		Payload:       e.Payload,
		Tags:          tags,
		ExpiresAt:     expires,
		Cached:        true,
		Summary:       summaryFromCache(e),
	}
}

// summaryFromCache 从原始 payload 重新生成一句话结论。
//
// 不直接复用"命中恶意判定（缓存）"这种泛化文案：缓存命中是常态，
// 每次都显示同一句话等于没有信息量，而且跟旁边的判定徽章重复。
func summaryFromCache(e *database.ThreatIntelCacheEntry) string {
	// 负缓存（unknown）必须走"无记录"文案：它的 payload 往往是
	// {"detail":"No information available"} 这类东西，交给各源的解析器
	// 会生成"有记录但未发现"这种自相矛盾的摘要，跟旁边的 unknown 徽章打架。
	if e.Verdict == database.ThreatVerdictUnknown {
		return fallbackVerdictText(database.ThreatVerdictUnknown)
	}
	if strings.TrimSpace(e.Payload) == "" {
		return fallbackVerdictText(e.Verdict)
	}
	switch e.Source {
	case "internetdb":
		var data internetDBResponse
		if err := json.Unmarshal([]byte(e.Payload), &data); err == nil {
			return summarizeInternetDB(data)
		}
	case "greynoise":
		var data greyNoiseResponse
		if err := json.Unmarshal([]byte(e.Payload), &data); err == nil {
			_, summary := classifyGreyNoise(data)
			return summary
		}
	case "otx":
		var data otxResponse
		if err := json.Unmarshal([]byte(e.Payload), &data); err == nil {
			_, summary := classifyOTX(data)
			return summary
		}
	case "abuseipdb":
		var data abuseIPDBResponse
		if err := json.Unmarshal([]byte(e.Payload), &data); err == nil {
			_, summary := classifyAbuseIPDB(data)
			return summary
		}
	case "virustotal":
		var data vtResponse
		if err := json.Unmarshal([]byte(e.Payload), &data); err == nil {
			_, summary := classifyVirusTotal(data)
			return summary
		}
	}
	return fallbackVerdictText(e.Verdict)
}

func fallbackVerdictText(verdict string) string {
	switch verdict {
	case database.ThreatVerdictMalicious:
		return "命中恶意判定"
	case database.ThreatVerdictSuspicious:
		return "命中可疑判定"
	case database.ThreatVerdictClean:
		return "未见恶意记录"
	case VerdictExposure:
		return "仅有暴露面记录"
	default:
		return "没有该指标的公开观测记录"
	}
}

// parseThreatTime 兼容多种时间表示。
//
// 不能只认 "2006-01-02 15:04:05"：列声明成 DATETIME 时，sqlite 驱动读出来
// 会转成 RFC3339（"2026-11-22T04:07:20Z"），单一格式会把结果解析成零值，
// 表现为页面上"缓存有效期"整块消失。
func parseThreatTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// SyncFeed 拉取一个订阅源并整批替换其条目。
//
// 只有整轮成功才删除旧数据：拉取失败时保留上一轮内容，总比表里空着好。
func (s *Service) SyncFeed(ctx context.Context, source string) (int, error) {
	// 用 TryLock 而不是 Lock：一轮同步最长十分钟，排队会把 REST 请求挂住，
	// 而且 ctx 取消也救不了已经被阻塞的 Lock。拿不到就明确告诉调用方稍后再试。
	if !feedSyncMu.TryLock() {
		return 0, ErrSyncInProgress
	}
	defer feedSyncMu.Unlock()
	return s.syncFeedLocked(ctx, source)
}

// syncFeedLocked 是不加锁的实现，只能由已持有 feedSyncMu 的调用方使用。
func (s *Service) syncFeedLocked(ctx context.Context, source string) (int, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return 0, fmt.Errorf("订阅源标识不能为空")
	}
	p := s.feedByName(source)
	if p == nil {
		return 0, fmt.Errorf("未知的订阅源: %s", source)
	}
	if s.db != nil {
		src, err := s.db.GetThreatIntelSource(source)
		if err != nil {
			return 0, err
		}
		if src != nil && !src.Enabled {
			return 0, ErrSourceDisabled
		}
	}
	key := strings.TrimSpace(s.cfg.Keys[source])
	if p.RequiresKey() && key == "" {
		return 0, ErrMissingKey
	}

	entries, err := p.Fetch(ctx, key)
	if err != nil {
		if s.db != nil {
			if perr := s.db.RecordThreatSourceResult(source, err); perr != nil {
				s.logger.Warn("记录订阅源状态失败", zap.String("source", source), zap.Error(perr))
			}
		}
		return 0, err
	}

	if s.db == nil {
		return len(entries), nil
	}

	// 整源替换放在一个事务里，写失败时旧数据还在。
	n, err := s.db.ReplaceThreatIntelFeed(source, entries)
	if err != nil {
		if perr := s.db.RecordThreatSourceResult(source, err); perr != nil {
			s.logger.Warn("记录订阅源状态失败", zap.String("source", source), zap.Error(perr))
		}
		return 0, err
	}
	// 状态在提交成功之后才记：否则页面会显示"最近成功"但库里其实没写进去。
	if perr := s.db.RecordThreatSourceResult(source, nil); perr != nil {
		s.logger.Warn("记录订阅源状态失败", zap.String("source", source), zap.Error(perr))
	}
	if n == 0 {
		// 空集合不清旧数据，只提示，避免上游异常把本地情报抹空。
		s.logger.Warn("订阅源返回空集合，保留上一轮数据", zap.String("source", source))
		return 0, nil
	}
	s.logger.Info("订阅源同步完成", zap.String("source", source), zap.Int("entries", n))
	return n, nil
}

// SyncAllFeeds 同步所有已注册的订阅源。单源失败不影响其它源：
// 一个源挂了不该让整轮同步空手而归。
//
// 第三个返回值 started 表示这一轮是否真的启动：false 意味着已有同步在跑，
// 调用方应视为"跳过"而不是"失败"。用 bool 而不是错误字符串来区分，
// 是因为文案会改、而语义不该跟着改。
func (s *Service) SyncAllFeeds(ctx context.Context) (results map[string]int, errs []string, started bool) {
	if !feedSyncMu.TryLock() {
		return map[string]int{}, nil, false
	}
	defer feedSyncMu.Unlock()

	s.mu.RLock()
	feeds := append([]FeedProvider(nil), s.feeds...)
	s.mu.RUnlock()

	out := map[string]int{}
	var failures []string
	for _, p := range feeds {
		n, err := s.syncFeedLocked(ctx, p.Name())
		if err != nil {
			// 没配 key / 已关闭属于"预期跳过"，不当成错误上报。
			if errors.Is(err, ErrMissingKey) || errors.Is(err, ErrSourceDisabled) {
				continue
			}
			failures = append(failures, p.Name()+": "+err.Error())
			continue
		}
		out[p.Name()] = n
	}
	return out, failures, true
}

// overallVerdict 把多源结果合成一个总判定。优先级：
// 恶意 > 可疑 > 仅暴露面 > 干净 > 未知。
func overallVerdict(results []*Result, feedHits []*database.ThreatIntelFeedEntry) string {
	if len(feedHits) > 0 {
		return database.ThreatVerdictMalicious
	}
	rank := map[string]int{
		database.ThreatVerdictMalicious:  5,
		database.ThreatVerdictSuspicious: 4,
		VerdictExposure:                  3,
		database.ThreatVerdictClean:      2,
		database.ThreatVerdictUnknown:    1,
	}
	best := ""
	bestRank := 0
	for _, r := range results {
		if v, ok := rank[r.Verdict]; ok && v > bestRank {
			best, bestRank = r.Verdict, v
		}
	}
	if best == "" {
		return database.ThreatVerdictUnknown
	}
	return best
}

// isPrivateIP 判断是否是不该去公开库里查的地址。
// 除了 RFC1918，还排除回环、链路本地、组播与文档保留段——
// 这些查了也必然是空，只是在烧配额。
func isPrivateIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// 共享地址、文档与测试保留段：公网库里同样不会有。
	// 100.64.0.0/10 是运营商级 NAT，Go 的 IsPrivate 不覆盖它。
	for _, cidr := range []string{
		"100.64.0.0/10",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15",
		"240.0.0.0/4", "255.255.255.255/32", "192.88.99.0/24",
		"2001:db8::/32", "64:ff9b::/96", "::/128",
	} {
		if _, block, err := net.ParseCIDR(cidr); err == nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

// SortResultsByCategory 让页面渲染顺序稳定：恶意判定在前，暴露面在后。
func SortResultsByCategory(results []*Result) {
	sort.SliceStable(results, func(i, j int) bool {
		return categoryRank(results[i].Category) < categoryRank(results[j].Category)
	})
}

func categoryRank(c string) int {
	if c == database.ThreatCategoryReputation {
		return 0
	}
	return 1
}

// Maintain 做一次例行清理：清过期查询缓存、按 FeedTTL 清旧订阅条目。
// 由定时任务在同步之后调用；不做的话 cache 行会一直涨（单行 payload 最大 16KB）。
func (s *Service) Maintain(ctx context.Context) (cacheDeleted, feedDeleted int64, err error) {
	if s.db == nil {
		return 0, 0, nil
	}
	cacheDeleted, err = s.db.PurgeExpiredThreatIntelCache(time.Now())
	if err != nil {
		return cacheDeleted, 0, err
	}
	ttl := s.cfg.FeedTTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	feedDeleted, err = s.db.PruneThreatIntelFeed(time.Now().Add(-ttl))
	return cacheDeleted, feedDeleted, err
}
