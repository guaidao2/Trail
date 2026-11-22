package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"trail/internal/config"
	"trail/internal/database"
	"trail/internal/mcp"
	"trail/internal/mcp/builtin"
	"trail/internal/threatintel"
)

// registerThreatIntelTools 注册威胁情报相关工具。
//
// 这组工具返回的是「外部源看到了什么」，不是「我们认定它是什么」。
// 想让某条观测进入 IOC 库，必须走 ioc_upsert 显式写入，避免外部源替人下结论。
func registerThreatIntelTools(server *mcp.Server, db *database.DB, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolThreatIntelQuery,
		ShortDescription: "查询外部威胁情报",
		Description:      "拿一个 IP / 域名 / URL / 哈希去外部情报源查观测事实：暴露端口、服务指纹、已知漏洞、恶意判定、扫描器分类等。返回按来源分列的证据，以及一个总判定。注意：这是外部源的观测，不是我们研判出的 IOC；要把它落成 IOC 请用 ioc_upsert 显式写入。内网地址会被直接跳过，因为公开情报库不覆盖。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"value": map[string]interface{}{"type": "string", "description": "指标值，如 1.2.3.4 / evil.example.com / https://x/y / <sha256>"},
				"type":  map[string]interface{}{"type": "string", "description": "指标类型：ip / domain / url / md5 / sha1 / sha256；留空默认 ip"},
			},
			"required": []string{"value"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "threatintel:read"); !ok {
			return textResult("缺少 threatintel:read 权限", true), nil
		}
		value := strings.TrimSpace(strArg(args, "value"))
		if value == "" {
			return textResult("value 不能为空", true), nil
		}
		indType := strings.TrimSpace(strArg(args, "type"))
		if indType == "" {
			indType = "ip"
		}
		svc := currentThreatIntelService(db, logger)
		result, err := svc.Query(ctx, indType, value)
		if err != nil {
			return textResult("查询威胁情报失败: "+err.Error(), true), nil
		}
		threatintel.SortResultsByCategory(result.Results)
		b, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolThreatIntelSources,
		ShortDescription: "查看威胁情报源状态",
		Description:      "列出所有外部情报源的接入模式（按需查询 / 订阅落地）、是否启用、是否需要 Key、今日配额用量、最近成功时间与最近错误，以及各订阅源的条目数。排查\"为什么查不到东西\"时先看这里。",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "threatintel:read"); !ok {
			return textResult("缺少 threatintel:read 权限", true), nil
		}
		svc := currentThreatIntelService(db, logger)
		sources, stats, err := svc.Sources()
		if err != nil {
			return textResult("读取威胁情报源失败: "+err.Error(), true), nil
		}
		payload := map[string]interface{}{"sources": sources, "feed_counts": stats}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolThreatIntelFeed,
		ShortDescription: "检索订阅情报条目",
		Description:      "在被拉取到本地的订阅 feed 里检索指标（URLhaus 的恶意 URL、ThreatFox 的 IOC、Feodo 的 C2、Spamhaus 的失陷网段）。可按来源、指标类型、类别与关键词过滤。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"keyword":   map[string]interface{}{"type": "string", "description": "关键词，匹配指标值 / 家族名 / 标签"},
				"source":    map[string]interface{}{"type": "string", "description": "只查某个订阅源"},
				"type":      map[string]interface{}{"type": "string", "description": "ip / domain / url / cidr / md5 / sha1 / sha256；填 hash 表示三种哈希算法都查"},
				"category":  map[string]interface{}{"type": "string", "description": "类别，如 c2 / malware_url / cidr"},
				"page":      map[string]interface{}{"type": "integer", "description": "页码，默认 1"},
				"page_size": map[string]interface{}{"type": "integer", "description": "每页条数，默认 20，上限 100"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "threatintel:read"); !ok {
			return textResult("缺少 threatintel:read 权限", true), nil
		}
		page := intArg(args, "page", 1)
		if page < 1 {
			page = 1
		}
		size := intArg(args, "page_size", 20)
		if size <= 0 {
			size = 20
		}
		if size > 100 {
			size = 100
		}
		items, total, err := db.ListThreatIntelFeed(database.ThreatIntelFeedFilter{
			Source:        strArg(args, "source"),
			IndicatorType: strArg(args, "type"),
			Category:      strArg(args, "category"),
			Keyword:       strArg(args, "keyword"),
		}, size, (page-1)*size)
		if err != nil {
			return textResult("检索订阅条目失败: "+err.Error(), true), nil
		}
		b, _ := json.MarshalIndent(map[string]interface{}{
			"items": items, "total": total, "page": page, "page_size": size,
		}, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolThreatIntelSync,
		ShortDescription: "同步威胁情报订阅源",
		Description:      "触发订阅式情报源（URLhaus / ThreatFox / Feodo / Spamhaus 等）拉取最新全量数据。source 留空则同步全部已启用的订阅源。需要 key 的源若未配置会被跳过，不算失败。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"source": map[string]interface{}{"type": "string", "description": "只同步某个源；留空同步全部"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "threatintel:write"); !ok {
			return textResult("缺少 threatintel:write 权限", true), nil
		}
		svc := currentThreatIntelService(db, logger)
		src := strings.TrimSpace(strArg(args, "source"))
		if src != "" {
			n, err := svc.SyncFeed(ctx, src)
			if err != nil {
				return textResult(src+" 同步失败: "+err.Error(), true), nil
			}
			b, _ := json.MarshalIndent(map[string]interface{}{"synced": map[string]int{src: n}}, "", "  ")
			return textResult(string(b), false), nil
		}
		results, errs, started := svc.SyncAllFeeds(ctx)
		if !started {
			return textResult("已有同步任务在进行中，请稍后重试", true), nil
		}
		b, _ := json.MarshalIndent(map[string]interface{}{"synced": results, "errors": errs}, "", "  ")
		return textResult(string(b), false), nil
	})
}

// threatIntelSvcState 是整个进程共享的威胁情报服务。
//
// 为什么不在注册工具时构造一个就完事：MCP 工具在 New() 早期注册，那时
// threatIntelCfgSnapshot 还没注入（要到 setupRoutes 阶段），提前构造会拿到
// 零配置，config.yaml 里的 keys / endpoints / proxy 全部失效。所以改成
// 调用时按当前配置取服务，配置一变就重建。
//
// 复用同一个实例还有一个必须的理由：节流器挂在 Service 上。每个入口
// （REST / MCP / 定时任务）各建一个实例，VirusTotal 的 4 次/分钟就会
// 变成实例数倍的 4 次，配额照样被打光。
var (
	threatIntelSvcMu  sync.Mutex
	threatIntelSvc    *threatintel.Service
	threatIntelSvcSig string
)

// currentThreatIntelService 返回当前配置对应的服务实例，必要时重建。
func currentThreatIntelService(db *database.DB, logger *zap.Logger) *threatintel.Service {
	threatIntelSvcMu.Lock()
	defer threatIntelSvcMu.Unlock()

	// 快照与签名都必须在锁内取：锁外取的话，两个并发调用可能以相反顺序
	// 进锁——读旧配置的那个后进，就会拿旧配置把新实例覆盖回去，直到下一次
	// 调用才自愈；窗口内某些请求会用缺失的 Key 或旧 endpoint。
	cfg := threatIntelCfgSnapshot()
	// db 也要进签名：同一进程里可能出现第二个 DB（测试、多 App 装配），
	// 只按配置缓存会让它们拿到绑定前一个 DB 的服务。
	sig := threatIntelConfigSignature(cfg) + "|db=" + dbIdentity(db)

	if threatIntelSvc != nil && threatIntelSvcSig == sig {
		return threatIntelSvc
	}
	svc := threatintel.NewService(db, threatintel.Config{
		Proxy:           cfg.Proxy,
		Keys:            cfg.SourceKeys(),
		Endpoints:       cfg.Endpoints,
		Timeout:         cfg.ThreatIntelTimeout(),
		FeedTTL:         cfg.ThreatIntelFeedTTL(),
		CacheTTL:        time.Duration(cfg.CacheTTLSeconds) * time.Second,
		DisabledSources: cfg.DisabledSources,
	}, logger)
	if err := svc.EnsureSources(context.Background()); err != nil && logger != nil {
		logger.Warn("初始化威胁情报源失败", zap.Error(err))
	}
	threatIntelSvc = svc
	threatIntelSvcSig = sig
	return svc
}

// dbIdentity 给数据库句柄一个稳定的身份标识，用于缓存键。
func dbIdentity(db *database.DB) string {
	if db == nil {
		return "nil"
	}
	return fmt.Sprintf("%p", db)
}

// threatIntelConfigSignature 把影响服务行为的配置折成一个可比较的签名。
// map 必须排序后再拼，否则每次迭代顺序不同会让签名永远不相等、服务被反复重建。
func threatIntelConfigSignature(cfg config.ThreatIntelConfig) string {
	return strings.Join([]string{
		cfg.Proxy,
		cfg.Timeout,
		cfg.FeedSyncInterval,
		strconv.Itoa(cfg.FeedTTLDays),
		strconv.Itoa(cfg.CacheTTLSeconds),
		// 四个 Key 是固定字段，直接拼进签名；任一改变都会触发服务重建。
		cfg.AbuseIPDBKey,
		cfg.VirusTotalKey,
		cfg.URLhausKey,
		cfg.ThreatFoxKey,
		sortedMapSignature(cfg.Endpoints),
		// 停用名单也影响服务行为，必须进签名，否则改完名单不会触发重建。
		strings.Join(cfg.DisabledSources, ","),
	}, "|")
}

func sortedMapSignature(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}
