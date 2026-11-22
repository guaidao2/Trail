package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"trail/internal/database"
	"trail/internal/security"
	"trail/internal/threatintel"
)

// ThreatIntelHandler 是「威胁情报」页面的接口层。
//
// 它刻意与 HostHandler 分开：威胁情报是独立的一等模块，数据、权限点、
// 页面都与 IOC 情报和漏洞情报分离，混进 HostHandler 只会让职责继续变糊。
type ThreatIntelHandler struct {
	db      *database.DB
	logger  *zap.Logger
	service func() *threatintel.Service
}

// NewThreatIntelHandler 构造 handler。
//
// service 传的是取值函数而不是实例：威胁情报服务会随配置变更重建，
// handler 如果抓着启动时那个实例，改完 Key 或代理后 REST 侧一直是旧配置。
func NewThreatIntelHandler(db *database.DB, service func() *threatintel.Service, logger *zap.Logger) *ThreatIntelHandler {
	return &ThreatIntelHandler{db: db, service: service, logger: logger}
}

// svc 返回当前的服务实例；未装配时返回 nil，各接口据此报"未启用"。
func (h *ThreatIntelHandler) svc() *threatintel.Service {
	if h.service == nil {
		return nil
	}
	return h.service()
}

// ListSources 返回所有源的注册信息、健康度与订阅条目数。
func (h *ThreatIntelHandler) ListSources(c *gin.Context) {
	svc := h.svc()
	if svc == nil {
		c.JSON(http.StatusOK, gin.H{"items": []any{}, "feed_counts": []any{}, "enabled": false})
		return
	}
	sources, stats, err := svc.Sources()
	if err != nil {
		h.logger.Warn("读取威胁情报源失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取威胁情报源失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": sources, "feed_counts": stats, "enabled": true})
}

// Query 查询一个指标在所有源上的观测，返回聚合结果。
func (h *ThreatIntelHandler) Query(c *gin.Context) {
	svc := h.svc()
	if svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "威胁情报模块未启用"})
		return
	}
	indType := strings.TrimSpace(c.Query("type"))
	value := strings.TrimSpace(c.Query("value"))
	if value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value 不能为空"})
		return
	}
	result, err := svc.Query(c.Request.Context(), indType, value)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	threatintel.SortResultsByCategory(result.Results)
	c.JSON(http.StatusOK, result)
}

// ListFeed 分页返回订阅条目。
func (h *ThreatIntelHandler) ListFeed(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	// 与 DB 层上限对齐，避免回显的 page_size 与实际取数不一致。
	if limit > 200 {
		limit = 200
	}
	items, total, err := h.db.ListThreatIntelFeed(database.ThreatIntelFeedFilter{
		Source:        c.Query("source"),
		IndicatorType: c.Query("type"),
		Category:      c.Query("category"),
		Keyword:       c.Query("keyword"),
	}, limit, (page-1)*max(limit, 1))
	if err != nil {
		h.logger.Warn("读取威胁情报订阅条目失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取订阅条目失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "page_size": limit})
}

// AdoptIOC 把一条外部观测显式写成 IOC 记录。
//
// 这是威胁情报与 IOC 之间**唯一**的通道，而且必须由人触发：
// 外部源说什么都不能自动进 IOC 库，否则最需要人工判断的状态机会被稀释。
// 权限上要求同时具备 threatintel:write（走这条路由）与 ioc:write（真的写 IOC 表）。
func (h *ThreatIntelHandler) AdoptIOC(c *gin.Context) {
	// 路由层已经按 threatintel:write 拦了一道；这里再查 ioc:write，
	// 因为采纳动作真正写的是 IOC 表，只具备威胁情报权限的人不该动它。
	if !security.SessionHasPermission(c, "ioc:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 ioc:write 权限，无法写入 IOC 库"})
		return
	}

	var req struct {
		Type    string `json:"type"`
		Value   string `json:"value"`
		Source  string `json:"source"`
		Verdict string `json:"verdict"`
		Summary string `json:"summary"`
		Note    string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	value := strings.TrimSpace(req.Value)
	if value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value 不能为空"})
		return
	}
	indType := strings.ToLower(strings.TrimSpace(req.Type))
	if indType == "" {
		indType = "ip"
	}

	// 置信度按外部判定给一个保守起点：恶意 80、可疑 60，其余 50。
	// 状态一律是 observed——外部源没有资格替人确认。
	confidence := 50
	switch strings.ToLower(strings.TrimSpace(req.Verdict)) {
	case database.ThreatVerdictMalicious:
		confidence = 80
	case database.ThreatVerdictSuspicious:
		confidence = 60
	}
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "threat-intel"
	} else {
		source = "threatintel:" + source
	}
	note := strings.TrimSpace(req.Note)
	if note == "" {
		note = strings.TrimSpace(req.Summary)
	}
	if note == "" {
		note = "由威胁情报页面采纳"
	}

	// 已经存在的条目只补备注线索，不动人工维护过的置信度与严重度：
	// 采纳是"外部证据入档"，不是"重新判一遍"，否则人工调好的评级会被冲掉。
	//
	// 注意来源不会被改写：UpsertIOC 的 UPDATE 分支没有 source 列，
	// 旧条目保留第一次入库时的来源。这是有意的——"最早是谁发现的"比
	// "最近谁又提了一次"更有价值。
	upsert := database.IOCUpsert{
		Type:       indType,
		Value:      value,
		Status:     database.IOCStatusObserved,
		Confidence: confidence,
		Severity:   "medium",
		Source:     source,
		Note:       note,
	}
	if existing, eerr := h.db.GetIOCByValue(indType, value); eerr != nil {
		// 查重失败不能当成"不存在"继续写：那会把人工维护的字段覆盖掉。
		h.logger.Warn("采纳前查重失败", zap.Error(eerr), zap.String("value", value))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取 IOC 失败: " + eerr.Error()})
		return
	} else if existing != nil {
		upsert.Confidence = existing.Confidence
		upsert.Severity = existing.Severity
		if strings.TrimSpace(existing.Note) != "" {
			upsert.Note = existing.Note
		}
	}
	rec, created, err := h.db.UpsertIOC(upsert)
	if err != nil {
		h.logger.Warn("采纳威胁情报为 IOC 失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 IOC 失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ioc": rec, "created": created})
}

// SyncFeed 触发一次订阅源同步。source 留空表示同步全部已注册的订阅源。
func (h *ThreatIntelHandler) SyncFeed(c *gin.Context) {
	svc := h.svc()
	if svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "威胁情报模块未启用"})
		return
	}
	var req struct {
		Source string `json:"source"`
	}
	// 空请求体是合法的（同步全部）；有内容但解析失败则明确报错，
	// 否则一个写坏的 JSON 会被静默当成"同步全部"。
	// ContentLength 为 -1 表示 chunked，读一次再解析，避免绕过校验。
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil && strings.TrimSpace(err.Error()) != "EOF" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
			return
		}
	}

	if src := strings.TrimSpace(req.Source); src != "" {
		n, err := svc.SyncFeed(c.Request.Context(), src)
		if err != nil {
			// 已有同步在跑不是客户端错误，用 409 让前端区分"稍后重试"和"参数不对"。
			if errors.Is(err, threatintel.ErrSyncInProgress) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": src + ": " + err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"synced": map[string]int{src: n}})
		return
	}

	results, errs, started := svc.SyncAllFeeds(c.Request.Context())
	if !started {
		// 已有同步在跑不是上游故障，用 409 让前端区分"稍后重试"和"源真的挂了"。
		c.JSON(http.StatusConflict, gin.H{"error": threatintel.ErrSyncInProgress.Error()})
		return
	}
	if len(results) == 0 && len(errs) > 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": strings.Join(errs, "; ")})
		return
	}
	c.JSON(http.StatusOK, gin.H{"synced": results, "errors": errs})
}
