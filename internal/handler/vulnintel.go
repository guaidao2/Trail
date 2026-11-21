package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"trail/internal/database"
	"trail/internal/vulnintel"

	"github.com/gin-gonic/gin"
)

// VulnIntelSyncFunc 由 app 层注入（同步需要 config 里的 key/代理/开关）。
type VulnIntelSyncFunc func(ctx context.Context, source string) (vulnintel.Summary, error)

// VulnIntelImportFunc 由 app 层注入：从本地文件离线导入情报。
type VulnIntelImportFunc func(ctx context.Context, path, format string) (vulnintel.Summary, error)

// ListVulnIntel 列出/检索漏洞情报，并返回总量、KEV 量与各源同步状态。
func (h *HostHandler) ListVulnIntel(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	kevOnly := c.Query("kev_only") == "1" || c.Query("kev_only") == "true"
	items, total, err := h.db.SearchVulnIntel(database.VulnIntelFilter{
		Keyword:  c.Query("keyword"),
		Product:  c.Query("product"),
		Vendor:   c.Query("vendor"),
		Version:  c.Query("version"),
		Severity: c.Query("severity"),
		KEVOnly:  kevOnly,
		Limit:    limit,
		Offset:   (page - 1) * limit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检索漏洞情报失败"})
		return
	}
	count, kev, err := h.db.CountVulnIntel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "统计漏洞情报失败"})
		return
	}
	ranges, _ := h.db.CountVulnIntelRanges()
	syncStates, _ := h.db.ListVulnIntelSync()
	c.JSON(http.StatusOK, gin.H{
		"items": items, "total": total, "page": page, "page_size": limit,
		"count": count, "kev": kev, "ranges": ranges, "sync": syncStates,
	})
}

// GetVulnIntel 返回单条情报详情（含区间与 PoC）。
func (h *HostHandler) GetVulnIntel(c *gin.Context) {
	cveID := strings.TrimSpace(c.Param("cve"))
	if cveID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CVE 编号不能为空"})
		return
	}
	rec, ranges, pocs, err := h.db.GetVulnIntel(cveID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取漏洞情报失败"})
		return
	}
	if rec == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "情报库没有这条记录"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"vulnerability": rec, "ranges": ranges, "pocs": pocs})
}

// SyncVulnIntel 触发一次同步（需 intel:write）。
func (h *HostHandler) SyncVulnIntel(c *gin.Context) {
	if h.vulnIntelSync == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "漏洞情报同步未启用（检查配置 vuln_intel）"})
		return
	}
	source := strings.ToLower(strings.TrimSpace(c.Query("source")))
	sum, err := h.vulnIntelSync(c.Request.Context(), source)
	payload := gin.H{"summary": sum}
	if err != nil {
		payload["error"] = err.Error()
		c.JSON(http.StatusBadGateway, payload)
		return
	}
	c.JSON(http.StatusOK, payload)
}

// ImportVulnIntel 从本地文件离线导入情报（需 intel:write）。
//
// 用途：内网环境拿不到外网时，把在别处下载好的 KEV / EPSS / NVD JSON 传上来导入。
// 路径是 Trail 所在机器上的本地文件路径；格式留空则按内容自动识别。
func (h *HostHandler) ImportVulnIntel(c *gin.Context) {
	if h.vulnIntelImport == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "漏洞情报导入未启用"})
		return
	}
	var body struct {
		Path   string `json:"path"`
		Format string `json:"format"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误（需要 path，可选 format）"})
		return
	}
	sum, err := h.vulnIntelImport(c.Request.Context(), body.Path, body.Format)
	payload := gin.H{"summary": sum}
	if err != nil {
		payload["error"] = err.Error()
		c.JSON(http.StatusBadRequest, payload)
		return
	}
	c.JSON(http.StatusOK, payload)
}
