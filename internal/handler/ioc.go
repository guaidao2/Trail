package handler

import (
	"net/http"
	"strconv"
	"strings"

	"trail/internal/database"
	"trail/internal/security"

	"github.com/gin-gonic/gin"
)

// IOC 情报库的 REST 接口。
//
// 情报库是全局知识（不按主机划分），所以这里不做主机归属校验：
// 可见性由 ioc:read / ioc:write 两个权限点控制，路由层已经拦过。
// 封禁/解封需要真的在主机上执行命令，仍走 Agent 的 ioc_block / ioc_unblock，
// 这里只负责情报本身的增删改查与状态流转。
func (h *HostHandler) ListIOC(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	items, total, err := h.db.ListIOCs(database.IOCFilter{
		Keyword: c.Query("keyword"),
		Type:    c.Query("type"),
		Status:  c.Query("status"),
		HostID:  c.Query("host_id"),
	}, limit, (page-1)*max(limit, 1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取 IOC 失败"})
		return
	}
	counts, _ := h.db.CountIOCByStatus()
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "page_size": limit, "by_status": counts})
}

// GetIOC 返回一条情报及其命中过的主机。
func (h *HostHandler) GetIOC(c *gin.Context) {
	rec, err := h.db.GetIOC(strings.TrimSpace(c.Param("id")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取 IOC 失败"})
		return
	}
	if rec == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IOC 不存在"})
		return
	}
	hosts, err := h.db.ListIOCHits(rec.ID, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取关联主机失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ioc": rec, "hosts": hosts})
}

// UpsertIOC 新增或更新一条情报（按类型 + 归一值去重）。
func (h *HostHandler) UpsertIOC(c *gin.Context) {
	var body struct {
		Type       string `json:"type"`
		Value      string `json:"value"`
		Status     string `json:"status"`
		Confidence int    `json:"confidence"`
		Severity   string `json:"severity"`
		Source     string `json:"source"`
		Tags       string `json:"tags"`
		Note       string `json:"note"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	ownerID := ""
	if session, ok := security.CurrentSession(c); ok {
		ownerID = session.UserID
	}
	rec, created, err := h.db.UpsertIOC(database.IOCUpsert{
		Type:       body.Type,
		Value:      body.Value,
		Status:     body.Status,
		Confidence: body.Confidence,
		Severity:   body.Severity,
		Source:     body.Source,
		Tags:       body.Tags,
		Note:       body.Note,
		ExpiresAt:  body.ExpiresAt,
		OwnerID:    ownerID,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"created": created, "ioc": rec})
}

// UpdateIOCStatus 流转情报状态。
func (h *HostHandler) UpdateIOCStatus(c *gin.Context) {
	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := h.db.SetIOCStatus(strings.TrimSpace(c.Param("id")), body.Status); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rec, _ := h.db.GetIOC(strings.TrimSpace(c.Param("id")))
	c.JSON(http.StatusOK, gin.H{"ok": true, "ioc": rec})
}

// DeleteIOC 删除情报及其命中记录。
func (h *HostHandler) DeleteIOC(c *gin.Context) {
	if err := h.db.DeleteIOC(strings.TrimSpace(c.Param("id"))); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
