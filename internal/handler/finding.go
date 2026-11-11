package handler

import (
	"net/http"
	"strconv"
	"strings"

	"trail/internal/database"

	"github.com/gin-gonic/gin"
)

// ListFindings 返回一台主机的检测发现（日志命中 + 基线不符合项）。
//
// 只读接口：按 host:read 授权，和主机详情同一套可见性。
func (h *HostHandler) ListFindings(c *gin.Context) {
	hostID := strings.TrimSpace(c.Param("id"))
	if hostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "主机 ID 不能为空"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("page_size", "100"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	if !hostAccessAllowed(h.db, hostAccess(c, "host:read"), hostID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该主机"})
		return
	}
	list, total, err := h.db.ListFindings(database.FindingFilter{
		HostID:   hostID,
		Source:   c.Query("source"),
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
		Keyword:  c.Query("keyword"),
	}, limit, (page-1)*max(limit, 1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取检测发现失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": list, "total": total, "page": page, "page_size": limit})
}

// FindingSummary 返回主机维度的严重度分布，供主机列表与详情页显示。
func (h *HostHandler) FindingSummary(c *gin.Context) {
	hostID := strings.TrimSpace(c.Param("id"))
	if hostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "主机 ID 不能为空"})
		return
	}
	if !hostAccessAllowed(h.db, hostAccess(c, "host:read"), hostID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该主机"})
		return
	}
	bySeverity, total, lastSeen, err := h.db.HostFindingSummary(hostID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "统计检测发现失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"host_id":     hostID,
		"by_severity": bySeverity,
		"total":       total,
		"last_seen":   lastSeen,
	})
}

// UpdateFindingStatus 流转发现状态（确认/解决/误报）。
func (h *HostHandler) UpdateFindingStatus(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "发现 ID 不能为空"})
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := h.db.SetFindingStatus(id, body.Status); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rec, err := h.db.GetFinding(id)
	if err != nil || rec == nil {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "finding": rec})
}
