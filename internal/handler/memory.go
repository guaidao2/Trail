package handler

import (
	"net/http"
	"strconv"
	"strings"

	"trail/internal/database"
	"trail/internal/security"

	"github.com/gin-gonic/gin"
)

// 记忆管理接口：Agent 自己也会用 memory_* 工具读写同一份数据，
// 这里的 REST 只是给人在界面上查看 / 修正 / 删除。

// ListMemories 列出记忆（默认排除过期短期记忆）。
func (h *HostHandler) ListMemories(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("page_size", "100"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	includeExpired := c.Query("include_expired") == "1" || c.Query("include_expired") == "true"
	if limit <= 0 {
		limit = 100
	}
	ownerID := ""
	if session, ok := security.CurrentSession(c); ok {
		ownerID = session.UserID
	}
	items, total, err := h.db.ListMemories(database.MemoryFilter{
		Tier:           c.Query("tier"),
		Scope:          c.Query("scope"),
		HostID:         c.Query("host_id"),
		Query:          c.Query("keyword"),
		OwnerID:        ownerID,
		IncludeExpired: includeExpired,
	}, limit, (page-1)*limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取记忆失败"})
		return
	}
	ownerForCount := ""
	if session, ok := security.CurrentSession(c); ok {
		ownerForCount = session.UserID
	}
	counts, _ := h.db.CountMemoriesByTier(ownerForCount)
	c.JSON(http.StatusOK, gin.H{
		"items": items, "total": total, "page": page, "page_size": limit, "by_tier": counts,
	})
}

// UpsertMemory 新增或更新一条记忆（同一个键覆盖内容）。
func (h *HostHandler) UpsertMemory(c *gin.Context) {
	var body struct {
		Tier    string `json:"tier"`
		Scope   string `json:"scope"`
		HostID  string `json:"host_id"`
		Key     string `json:"key"`
		Content string `json:"content"`
		Tags    string `json:"tags"`
		TTLDays int    `json:"ttl_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误"})
		return
	}
	ownerID := ""
	if session, ok := security.CurrentSession(c); ok {
		ownerID = session.UserID
	}
	// owner_user_id 参与唯一键：只有 user 作用域才写。
	if strings.ToLower(strings.TrimSpace(body.Scope)) != database.MemoryScopeUser {
		ownerID = ""
	}
	rec, created, err := h.db.UpsertMemory(database.MemoryUpsert{
		Tier: body.Tier, Scope: body.Scope, HostID: body.HostID, OwnerID: ownerID,
		Key: body.Key, Content: body.Content, Tags: body.Tags, Source: "ui", TTLDays: body.TTLDays,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"created": created, "memory": rec})
}

// DeleteMemory 删除一条记忆。
func (h *HostHandler) DeleteMemory(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if rec, err := h.db.GetMemory(id); err == nil && rec != nil &&
		rec.Scope == database.MemoryScopeUser && rec.OwnerID != "" {
		if session, ok := security.CurrentSession(c); !ok || session.UserID != rec.OwnerID {
			c.JSON(http.StatusForbidden, gin.H{"error": "不能删除其他用户的记忆"})
			return
		}
	}
	if err := h.db.DeleteMemory(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
