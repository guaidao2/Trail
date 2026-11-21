package handler

import (
	"net/http"
	"strconv"

	"trail/internal/security"

	"github.com/gin-gonic/gin"
)

// WallGraph 返回攻防态势大屏的聚合数据。
//
// 只读展示口：按 host:read 的作用域过滤——看不到的主机不会出现在图里，
// 依赖它的 IOC 边也会被丢弃。
func (h *HostHandler) WallGraph(c *gin.Context) {
	events, _ := strconv.Atoi(c.DefaultQuery("events", "30"))
	// IOC 明细属于 ioc:read 的范围：只有 host:read 的角色看不到 IOC 节点、边与统计。
	includeIOC := security.SessionHasPermission(c, "ioc:read")
	graph, err := h.db.WallGraph(hostAccess(c, "host:read"), events, includeIOC)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取态势数据失败"})
		return
	}
	c.JSON(http.StatusOK, graph)
}
