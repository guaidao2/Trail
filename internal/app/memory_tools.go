package app

import (
	"context"
	"encoding/json"
	"strings"

	"trail/internal/database"
	"trail/internal/mcp"
	"trail/internal/mcp/builtin"

	"go.uber.org/zap"
)

// registerMemoryTools 注册 Agent 记忆工具（关键 / 长期 / 短期三级）。
//
// 设计取舍：
//   - 记忆是 Agent 自己的运营经验，所以允许它自己写、自己改、自己删；
//   - 但"关键记忆"代表硬约束（例如生产库禁止重启），写入与删除都要 memory:write；
//   - 查询命中会回写 hit_count / last_used_at，方便人和 Agent 判断"这条还有没有用"。
func registerMemoryTools(server *mcp.Server, db *database.DB, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolMemorySave,
		ShortDescription: "记住一条运维经验",
		Description:      "把值得长期保留的信息写入记忆。等级：critical（关键，永不自动过期，只存硬约束如“生产库禁止重启”）、long_term（长期，默认，存网络分段/命名习惯/环境约定）、short_term（短期，默认 30 天过期，存本周排查上下文）。同一个键重复写入会更新内容而不是新增。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key":      map[string]interface{}{"type": "string", "description": "简短唯一的键，如 prod-db-no-restart"},
				"content":  map[string]interface{}{"type": "string", "description": "记忆内容：结论与依据，写清楚适用范围"},
				"tier":     map[string]interface{}{"type": "string", "description": "critical / long_term（默认）/ short_term"},
				"scope":    map[string]interface{}{"type": "string", "description": "global（默认）/ host（需 host_id）/ user"},
				"host_id":  map[string]interface{}{"type": "string", "description": "scope=host 时的主机 ID"},
				"tags":     map[string]interface{}{"type": "string", "description": "逗号分隔标签，如 数据库,变更禁忌"},
				"ttl_days": map[string]interface{}{"type": "integer", "description": "仅 short_term 生效，默认 30 天"},
			},
			"required": []string{"key", "content"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "memory:write")
		if !ok {
			return textResult("缺少 memory:write 权限", true), nil
		}
		scope := strings.ToLower(strings.TrimSpace(strArg(args, "scope")))
		if scope == "" {
			scope = database.MemoryScopeGlobal
		}
		// owner_user_id 参与唯一键：只有 user 作用域才写，否则全局/主机记忆会按人重复。
		ownerID := ""
		if scope == database.MemoryScopeUser {
			ownerID = strings.TrimSpace(access.UserID)
		}
		rec, created, err := db.UpsertMemory(database.MemoryUpsert{
			Tier:    strArg(args, "tier"),
			Scope:   scope,
			HostID:  strArg(args, "host_id"),
			OwnerID: ownerID,
			Key:     strArg(args, "key"),
			Content: strArg(args, "content"),
			Tags:    strArg(args, "tags"),
			Source:  "agent",
			TTLDays: intArg(args, "ttl_days", 30),
		})
		if err != nil {
			return textResult("写入记忆失败: "+err.Error(), true), nil
		}
		logger.Info("Agent 写入记忆", zap.String("tier", rec.Tier), zap.String("key", rec.Key), zap.Bool("created", created))
		b, _ := json.MarshalIndent(map[string]interface{}{"created": created, "memory": rec}, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolMemorySearch,
		ShortDescription: "检索运维记忆",
		Description:      "按关键字检索记忆（键、内容、标签模糊匹配），默认排除已过期的短期记忆。返回命中条目并累加使用次数；关键记忆优先。做变更、排查、写报告前先查一次，避免重复踩坑。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query":    map[string]interface{}{"type": "string", "description": "关键字，如 数据库 重启 nginx"},
				"tier":     map[string]interface{}{"type": "string", "description": "只查某一级：critical / long_term / short_term"},
				"host_id":  map[string]interface{}{"type": "string", "description": "只看这台主机相关（含全局记忆）"},
				"limit":    map[string]interface{}{"type": "integer", "description": "返回条数，默认 20，最大 100"},
			},
			"required": []string{"query"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "memory:read")
		if !ok {
			return textResult("缺少 memory:read 权限", true), nil
		}
		limit := intArg(args, "limit", 20)
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		items, total, err := db.ListMemories(database.MemoryFilter{
			Tier:   strArg(args, "tier"),
			HostID: strArg(args, "host_id"),
			Query:   strArg(args, "query"),
			OwnerID: strings.TrimSpace(access.UserID),
		}, limit, 0)
		if err != nil {
			return textResult("检索记忆失败: "+err.Error(), true), nil
		}
		ids := make([]string, 0, len(items))
		for _, m := range items {
			ids = append(ids, m.ID)
		}
		if err := db.TouchMemory(ids); err != nil {
			logger.Warn("更新记忆命中失败", zap.Error(err))
		}
		b, _ := json.MarshalIndent(map[string]interface{}{"total": total, "items": items}, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolMemoryList,
		ShortDescription: "列出运维记忆",
		Description:      "列出记忆条目（可按等级、作用域、主机过滤），同时返回各级数量。用于定期回顾，清理过时或没用的记忆。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tier":     map[string]interface{}{"type": "string", "description": "critical / long_term / short_term"},
				"scope":    map[string]interface{}{"type": "string", "description": "global / host / user"},
				"host_id":  map[string]interface{}{"type": "string", "description": "按主机过滤（含全局记忆）"},
				"limit":    map[string]interface{}{"type": "integer", "description": "返回条数，默认 100，最大 500"},
				"include_expired": map[string]interface{}{"type": "boolean", "description": "是否包含已过期的短期记忆，默认 false"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "memory:read")
		if !ok {
			return textResult("缺少 memory:read 权限", true), nil
		}
		items, total, err := db.ListMemories(database.MemoryFilter{
			Tier:           strArg(args, "tier"),
			Scope:          strArg(args, "scope"),
			HostID:         strArg(args, "host_id"),
			OwnerID:        strings.TrimSpace(access.UserID),
			IncludeExpired: boolArg(args, "include_expired"),
		}, intArg(args, "limit", 100), 0)
		if err != nil {
			return textResult("列出记忆失败: "+err.Error(), true), nil
		}
		counts, _ := db.CountMemoriesByTier(strings.TrimSpace(access.UserID))
		b, _ := json.MarshalIndent(map[string]interface{}{"total": total, "items": items, "by_tier": counts}, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolMemoryForget,
		ShortDescription: "忘掉一条记忆",
		Description:      "删除没用的记忆：按 id 删除，或用 key 精确删除。关键记忆也可以用这个删，但需要明确指定 key，避免误删硬约束。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":      map[string]interface{}{"type": "string", "description": "记忆 ID"},
				"key":     map[string]interface{}{"type": "string", "description": "记忆键（与 id 二选一）"},
				"tier":    map[string]interface{}{"type": "string", "description": "配合 key 使用，默认 long_term"},
				"scope":   map[string]interface{}{"type": "string", "description": "配合 key 使用，默认 global"},
				"host_id": map[string]interface{}{"type": "string", "description": "scope=host 时的主机 ID"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "memory:write")
		if !ok {
			return textResult("缺少 memory:write 权限", true), nil
		}
		id := strings.TrimSpace(strArg(args, "id"))
		if id == "" {
			key := strings.TrimSpace(strArg(args, "key"))
			if key == "" {
				return textResult("id 与 key 至少给一个", true), nil
			}
			tier := strings.ToLower(strings.TrimSpace(strArg(args, "tier")))
			if tier == "" {
				tier = database.MemoryTierLongTerm
			}
			scope := strings.ToLower(strings.TrimSpace(strArg(args, "scope")))
			if scope == "" {
				scope = database.MemoryScopeGlobal
			}
			items, _, err := db.ListMemories(database.MemoryFilter{
				Tier: tier, Scope: scope, HostID: strArg(args, "host_id"),
				OwnerID: strings.TrimSpace(access.UserID), IncludeExpired: true,
			}, 500, 0)
			if err != nil {
				return textResult("查找记忆失败: "+err.Error(), true), nil
			}
			for _, m := range items {
				if m.Key == key {
					id = m.ID
					break
				}
			}
			if id == "" {
				return textResult("没有找到这条记忆: "+key, true), nil
			}
		}
		rec, _ := db.GetMemory(id)
		// user 作用域的记忆属于个人：别人的不许删，避免 memory:write 越权。
		if rec != nil && rec.Scope == database.MemoryScopeUser && rec.OwnerID != "" &&
			rec.OwnerID != strings.TrimSpace(access.UserID) {
			return textResult("不能删除其他用户的记忆", true), nil
		}
		if err := db.DeleteMemory(id); err != nil {
			return textResult("删除记忆失败: "+err.Error(), true), nil
		}
		logger.Info("Agent 删除记忆", zap.String("id", id))
		payload := map[string]interface{}{"deleted": true, "id": id}
		if rec != nil {
			payload["key"] = rec.Key
			payload["tier"] = rec.Tier
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})
}
