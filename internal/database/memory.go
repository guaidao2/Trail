package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Agent 记忆的三级分类。
//
//   - critical（关键）：永不自动过期，只能显式删除；用于"生产库禁止重启"这类硬约束
//   - long_term（长期）：永久保存，但 Agent 判定过时后可改可删；用于网络分段、命名习惯
//   - short_term（短期）：默认 30 天过期，可续期；用于"本周在排查某告警"这类临时上下文
const (
	MemoryTierCritical  = "critical"
	MemoryTierLongTerm  = "long_term"
	MemoryTierShortTerm = "short_term"
)

const (
	MemoryScopeGlobal = "global"
	MemoryScopeHost   = "host"
	MemoryScopeUser   = "user"
)

// AgentMemory 是一条 Agent 记忆。
type AgentMemory struct {
	ID        string    `json:"id"`
	Tier      string    `json:"tier"`
	Scope     string    `json:"scope"`
	HostID    string    `json:"host_id,omitempty"`
	OwnerID   string    `json:"owner_user_id,omitempty"`
	Key       string    `json:"key"`
	Content   string    `json:"content"`
	Tags      string    `json:"tags,omitempty"`
	Source    string    `json:"source,omitempty"`
	HitCount  int       `json:"hit_count"`
	LastUsed  string    `json:"last_used_at,omitempty"`
	ExpiresAt string    `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MemoryUpsert 是写入一条记忆的入参。
type MemoryUpsert struct {
	Tier    string
	Scope   string
	HostID  string
	OwnerID string
	Key     string
	Content string
	Tags    string
	Source  string
	TTLDays int // 仅 short_term 生效；<=0 时默认 30 天
}

// MemoryFilter 是查询条件。
type MemoryFilter struct {
	Tier    string
	Scope   string
	HostID  string
	Query   string
	OwnerID string // 非空时：user 作用域只返回该用户的记忆
	IncludeExpired bool
}

var memoryTierOrder = map[string]int{
	MemoryTierCritical:  1,
	MemoryTierLongTerm:  2,
	MemoryTierShortTerm: 3,
}

// MemoryTierLabel 返回 tier 的展示名（中文），供日志与提示词使用。
func MemoryTierLabel(tier string) string {
	switch tier {
	case MemoryTierCritical:
		return "关键记忆"
	case MemoryTierLongTerm:
		return "长期记忆"
	case MemoryTierShortTerm:
		return "短期记忆"
	}
	return tier
}

func validMemoryTier(t string) bool { _, ok := memoryTierOrder[t]; return ok }

func validMemoryScope(s string) bool {
	return s == MemoryScopeGlobal || s == MemoryScopeHost || s == MemoryScopeUser
}

// UpsertMemory 写入或更新一条记忆（按 tier + scope + key + host/owner 去重）。
//
// 永久性规则在这里落地，而不是靠调用方自觉：
// critical / long_term 一律写 expires_at = NULL；short_term 才写过期时间。
func (db *DB) UpsertMemory(in MemoryUpsert) (*AgentMemory, bool, error) {
	tier := strings.ToLower(strings.TrimSpace(in.Tier))
	if tier == "" {
		tier = MemoryTierLongTerm
	}
	if !validMemoryTier(tier) {
		return nil, false, fmt.Errorf("不支持的记忆等级: %s（可选 critical / long_term / short_term）", tier)
	}
	scope := strings.ToLower(strings.TrimSpace(in.Scope))
	if scope == "" {
		scope = MemoryScopeGlobal
	}
	if !validMemoryScope(scope) {
		return nil, false, fmt.Errorf("不支持的作用域: %s（可选 global / host / user）", scope)
	}
	key := strings.TrimSpace(in.Key)
	if key == "" {
		return nil, false, fmt.Errorf("记忆键不能为空")
	}
	if len(key) > 128 {
		return nil, false, fmt.Errorf("记忆键过长（最多 128 字符）")
	}
	content := strings.TrimSpace(in.Content)
	if content == "" {
		return nil, false, fmt.Errorf("记忆内容不能为空")
	}
	if runes := []rune(content); len(runes) > 2000 {
		content = string(runes[:2000])
	}
	hostID := strings.TrimSpace(in.HostID)
	ownerID := strings.TrimSpace(in.OwnerID)
	switch scope {
	case MemoryScopeHost:
		if hostID == "" {
			return nil, false, fmt.Errorf("作用域为 host 时必须提供 host_id")
		}
	case MemoryScopeUser:
		if ownerID == "" {
			return nil, false, fmt.Errorf("作用域为 user 时必须提供用户 ID")
		}
	}

	now := time.Now()
	var expires interface{}
	if tier == MemoryTierShortTerm {
		days := in.TTLDays
		if days <= 0 {
			days = 30
		}
		if days > 3650 {
			days = 3650
		}
		expires = now.AddDate(0, 0, days)
	}

	var existingID string
	err := db.QueryRow(`SELECT id FROM agent_memory
		WHERE tier = ? AND scope = ? AND mem_key = ? AND IFNULL(host_id,'') = ? AND IFNULL(owner_user_id,'') = ?`,
		tier, scope, key, hostID, ownerID).Scan(&existingID)
	switch {
	case err == nil:
		_, err = db.Exec(`UPDATE agent_memory SET content = ?,
			tags = CASE WHEN ? <> '' THEN ? ELSE tags END,
			source = CASE WHEN ? <> '' THEN ? ELSE source END,
			expires_at = ?, updated_at = ?
			WHERE id = ?`,
			content,
			strings.TrimSpace(in.Tags), strings.TrimSpace(in.Tags),
			strings.TrimSpace(in.Source), strings.TrimSpace(in.Source),
			expires, now, existingID)
		if err != nil {
			return nil, false, fmt.Errorf("更新记忆失败: %w", err)
		}
		rec, err := db.GetMemory(existingID)
		return rec, false, err
	case err != sql.ErrNoRows:
		return nil, false, fmt.Errorf("查询记忆失败: %w", err)
	}

	id := "mem_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	_, err = db.Exec(`INSERT INTO agent_memory
		(id, tier, scope, host_id, owner_user_id, mem_key, content, tags, source,
		 hit_count, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		id, tier, scope, nullableHostString(hostID), nullableHostString(ownerID),
		key, content, strings.TrimSpace(in.Tags), strings.TrimSpace(in.Source),
		expires, now, now)
	if err != nil {
		return nil, false, fmt.Errorf("创建记忆失败: %w", err)
	}
	rec, err := db.GetMemory(id)
	return rec, true, err
}

const memorySelectColumns = `id, tier, scope, host_id, owner_user_id, mem_key, content, tags, source,
	hit_count, last_used_at, expires_at, created_at, updated_at`

// GetMemory 按 ID 读取。
func (db *DB) GetMemory(id string) (*AgentMemory, error) {
	row := db.QueryRow(`SELECT `+memorySelectColumns+` FROM agent_memory WHERE id = ?`, strings.TrimSpace(id))
	rec, err := scanMemory(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询记忆失败: %w", err)
	}
	return rec, nil
}

// ListMemories 按条件列出记忆；默认排除已过期的短期记忆。
func (db *DB) ListMemories(filter MemoryFilter, limit, offset int) ([]*AgentMemory, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where := []string{"1=1"}
	args := []interface{}{}
	if v := strings.ToLower(strings.TrimSpace(filter.Tier)); v != "" {
		where = append(where, "tier = ?")
		args = append(args, v)
	}
	if v := strings.ToLower(strings.TrimSpace(filter.Scope)); v != "" {
		where = append(where, "scope = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.HostID); v != "" {
		where = append(where, "(host_id = ? OR scope = 'global')")
		args = append(args, v)
	}
	if kw := strings.TrimSpace(filter.Query); kw != "" {
		where = append(where, "(mem_key LIKE ? OR content LIKE ? OR tags LIKE ?)")
		like := "%" + escapeVulnerabilityLikePattern(kw) + "%"
		args = append(args, like, like, like)
	}
	if owner := strings.TrimSpace(filter.OwnerID); owner != "" {
		// user 作用域只对本人可见；global / host 不受影响。
		where = append(where, "(scope <> 'user' OR IFNULL(owner_user_id,'') = ?)")
		args = append(args, owner)
	}
	if !filter.IncludeExpired {
		where = append(where, "(expires_at IS NULL OR expires_at > ?)")
		args = append(args, time.Now())
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM agent_memory WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计记忆失败: %w", err)
	}
	rows, err := db.Query(`SELECT `+memorySelectColumns+` FROM agent_memory WHERE `+cond+
		` ORDER BY CASE tier WHEN 'critical' THEN 1 WHEN 'long_term' THEN 2 ELSE 3 END, updated_at DESC
		 LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询记忆失败: %w", err)
	}
	defer rows.Close()
	out := []*AgentMemory{}
	for rows.Next() {
		rec, err := scanMemoryRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rec)
	}
	return out, total, nil
}

// DeleteMemory 删除一条记忆（Agent 与用户都可以删"没用的记忆"）。
func (db *DB) DeleteMemory(id string) error {
	res, err := db.Exec(`DELETE FROM agent_memory WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("删除记忆失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("记忆不存在: %s", id)
	}
	return nil
}

// TouchMemory 记录一次命中（用于判断"这条记忆是否还有用"）。
func (db *DB) TouchMemory(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now()
	for _, id := range ids {
		if _, err := db.Exec(`UPDATE agent_memory SET hit_count = hit_count + 1, last_used_at = ? WHERE id = ?`,
			now, strings.TrimSpace(id)); err != nil {
			return fmt.Errorf("更新记忆命中失败: %w", err)
		}
	}
	return nil
}

// PruneExpiredMemories 清理已过期的短期记忆（关键/长期永不参与）。
func (db *DB) PruneExpiredMemories(now time.Time) (int, error) {
	res, err := db.Exec(`DELETE FROM agent_memory WHERE tier = ? AND expires_at IS NOT NULL AND expires_at <= ?`,
		MemoryTierShortTerm, now)
	if err != nil {
		return 0, fmt.Errorf("清理过期记忆失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// CountMemoriesByTier 返回各级记忆数量（概览用）。
// ownerID 非空时，user 作用域只统计该用户自己的记忆，与列表口径保持一致。
func (db *DB) CountMemoriesByTier(ownerID string) (map[string]int, error) {
	query := `SELECT tier, COUNT(*) FROM agent_memory
		WHERE (expires_at IS NULL OR expires_at > ?)`
	args := []interface{}{time.Now()}
	if owner := strings.TrimSpace(ownerID); owner != "" {
		query += ` AND (scope <> 'user' OR IFNULL(owner_user_id,'') = ?)`
		args = append(args, owner)
	}
	query += ` GROUP BY tier`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("统计记忆失败: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, nil
}

func scanMemory(row *sql.Row) (*AgentMemory, error) {
	rec := &AgentMemory{}
	var host, owner, lastUsed, expires sql.NullString
	var created, updated time.Time
	err := row.Scan(&rec.ID, &rec.Tier, &rec.Scope, &host, &owner, &rec.Key, &rec.Content,
		&rec.Tags, &rec.Source, &rec.HitCount, &lastUsed, &expires, &created, &updated)
	if err != nil {
		return nil, err
	}
	if host.Valid {
		rec.HostID = host.String
	}
	if owner.Valid {
		rec.OwnerID = owner.String
	}
	if lastUsed.Valid {
		rec.LastUsed = lastUsed.String
	}
	if expires.Valid {
		rec.ExpiresAt = expires.String
	}
	rec.CreatedAt = created
	rec.UpdatedAt = updated
	return rec, nil
}

func scanMemoryRows(rows *sql.Rows) (*AgentMemory, error) {
	rec := &AgentMemory{}
	var host, owner, lastUsed, expires sql.NullString
	var created, updated time.Time
	if err := rows.Scan(&rec.ID, &rec.Tier, &rec.Scope, &host, &owner, &rec.Key, &rec.Content,
		&rec.Tags, &rec.Source, &rec.HitCount, &lastUsed, &expires, &created, &updated); err != nil {
		return nil, fmt.Errorf("扫描记忆失败: %w", err)
	}
	if host.Valid {
		rec.HostID = host.String
	}
	if owner.Valid {
		rec.OwnerID = owner.String
	}
	if lastUsed.Valid {
		rec.LastUsed = lastUsed.String
	}
	if expires.Valid {
		rec.ExpiresAt = expires.String
	}
	rec.CreatedAt = created
	rec.UpdatedAt = updated
	return rec, nil
}
