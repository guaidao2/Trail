package database

import (
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// IOC 状态机：观察 → 确认 → 已封禁；误判走 false_positive。
//
// 为什么要四态而不是一个"是否恶意"布尔：
// 日志里出现一个 IP 不等于它恶意（可能是扫描器顺带、CDN 回源、自家监控），
// 所以命中只算"观察"；只有人工确认或强证据才能升"确认"；只有"确认"的条目
// 才允许被检测引擎当作匹配源、才允许下发封禁。
const (
	IOCStatusObserved      = "observed"
	IOCStatusConfirmed     = "confirmed"
	IOCStatusBlocked       = "blocked"
	IOCStatusFalsePositive = "false_positive"
)

// IOC 是情报库里的一条攻击者档案。
type IOC struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Normalized string    `json:"normalized"`
	Status     string    `json:"status"`
	Confidence int       `json:"confidence"`
	Severity   string    `json:"severity"`
	Source     string    `json:"source"`
	Tags       string    `json:"tags,omitempty"`
	Note       string    `json:"note,omitempty"`
	FirstSeen  string    `json:"first_seen"`
	LastSeen   string    `json:"last_seen"`
	HitCount   int       `json:"hit_count"`
	ExpiresAt  string    `json:"expires_at,omitempty"`
	OwnerID    string    `json:"owner_user_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	HostCount  int       `json:"host_count"` // 关联主机数，列表查询时填充
}

// IOCHit 是"某个 IOC 命中过某台主机"的记录，也是封禁/解封的留痕处。
type IOCHit struct {
	ID             string    `json:"id"`
	IOCID          string    `json:"ioc_id"`
	HostID         string    `json:"host_id"`
	Source         string    `json:"source"`
	RuleID         string    `json:"rule_id,omitempty"`
	Evidence       string    `json:"evidence,omitempty"`
	FirstSeen      string    `json:"first_seen"`
	LastSeen       string    `json:"last_seen"`
	HitCount       int       `json:"hit_count"`
	BlockedAt      string    `json:"blocked_at,omitempty"`
	BlockCommand   string    `json:"block_command,omitempty"`
	UnblockCommand string    `json:"unblock_command,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// IOCUpsert 是写入/更新一条 IOC 的入参。
type IOCUpsert struct {
	Type       string
	Value      string
	Status     string
	Confidence int
	Severity   string
	Source     string
	Tags       string
	Note       string
	ExpiresAt  string // RFC3339 或 "2006-01-02 15:04:05"；空表示不过期
	OwnerID    string
}

// IOCFilter 是列表筛选条件。
type IOCFilter struct {
	Keyword  string
	Type     string
	Status   string
	HostID   string // 只看命中过某台主机的
}

var iocValidTypes = map[string]bool{
	"ip": true, "domain": true, "url": true,
	"md5": true, "sha1": true, "sha256": true,
	"email": true, "filename": true,
}

// NormalizeIOCValue 把同一个指标的不同写法归一，作为去重键。
//
// 归一规则刻意保守：只做"确定等价"的变换（大小写、尾点、IP 记法），
// 不做会改变语义的清洗（比如 URL 去掉 query 会把两个真实不同的地址并成一个）。
func NormalizeIOCValue(iocType, value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch iocType {
	case "ip":
		if canon := normalizeIPValue(v); canon != "" {
			return canon
		}
	case "domain":
		v = strings.TrimPrefix(v, "*.")
		v = strings.TrimSuffix(v, ".")
		v = strings.TrimSuffix(v, "/")
	case "url":
		if i := strings.Index(v, "#"); i >= 0 {
			v = v[:i]
		}
	}
	return v
}

func validIOCType(t string) bool { return iocValidTypes[t] }

// iocStatusRank 给状态排序，用来实现"只升不降"。
var iocStatusRank = map[string]int{
	IOCStatusObserved: 1,
	IOCStatusConfirmed: 2,
	IOCStatusBlocked:   3,
}

// mergeIOCStatus 合并新旧状态：误报优先（人工判断不可被自动流程覆盖），
// 其余只允许沿 observed → confirmed → blocked 上升。
func mergeIOCStatus(current, incoming string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	incoming = strings.ToLower(strings.TrimSpace(incoming))
	if current == IOCStatusFalsePositive {
		return current
	}
	if incoming == IOCStatusFalsePositive {
		return IOCStatusFalsePositive
	}
	if iocStatusRank[incoming] > iocStatusRank[current] {
		return incoming
	}
	return current
}

// GetIOCByValue 按类型 + 归一值精确查询（唯一索引命中，避免子串误匹配）。
func (db *DB) GetIOCByValue(iocType, value string) (*IOC, error) {
	t := strings.ToLower(strings.TrimSpace(iocType))
	if t == "" {
		t = "ip"
	}
	normalized := NormalizeIOCValue(t, value)
	if normalized == "" {
		return nil, nil
	}
	row := db.QueryRow(`SELECT `+iocSelectColumns+` FROM ioc WHERE ioc_type = ? AND normalized = ?`, t, normalized)
	rec, err := scanIOC(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询 IOC 失败: %w", err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM ioc_host_hit WHERE ioc_id = ?`, rec.ID).Scan(&n)
	rec.HostCount = n
	return rec, nil
}

// CountIOCHostBlocked 返回这条 IOC 还有多少台主机处于封禁状态。
func (db *DB) CountIOCHostBlocked(iocID string) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM ioc_host_hit WHERE ioc_id = ? AND blocked_at IS NOT NULL`, strings.TrimSpace(iocID)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("统计封禁主机失败: %w", err)
	}
	return n, nil
}

// normalizeIPValue 把 IP 的各种等价写法归一成点分十进制。
//
// 为什么要自己处理而不是只用 net.ParseIP：后者接受 1.2.3.4、拒绝 1.2.3.004，
// 但攻击者恰恰会用前导零、十进制整数、十六进制/八进制段来让同一个地址在
// 名单匹配时"看起来是另一个值"。这里按 inet_aton 的语义归一（a / a.b / a.b.c /
// a.b.c.d，每段支持十进制、0x 十六进制、0 开头八进制），归一不了就返回空串。
func normalizeIPValue(v string) string {
	if ip := net.ParseIP(v); ip != nil {
		return ip.String()
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return ""
	}
	vals := make([]uint64, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return ""
		}
		var n uint64
		var err error
		switch {
		case strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X"):
			n, err = strconv.ParseUint(part[2:], 16, 32)
		case len(part) > 1 && strings.HasPrefix(part, "0"):
			n, err = strconv.ParseUint(part[1:], 8, 32)
		default:
			n, err = strconv.ParseUint(part, 10, 32)
		}
		if err != nil {
			return ""
		}
		vals = append(vals, n)
	}
	var addr uint64
	switch len(vals) {
	case 1:
		addr = vals[0]
	case 2:
		addr = vals[0]<<24 | vals[1]
	case 3:
		addr = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4:
		addr = vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3]
	}
	if addr > 0xFFFFFFFF {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", addr>>24&0xFF, addr>>16&0xFF, addr>>8&0xFF, addr&0xFF)
}

// UpsertIOC 写入或更新一条 IOC（按 type + normalized 去重）。
// 返回记录本身与是否为新建。
func (db *DB) UpsertIOC(in IOCUpsert) (*IOC, bool, error) {
	iocType := strings.ToLower(strings.TrimSpace(in.Type))
	if iocType == "" {
		iocType = "ip"
	}
	if !validIOCType(iocType) {
		return nil, false, fmt.Errorf("不支持的 IOC 类型: %s", iocType)
	}
	value := strings.TrimSpace(in.Value)
	if value == "" {
		return nil, false, fmt.Errorf("IOC 值不能为空")
	}
	normalized := NormalizeIOCValue(iocType, value)
	if normalized == "" {
		return nil, false, fmt.Errorf("IOC 值归一后为空: %q", value)
	}

	status := strings.ToLower(strings.TrimSpace(in.Status))
	if status == "" {
		status = IOCStatusObserved
	}
	switch status {
	case IOCStatusObserved, IOCStatusConfirmed, IOCStatusBlocked, IOCStatusFalsePositive:
	default:
		return nil, false, fmt.Errorf("不支持的 IOC 状态: %s", status)
	}
	confidence := in.Confidence
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	if confidence == 0 {
		confidence = 50
	}
	severity := strings.ToLower(strings.TrimSpace(in.Severity))
	if severity == "" {
		severity = "medium"
	}
	now := time.Now()

	var existingID, currentStatus string
	err := db.QueryRow(`SELECT id, status FROM ioc WHERE ioc_type = ? AND normalized = ?`, iocType, normalized).Scan(&existingID, &currentStatus)
	switch {
	case err == nil:
		// 状态只允许"升级"（观察 → 确认 → 已封禁），误报是终态。
		// 否则每次自动扫描都会把人工确认过的条目打回观察态，状态机就失去意义。
		status = mergeIOCStatus(currentStatus, status)
		_, err = db.Exec(`UPDATE ioc SET value = ?, status = ?, confidence = ?, severity = ?,
			tags = CASE WHEN ? <> '' THEN ? ELSE tags END,
			note = CASE WHEN ? <> '' THEN ? ELSE note END,
			expires_at = COALESCE(?, expires_at),
			last_seen = ?, updated_at = ?
			WHERE id = ?`,
			value, status, confidence, severity,
			strings.TrimSpace(in.Tags), strings.TrimSpace(in.Tags),
			strings.TrimSpace(in.Note), strings.TrimSpace(in.Note),
			nullableIOCTime(in.ExpiresAt), now, now, existingID)
		if err != nil {
			return nil, false, fmt.Errorf("更新 IOC 失败: %w", err)
		}
		rec, err := db.GetIOC(existingID)
		return rec, false, err
	case err != sql.ErrNoRows:
		return nil, false, fmt.Errorf("查询 IOC 失败: %w", err)
	}

	id := "ioc_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	_, err = db.Exec(`INSERT INTO ioc (id, ioc_type, value, normalized, status, confidence, severity,
		source, tags, note, first_seen, last_seen, hit_count, expires_at, owner_user_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		id, iocType, value, normalized, status, confidence, severity,
		strings.TrimSpace(in.Source), strings.TrimSpace(in.Tags), strings.TrimSpace(in.Note),
		now, now, nullableIOCTime(in.ExpiresAt), nullableHostString(strings.TrimSpace(in.OwnerID)), now, now)
	if err != nil {
		return nil, false, fmt.Errorf("创建 IOC 失败: %w", err)
	}
	rec, err := db.GetIOC(id)
	return rec, true, err
}

const iocSelectColumns = `id, ioc_type, value, normalized, status, confidence, severity, source,
	tags, note, first_seen, last_seen, hit_count, expires_at, owner_user_id, created_at, updated_at`

// GetIOC 按 ID 读取一条记录。
func (db *DB) GetIOC(id string) (*IOC, error) {
	row := db.QueryRow(`SELECT `+iocSelectColumns+` FROM ioc WHERE id = ?`, strings.TrimSpace(id))
	rec, err := scanIOC(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询 IOC 失败: %w", err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM ioc_host_hit WHERE ioc_id = ?`, rec.ID).Scan(&n)
	rec.HostCount = n
	return rec, nil
}

// ListIOCs 分页列出 IOC。
func (db *DB) ListIOCs(filter IOCFilter, limit, offset int) ([]*IOC, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where := []string{"1=1"}
	args := []interface{}{}
	if kw := strings.TrimSpace(filter.Keyword); kw != "" {
		where = append(where, "(ioc.value LIKE ? OR ioc.note LIKE ? OR ioc.tags LIKE ?)")
		like := "%" + escapeVulnerabilityLikePattern(kw) + "%"
		args = append(args, like, like, like)
	}
	if t := strings.ToLower(strings.TrimSpace(filter.Type)); t != "" {
		where = append(where, "ioc.ioc_type = ?")
		args = append(args, t)
	}
	if s := strings.ToLower(strings.TrimSpace(filter.Status)); s != "" {
		where = append(where, "ioc.status = ?")
		args = append(args, s)
	}
	if h := strings.TrimSpace(filter.HostID); h != "" {
		where = append(where, "EXISTS (SELECT 1 FROM ioc_host_hit h WHERE h.ioc_id = ioc.id AND h.host_id = ?)")
		args = append(args, h)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ioc WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 IOC 失败: %w", err)
	}
	rows, err := db.Query(`SELECT `+iocSelectColumns+`,
		(SELECT COUNT(*) FROM ioc_host_hit h WHERE h.ioc_id = ioc.id)
		FROM ioc WHERE `+cond+` ORDER BY last_seen DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询 IOC 失败: %w", err)
	}
	defer rows.Close()
	out := []*IOC{}
	for rows.Next() {
		rec := &IOC{}
		var expires sql.NullTime
		var owner sql.NullString
		var created, updated time.Time
		if err := rows.Scan(&rec.ID, &rec.Type, &rec.Value, &rec.Normalized, &rec.Status,
			&rec.Confidence, &rec.Severity, &rec.Source, &rec.Tags, &rec.Note,
			&rec.FirstSeen, &rec.LastSeen, &rec.HitCount, &expires, &owner,
			&created, &updated, &rec.HostCount); err != nil {
			return nil, 0, fmt.Errorf("扫描 IOC 失败: %w", err)
		}
		if expires.Valid {
			rec.ExpiresAt = expires.Time.Format("2006-01-02 15:04:05")
		}
		if owner.Valid {
			rec.OwnerID = owner.String
		}
		rec.CreatedAt = created
		rec.UpdatedAt = updated
		out = append(out, rec)
	}
	return out, total, nil
}

// SetIOCStatus 改状态。
func (db *DB) SetIOCStatus(id, status string) error {
	s := strings.ToLower(strings.TrimSpace(status))
	switch s {
	case IOCStatusObserved, IOCStatusConfirmed, IOCStatusBlocked, IOCStatusFalsePositive:
	default:
		return fmt.Errorf("不支持的 IOC 状态: %s", status)
	}
	res, err := db.Exec(`UPDATE ioc SET status = ?, updated_at = ? WHERE id = ?`, s, time.Now(), strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("更新 IOC 状态失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("IOC 不存在: %s", id)
	}
	return nil
}

// DeleteIOC 删除一条 IOC 及其命中记录。
func (db *DB) DeleteIOC(id string) error {
	if _, err := db.Exec(`DELETE FROM ioc_host_hit WHERE ioc_id = ?`, strings.TrimSpace(id)); err != nil {
		return fmt.Errorf("删除 IOC 命中记录失败: %w", err)
	}
	if _, err := db.Exec(`DELETE FROM ioc WHERE id = ?`, strings.TrimSpace(id)); err != nil {
		return fmt.Errorf("删除 IOC 失败: %w", err)
	}
	return nil
}

// RecordIOCHit 记录"某 IOC 命中某主机"；同一对只累加次数，不产生新行。
func (db *DB) RecordIOCHit(iocID, hostID, source, ruleID, evidence string) error {
	iocID = strings.TrimSpace(iocID)
	hostID = strings.TrimSpace(hostID)
	if iocID == "" || hostID == "" {
		return fmt.Errorf("IOC 与主机 ID 均不能为空")
	}
	now := time.Now()
	ev := strings.TrimSpace(evidence)
	if len(ev) > 2000 {
		ev = ev[:2000]
	}
	res, err := db.Exec(`UPDATE ioc_host_hit SET last_seen = ?, hit_count = hit_count + 1,
		source = CASE WHEN ? <> '' THEN ? ELSE source END,
		rule_id = CASE WHEN ? <> '' THEN ? ELSE rule_id END,
		evidence = CASE WHEN ? <> '' THEN ? ELSE evidence END,
		updated_at = ?
		WHERE ioc_id = ? AND host_id = ?`,
		now, strings.TrimSpace(source), strings.TrimSpace(source),
		strings.TrimSpace(ruleID), strings.TrimSpace(ruleID),
		ev, ev, now, iocID, hostID)
	if err != nil {
		return fmt.Errorf("更新 IOC 命中记录失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_, err = db.Exec(`INSERT INTO ioc_host_hit (id, ioc_id, host_id, source, rule_id, evidence,
			first_seen, last_seen, hit_count, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			"iochit_"+strings.ReplaceAll(uuid.New().String(), "-", "")[:12],
			iocID, hostID, strings.TrimSpace(source), strings.TrimSpace(ruleID), ev, now, now, now, now)
		if err != nil {
			return fmt.Errorf("写入 IOC 命中记录失败: %w", err)
		}
	}
	_, err = db.Exec(`UPDATE ioc SET last_seen = ?, hit_count = hit_count + 1, updated_at = ? WHERE id = ?`, now, now, iocID)
	return err
}

// ListIOCHits 列出某条 IOC 命中过的主机。
func (db *DB) ListIOCHits(iocID string, limit int) ([]*IOCHit, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.Query(`SELECT id, ioc_id, host_id, source, rule_id, evidence, first_seen, last_seen,
		hit_count, blocked_at, block_command, unblock_command, created_at, updated_at
		FROM ioc_host_hit WHERE ioc_id = ? ORDER BY last_seen DESC LIMIT ?`, strings.TrimSpace(iocID), limit)
	if err != nil {
		return nil, fmt.Errorf("查询 IOC 命中主机失败: %w", err)
	}
	defer rows.Close()
	return scanIOCHits(rows)
}

// ListIOCHitsForHost 列出某台主机关联的 IOC。
func (db *DB) ListIOCHitsForHost(hostID string, limit int) ([]*IOCHit, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.Query(`SELECT id, ioc_id, host_id, source, rule_id, evidence, first_seen, last_seen,
		hit_count, blocked_at, block_command, unblock_command, created_at, updated_at
		FROM ioc_host_hit WHERE host_id = ? ORDER BY last_seen DESC LIMIT ?`, strings.TrimSpace(hostID), limit)
	if err != nil {
		return nil, fmt.Errorf("查询主机关联 IOC 失败: %w", err)
	}
	defer rows.Close()
	return scanIOCHits(rows)
}

// MarkIOCHostBlocked 记录一次封禁（命令原文与撤销命令都留痕）。
func (db *DB) MarkIOCHostBlocked(iocID, hostID, blockCmd, unblockCmd string) error {
	now := time.Now()
	res, err := db.Exec(`UPDATE ioc_host_hit SET blocked_at = ?, block_command = ?, unblock_command = ?, updated_at = ?
		WHERE ioc_id = ? AND host_id = ?`, now, blockCmd, unblockCmd, now,
		strings.TrimSpace(iocID), strings.TrimSpace(hostID))
	if err != nil {
		return fmt.Errorf("记录封禁失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if err := db.RecordIOCHit(iocID, hostID, "block", "", ""); err != nil {
			return err
		}
		if _, err := db.Exec(`UPDATE ioc_host_hit SET blocked_at = ?, block_command = ?, unblock_command = ?, updated_at = ?
			WHERE ioc_id = ? AND host_id = ?`, now, blockCmd, unblockCmd, now,
			strings.TrimSpace(iocID), strings.TrimSpace(hostID)); err != nil {
			return fmt.Errorf("记录封禁失败: %w", err)
		}
	}
	return nil
}

// MarkIOCHostUnblocked 清除封禁留痕。
func (db *DB) MarkIOCHostUnblocked(iocID, hostID string) error {
	_, err := db.Exec(`UPDATE ioc_host_hit SET blocked_at = NULL, block_command = '', unblock_command = '', updated_at = ?
		WHERE ioc_id = ? AND host_id = ?`, time.Now(), strings.TrimSpace(iocID), strings.TrimSpace(hostID))
	if err != nil {
		return fmt.Errorf("记录解封失败: %w", err)
	}
	return nil
}

// CountIOCByStatus 返回各状态的数量（用于概览）。
func (db *DB) CountIOCByStatus() (map[string]int, error) {
	rows, err := db.Query(`SELECT status, COUNT(*) FROM ioc GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("统计 IOC 状态失败: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, nil
}

func scanIOC(row *sql.Row) (*IOC, error) {
	rec := &IOC{}
	var expires sql.NullTime
	var owner sql.NullString
	var created, updated time.Time
	err := row.Scan(&rec.ID, &rec.Type, &rec.Value, &rec.Normalized, &rec.Status, &rec.Confidence,
		&rec.Severity, &rec.Source, &rec.Tags, &rec.Note, &rec.FirstSeen, &rec.LastSeen,
		&rec.HitCount, &expires, &owner, &created, &updated)
	if err != nil {
		return nil, err
	}
	if expires.Valid {
		rec.ExpiresAt = expires.Time.Format("2006-01-02 15:04:05")
	}
	if owner.Valid {
		rec.OwnerID = owner.String
	}
	rec.CreatedAt = created
	rec.UpdatedAt = updated
	return rec, nil
}

func scanIOCHits(rows *sql.Rows) ([]*IOCHit, error) {
	out := []*IOCHit{}
	for rows.Next() {
		h := &IOCHit{}
		var blocked sql.NullTime
		var created, updated time.Time
		if err := rows.Scan(&h.ID, &h.IOCID, &h.HostID, &h.Source, &h.RuleID, &h.Evidence,
			&h.FirstSeen, &h.LastSeen, &h.HitCount, &blocked, &h.BlockCommand, &h.UnblockCommand,
			&created, &updated); err != nil {
			return nil, fmt.Errorf("扫描 IOC 命中记录失败: %w", err)
		}
		if blocked.Valid {
			h.BlockedAt = blocked.Time.Format("2006-01-02 15:04:05")
		}
		h.CreatedAt = created
		h.UpdatedAt = updated
		out = append(out, h)
	}
	return out, nil
}

// nullableIOCTime 把宽松的时间字符串转成可 NULL 的时间；解析失败也返回 NULL
// （宁可不过期，也不要因为格式写错把记录写成不该有的时间）。
func nullableIOCTime(s string) interface{} {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}
	return nil
}
