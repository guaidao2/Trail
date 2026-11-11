package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 检测发现的状态。
const (
	FindingStatusOpen          = "open"
	FindingStatusAcked         = "acked"
	FindingStatusResolved      = "resolved"
	FindingStatusFalsePositive = "false_positive"
)

// Finding 是一条落库的检测发现（日志命中或基线不符合项）。
//
// 去重键是 (host_id, source, rule_id, subject)：同一台主机、同一条规则、同一个主体
// （如来源 IP）只保留一行，重复命中累加 hit_count 并推进 last_seen。
// 这样"这一轮 vs 上一轮"的差分不需要额外快照表：
//   - 本轮新出现：first_seen 落在本轮时间窗内
//   - 本轮消失：last_seen 早于本轮开始（或已被 resolve）
type Finding struct {
	ID          string    `json:"id"`
	HostID      string    `json:"host_id"`
	Source      string    `json:"source"`
	BatchTaskID string    `json:"batch_task_id,omitempty"`
	Kind        string    `json:"kind"`
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Subject     string    `json:"subject,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	FirstSeen   string    `json:"first_seen"`
	LastSeen    string    `json:"last_seen"`
	HitCount    int       `json:"hit_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FindingUpsert 是写入一条发现的入参。
type FindingUpsert struct {
	HostID      string
	Source      string
	BatchTaskID string
	Kind        string
	RuleID      string
	Title       string
	Category    string
	Severity    string
	Subject     string
	Evidence    string
}

// FindingFilter 是查询条件。
type FindingFilter struct {
	HostID   string
	Source   string
	Severity string
	Status   string
	Keyword  string
}

// UpsertFinding 写入或累加一条发现。
func (db *DB) UpsertFinding(in FindingUpsert) (*Finding, error) {
	hostID := strings.TrimSpace(in.HostID)
	if hostID == "" {
		return nil, fmt.Errorf("host_id 不能为空")
	}
	ruleID := strings.TrimSpace(in.RuleID)
	if ruleID == "" {
		return nil, fmt.Errorf("rule_id 不能为空")
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = "unknown"
	}
	subject := strings.TrimSpace(in.Subject)
	severity := strings.ToLower(strings.TrimSpace(in.Severity))
	if severity == "" {
		severity = "medium"
	}
	evidence := strings.TrimSpace(in.Evidence)
	if len(evidence) > 2000 {
		evidence = evidence[:2000]
	}
	now := time.Now()

	var existingID string
	err := db.QueryRow(`SELECT id FROM detect_findings WHERE host_id = ? AND source = ? AND rule_id = ? AND subject = ?`,
		hostID, source, ruleID, subject).Scan(&existingID)
	switch {
	case err == nil:
		if _, err = db.Exec(`UPDATE detect_findings SET
				title = CASE WHEN ? <> '' THEN ? ELSE title END,
				category = CASE WHEN ? <> '' THEN ? ELSE category END,
				severity = ?, evidence = CASE WHEN ? <> '' THEN ? ELSE evidence END,
				batch_task_id = COALESCE(?, batch_task_id),
				status = CASE WHEN status = ? THEN ? ELSE status END,
				last_seen = ?, hit_count = hit_count + 1, updated_at = ?
			WHERE id = ?`,
			strings.TrimSpace(in.Title), strings.TrimSpace(in.Title),
			strings.TrimSpace(in.Category), strings.TrimSpace(in.Category),
			severity, evidence, evidence,
			nullableHostString(strings.TrimSpace(in.BatchTaskID)),
			FindingStatusResolved, FindingStatusOpen,
			now, now, existingID); err != nil {
			return nil, fmt.Errorf("更新检测发现失败: %w", err)
		}
		return db.GetFinding(existingID)
	case err != sql.ErrNoRows:
		return nil, fmt.Errorf("查询检测发现失败: %w", err)
	}

	id := "find_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	_, err = db.Exec(`INSERT INTO detect_findings (id, host_id, source, batch_task_id, kind, rule_id, title,
		category, severity, status, subject, evidence, first_seen, last_seen, hit_count, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id, hostID, source, nullableHostString(strings.TrimSpace(in.BatchTaskID)),
		strings.TrimSpace(in.Kind), ruleID, strings.TrimSpace(in.Title),
		strings.TrimSpace(in.Category), severity, FindingStatusOpen, subject, evidence,
		now, now, now, now)
	if err != nil {
		return nil, fmt.Errorf("写入检测发现失败: %w", err)
	}
	return db.GetFinding(id)
}

const findingSelectColumns = `id, host_id, source, batch_task_id, kind, rule_id, title, category,
	severity, status, subject, evidence, first_seen, last_seen, hit_count, created_at, updated_at`

// GetFinding 按 ID 读取。
func (db *DB) GetFinding(id string) (*Finding, error) {
	row := db.QueryRow(`SELECT `+findingSelectColumns+` FROM detect_findings WHERE id = ?`, strings.TrimSpace(id))
	f, err := scanFinding(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询检测发现失败: %w", err)
	}
	return f, nil
}

// ListFindings 分页查询，按最近出现时间倒序。
func (db *DB) ListFindings(filter FindingFilter, limit, offset int) ([]*Finding, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where := []string{"1=1"}
	args := []interface{}{}
	if v := strings.TrimSpace(filter.HostID); v != "" {
		where = append(where, "host_id = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.Source); v != "" {
		where = append(where, "source = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.Severity); v != "" {
		where = append(where, "severity = ?")
		args = append(args, strings.ToLower(v))
	}
	if v := strings.TrimSpace(filter.Status); v != "" {
		where = append(where, "status = ?")
		args = append(args, v)
	}
	if kw := strings.TrimSpace(filter.Keyword); kw != "" {
		where = append(where, "(title LIKE ? OR rule_id LIKE ? OR evidence LIKE ?)")
		like := "%" + escapeVulnerabilityLikePattern(kw) + "%"
		args = append(args, like, like, like)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM detect_findings WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计检测发现失败: %w", err)
	}
	rows, err := db.Query(`SELECT `+findingSelectColumns+` FROM detect_findings WHERE `+cond+
		` ORDER BY last_seen DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询检测发现失败: %w", err)
	}
	defer rows.Close()
	out := []*Finding{}
	for rows.Next() {
		f := &Finding{}
		var batch sql.NullString
		var created, updated time.Time
		if err := rows.Scan(&f.ID, &f.HostID, &f.Source, &batch, &f.Kind, &f.RuleID, &f.Title, &f.Category,
			&f.Severity, &f.Status, &f.Subject, &f.Evidence, &f.FirstSeen, &f.LastSeen, &f.HitCount,
			&created, &updated); err != nil {
			return nil, 0, fmt.Errorf("扫描检测发现失败: %w", err)
		}
		if batch.Valid {
			f.BatchTaskID = batch.String
		}
		f.CreatedAt = created
		f.UpdatedAt = updated
		out = append(out, f)
	}
	return out, total, nil
}

// HostFindingSummary 返回一台主机的严重度分布、总数与最近一次发现时间。
func (db *DB) HostFindingSummary(hostID string) (map[string]int, int, string, error) {
	hostID = strings.TrimSpace(hostID)
	rows, err := db.Query(`SELECT severity, COUNT(*) FROM detect_findings
		WHERE host_id = ? AND status NOT IN (?, ?) GROUP BY severity`,
		hostID, FindingStatusResolved, FindingStatusFalsePositive)
	if err != nil {
		return nil, 0, "", fmt.Errorf("统计主机发现失败: %w", err)
	}
	defer rows.Close()
	bySeverity := map[string]int{}
	total := 0
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, 0, "", err
		}
		bySeverity[sev] = n
		total += n
	}
	var last sql.NullString
	if err := db.QueryRow(`SELECT MAX(last_seen) FROM detect_findings WHERE host_id = ?`, hostID).Scan(&last); err != nil && err != sql.ErrNoRows {
		return bySeverity, total, "", nil
	}
	if last.Valid {
		return bySeverity, total, last.String, nil
	}
	return bySeverity, total, "", nil
}

// SetFindingStatus 改状态。
func (db *DB) SetFindingStatus(id, status string) error {
	s := strings.ToLower(strings.TrimSpace(status))
	switch s {
	case FindingStatusOpen, FindingStatusAcked, FindingStatusResolved, FindingStatusFalsePositive:
	default:
		return fmt.Errorf("不支持的发现状态: %s", status)
	}
	res, err := db.Exec(`UPDATE detect_findings SET status = ?, updated_at = ? WHERE id = ?`, s, time.Now(), strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("更新发现状态失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("检测发现不存在: %s", id)
	}
	return nil
}

// ResolveStaleFindings 把"本轮没再出现"的发现标为 resolved。
//
// 只在**完整**扫描后调用：被截断的扫描（预算耗尽 / 只看了部分日志）不能据此判定
// 旧问题已消失，否则会得到"问题自己消失了"的假象。
func (db *DB) ResolveStaleFindings(hostID, source string, keepIDs []string, before time.Time) (int, error) {
	hostID = strings.TrimSpace(hostID)
	if hostID == "" {
		return 0, fmt.Errorf("host_id 不能为空")
	}
	query := `UPDATE detect_findings SET status = ?, updated_at = ?
		WHERE host_id = ? AND source = ? AND status = ? AND last_seen < ?`
	args := []interface{}{FindingStatusResolved, time.Now(), hostID, strings.TrimSpace(source),
		FindingStatusOpen, before}
	if len(keepIDs) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(keepIDs)), ",")
		query += ` AND id NOT IN (` + placeholders + `)`
		for _, id := range keepIDs {
			args = append(args, id)
		}
	}
	res, err := db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("标记过期发现失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func scanFinding(row *sql.Row) (*Finding, error) {
	f := &Finding{}
	var batch sql.NullString
	var created, updated time.Time
	err := row.Scan(&f.ID, &f.HostID, &f.Source, &batch, &f.Kind, &f.RuleID, &f.Title, &f.Category,
		&f.Severity, &f.Status, &f.Subject, &f.Evidence, &f.FirstSeen, &f.LastSeen, &f.HitCount,
		&created, &updated)
	if err != nil {
		return nil, err
	}
	if batch.Valid {
		f.BatchTaskID = batch.String
	}
	f.CreatedAt = created
	f.UpdatedAt = updated
	return f, nil
}
