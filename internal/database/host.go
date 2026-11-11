package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Host 是纳管的一台远程主机（SSH / Telnet）。凭据只以密文形式保存，
// 明文永不落库、也不通过 API 返回。
type Host struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Address          string    `json:"address"`
	Protocol         string    `json:"protocol"`
	Port             int       `json:"port"`
	Username         string    `json:"username"`
	AuthType         string    `json:"auth_type"`
	GroupName        string    `json:"group_name,omitempty"`
	Env              string    `json:"environment,omitempty"`
	Tags             string    `json:"tags,omitempty"`
	Status           string    `json:"status"`
	LastError        string    `json:"last_error,omitempty"`
	LastCheck        string    `json:"last_check_at,omitempty"`
	LastSeen         string    `json:"last_seen_at,omitempty"`
	OSInfo           string    `json:"os_info,omitempty"`
	HostKey          string    `json:"host_key,omitempty"` // 首次信任记录的主机密钥指纹（SHA256）
	OwnerID          string    `json:"owner_user_id,omitempty"`
	Remark           string    `json:"remark,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	HasSecret        bool      `json:"has_secret"`
	SecretCipher     string    `json:"-"`
	PassphraseCipher string    `json:"-"`
}

// HostFilter 是主机列表的筛选条件。
type HostFilter struct {
	Keyword     string
	Group       string
	Environment string
	Status      string
	Protocol    string
}

const hostSelectColumns = `id, name, address, protocol, port, username, auth_type,
	secret_cipher, passphrase_cipher, group_name, environment, tags, status, last_error,
	COALESCE(last_check_at, ''), COALESCE(last_seen_at, ''), os_info, host_key,
	COALESCE(owner_user_id, ''), remark, created_at, updated_at`

func nullableHostString(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func scanHost(scanner interface {
	Scan(dest ...interface{}) error
}) (*Host, error) {
	var h Host
	var lastCheck, lastSeen, createdAt, updatedAt string
	if err := scanner.Scan(
		&h.ID, &h.Name, &h.Address, &h.Protocol, &h.Port, &h.Username, &h.AuthType,
		&h.SecretCipher, &h.PassphraseCipher, &h.GroupName, &h.Env, &h.Tags, &h.Status,
		&h.LastError, &lastCheck, &lastSeen, &h.OSInfo, &h.HostKey, &h.OwnerID, &h.Remark,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	h.LastCheck = lastCheck
	h.LastSeen = lastSeen
	h.HasSecret = strings.TrimSpace(h.SecretCipher) != ""
	h.CreatedAt = parseHostTime(createdAt)
	h.UpdatedAt = parseHostTime(updatedAt)
	return &h, nil
}

func parseHostTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

// CreateHost 新增主机；调用方负责先把凭据加密好。
func (db *DB) CreateHost(h *Host) (*Host, error) {
	if h == nil {
		return nil, fmt.Errorf("主机信息为空")
	}
	address := strings.TrimSpace(h.Address)
	if address == "" {
		return nil, fmt.Errorf("主机地址不能为空")
	}
	if h.ID == "" {
		h.ID = "host_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	}
	protocol := strings.ToLower(strings.TrimSpace(h.Protocol))
	if protocol == "" {
		protocol = "ssh"
	}
	if protocol != "ssh" && protocol != "telnet" {
		return nil, fmt.Errorf("不支持的协议: %s", protocol)
	}
	port := h.Port
	if port <= 0 {
		if protocol == "telnet" {
			port = 23
		} else {
			port = 22
		}
	}
	authType := strings.ToLower(strings.TrimSpace(h.AuthType))
	if authType == "" {
		authType = "password"
	}
	if authType != "password" && authType != "key" {
		return nil, fmt.Errorf("不支持的认证方式: %s", authType)
	}
	name := strings.TrimSpace(h.Name)
	if name == "" {
		name = address
	}
	now := time.Now()
	_, err := db.Exec(
		`INSERT INTO hosts (id, name, address, protocol, port, username, auth_type,
			secret_cipher, passphrase_cipher, group_name, environment, tags, status, last_error,
			os_info, owner_user_id, remark, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?, ?, ?)`,
		h.ID, name, address, protocol, port, strings.TrimSpace(h.Username), authType,
		h.SecretCipher, h.PassphraseCipher, strings.TrimSpace(h.GroupName), strings.TrimSpace(h.Env),
		strings.TrimSpace(h.Tags), "unknown",
		nullableHostString(strings.TrimSpace(h.OwnerID)), strings.TrimSpace(h.Remark), now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("创建主机失败: %w", err)
	}
	return db.GetHost(h.ID)
}

// UpdateHost 更新主机元信息；凭据密文为空时保留原值（前端不回显明文）。
func (db *DB) UpdateHost(h *Host) (*Host, error) {
	if h == nil || strings.TrimSpace(h.ID) == "" {
		return nil, fmt.Errorf("主机 ID 不能为空")
	}
	existing, err := db.GetHost(h.ID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("主机不存在")
	}
	address := strings.TrimSpace(h.Address)
	if address == "" {
		address = existing.Address
	}
	name := strings.TrimSpace(h.Name)
	if name == "" {
		name = existing.Name
	}
	protocol := strings.ToLower(strings.TrimSpace(h.Protocol))
	if protocol == "" {
		protocol = existing.Protocol
	}
	authType := strings.ToLower(strings.TrimSpace(h.AuthType))
	if authType == "" {
		authType = existing.AuthType
	}
	port := h.Port
	if port <= 0 {
		port = existing.Port
	}
	secret := h.SecretCipher
	if strings.TrimSpace(secret) == "" {
		secret = existing.SecretCipher
	}
	passphrase := h.PassphraseCipher
	if strings.TrimSpace(passphrase) == "" {
		passphrase = existing.PassphraseCipher
	}
	_, err = db.Exec(
		`UPDATE hosts SET name = ?, address = ?, protocol = ?, port = ?, username = ?,
			auth_type = ?, secret_cipher = ?, passphrase_cipher = ?, group_name = ?,
			environment = ?, tags = ?, remark = ?, updated_at = ?
		 WHERE id = ?`,
		name, address, protocol, port, strings.TrimSpace(h.Username), authType, secret, passphrase,
		strings.TrimSpace(h.GroupName), strings.TrimSpace(h.Env), strings.TrimSpace(h.Tags),
		strings.TrimSpace(h.Remark), time.Now(), h.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("更新主机失败: %w", err)
	}
	return db.GetHost(h.ID)
}

// GetHost 按 ID 读取主机（不做权限过滤，调用方须先校验访问权）。
func (db *DB) GetHost(id string) (*Host, error) {
	row := db.QueryRow(`SELECT `+hostSelectColumns+` FROM hosts WHERE id = ?`, strings.TrimSpace(id))
	h, err := scanHost(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询主机失败: %w", err)
	}
	return h, nil
}

// DeleteHost 删除主机。
func (db *DB) DeleteHost(id string) error {
	res, err := db.Exec(`DELETE FROM hosts WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("删除主机失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("主机不存在")
	}
	return nil
}

// ListHosts 按访问范围列出主机，返回当前页与总数。
func (db *DB) ListHosts(limit, offset int, filter HostFilter, access RBACListAccess) ([]*Host, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where := " WHERE 1=1"
	args := []interface{}{}
	if kw := strings.TrimSpace(filter.Keyword); kw != "" {
		where += " AND (name LIKE ? OR address LIKE ? OR remark LIKE ? OR tags LIKE ?)"
		pattern := escapeVulnerabilityLikePattern(strings.Trim(kw, "%"))
		args = append(args, pattern, pattern, pattern, pattern)
	}
	if v := strings.TrimSpace(filter.Group); v != "" {
		where += " AND group_name = ?"
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.Environment); v != "" {
		where += " AND environment = ?"
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.Status); v != "" && v != "all" {
		where += " AND status = ?"
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.Protocol); v != "" {
		where += " AND protocol = ?"
		args = append(args, v)
	}
	userID := strings.TrimSpace(access.UserID)
	if userID != "" && access.Scope != RBACScopeAll {
		where += ` AND (
			owner_user_id = ?
			OR EXISTS (
				SELECT 1 FROM rbac_resource_assignments ra
				WHERE ra.user_id = ? AND ra.resource_type = 'host' AND ra.resource_id = hosts.id
			)
		)`
		args = append(args, userID, userID)
	}

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计主机失败: %w", err)
	}

	query := `SELECT ` + hostSelectColumns + ` FROM hosts` + where + ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := db.Query(query, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询主机列表失败: %w", err)
	}
	defer rows.Close()
	list := make([]*Host, 0)
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("读取主机失败: %w", err)
		}
		list = append(list, h)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// ClearHostKey 清空主机密钥指纹：主机重装换钥后需重新信任，否则所有连接都会
// 因「主机密钥不匹配」被拒绝。
func (db *DB) ClearHostKey(id string) error {
	_, err := db.Exec(`UPDATE hosts SET host_key = '', updated_at = ? WHERE id = ?`, time.Now(), strings.TrimSpace(id))
	return err
}

// SetHostKey 记录主机的密钥指纹（首次信任），供后续连接校验。
func (db *DB) SetHostKey(id, hostKey string) error {
	hostKey = strings.TrimSpace(hostKey)
	if hostKey == "" {
		return nil
	}
	_, err := db.Exec(`UPDATE hosts SET host_key = ?, updated_at = ? WHERE id = ?`, hostKey, time.Now(), strings.TrimSpace(id))
	return err
}

func (db *DB) UpdateHostProbe(id, status, errMsg, osInfo string) error {
	if strings.TrimSpace(status) == "" {
		status = "unknown"
	}
	now := time.Now()
	query := `UPDATE hosts SET status = ?, last_error = ?, last_check_at = ?, updated_at = ?`
	args := []interface{}{status, strings.TrimSpace(errMsg), now, now}
	if status == "online" {
		query += `, last_seen_at = ?`
		args = append(args, now)
	}
	if strings.TrimSpace(osInfo) != "" {
		query += `, os_info = ?`
		args = append(args, strings.TrimSpace(osInfo))
	}
	query += ` WHERE id = ?`
	args = append(args, strings.TrimSpace(id))
	if _, err := db.Exec(query, args...); err != nil {
		return fmt.Errorf("更新主机探测结果失败: %w", err)
	}
	return nil
}
