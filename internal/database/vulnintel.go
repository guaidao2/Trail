package database

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 漏洞情报（外部公开知识库）：NVD 主体 + CISA KEV 在野标记 + EPSS 利用概率 + GHSA 版本区间。
//
// 与 vulnerabilities 的区别：vulnerabilities 是"我在自己资产上发现了什么"，
// 这里是"外界已知什么"。只有把情报与主机软件清单匹配上，才写成 detect_findings。

// VulnIntel 是一条 CVE 记录。
type VulnIntel struct {
	CVEID          string    `json:"cve_id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       string    `json:"severity"`
	CVSSScore      *float64  `json:"cvss_score,omitempty"`
	CVSSVector     string    `json:"cvss_vector,omitempty"`
	PublishedAt    string    `json:"published_at,omitempty"`
	ModifiedAt     string    `json:"modified_at,omitempty"`
	KEV            bool      `json:"kev"`
	KEVAddedAt     string    `json:"kev_added_at,omitempty"`
	EPSS           *float64  `json:"epss,omitempty"`
	EPSSPercentile *float64  `json:"epss_percentile,omitempty"`
	EPSSUpdatedAt  string    `json:"epss_updated_at,omitempty"`
	Source         string    `json:"source,omitempty"`
	Refs           []string  `json:"refs,omitempty"`
	CWEs           []string  `json:"cwes,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// VulnIntelRange 是一条结构化版本区间（NVD cpeMatch 或 GHSA vulnerableVersionRange）。
// 空串表示该边界不存在。
type VulnIntelRange struct {
	Vendor         string `json:"vendor,omitempty"`
	Product        string `json:"product,omitempty"`
	Criteria       string `json:"criteria,omitempty"`
	StartIncl      string `json:"start_including,omitempty"`
	StartExcl      string `json:"start_excluding,omitempty"`
	EndIncl        string `json:"end_including,omitempty"`
	EndExcl        string `json:"end_excluding,omitempty"`
	Source         string `json:"source,omitempty"`
	PatchedVersion string `json:"patched_version,omitempty"`
}

// VulnIntelPOC 是公开 PoC / 利用链接。
type VulnIntelPOC struct {
	CVEID     string `json:"cve_id"`
	URL       string `json:"url"`
	Repo      string `json:"repo,omitempty"`
	Stars     int    `json:"stars"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// VulnIntelHit 是检索结果。
//
// VersionInRange 是三态：nil 表示没有结构化区间、无法判断；true/false 才是判定结果。
// 之所以不用 bool，是因为"无法判断"和"不在区间内"对蓝队是完全不同的结论。
type VulnIntelHit struct {
	CVEID          string   `json:"cve_id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	CVSSScore      *float64 `json:"cvss_score,omitempty"`
	KEV            bool     `json:"kev"`
	EPSS           *float64 `json:"epss,omitempty"`
	Published      string   `json:"published,omitempty"`
	Matched        []string `json:"matched,omitempty"`
	VersionSeen    bool     `json:"version_seen_in_criteria,omitempty"`
	VersionInRange *bool    `json:"version_in_range,omitempty"`
	Source         string   `json:"source,omitempty"`
}

// VulnIntelFilter 是检索条件。
type VulnIntelFilter struct {
	Keyword    string
	Vendor     string
	Product    string
	Version    string
	Severity   string
	KEVOnly    bool
	Source     string
	SortByEPSS bool
	Limit      int
	Offset     int
}

// VulnIntelSyncState 是单个同步源的状态。
type VulnIntelSyncState struct {
	Source      string `json:"source"`
	Cursor      string `json:"cursor,omitempty"`
	LastSyncAt  string `json:"last_sync_at,omitempty"`
	TotalSynced int    `json:"total_synced"`
	LastError   string `json:"last_error,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// Package 是主机上采集到的软件包（name + version）。
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source,omitempty"` // dpkg / rpm / pip / npm / docker
}

// PackageMatch 是一条"包 → CVE"的匹配结果。
//
// Status 三态：
//   - affected     版本明确落在结构化区间内
//   - not_affected 有结构化区间且明确不在区间内
//   - unknown      没有可用区间 / 版本不可解析 / 发行版可能已回补丁
//
// NeedsPatchCheck 在版本带发行版后缀（-1ubuntu2.16 / -1.el8）时为 true：
// 这类版本号看着老，但发行版可能已回移补丁，不能直接判"受影响"。
type PackageMatch struct {
	Package         Package  `json:"package"`
	CVEID           string   `json:"cve_id"`
	Severity        string   `json:"severity,omitempty"`
	KEV             bool     `json:"kev"`
	EPSS            *float64 `json:"epss,omitempty"`
	Status          string   `json:"status"`
	MatchedProduct  string   `json:"matched_product,omitempty"`
	Range           string   `json:"range,omitempty"`
	NeedsPatchCheck bool     `json:"needs_patch_check,omitempty"`
	PatchedVersion  string   `json:"patched_version,omitempty"`
}

const vulnIntelColumns = `cve_id, title, description, severity, cvss_score, cvss_vector,
	published_at, modified_at, kev, kev_added_at, epss, epss_percentile, epss_updated_at,
	source, refs, cwes, created_at, updated_at`

// UpsertVulnIntel 写入一条 CVE 与其结构化区间。
//
// KEV / EPSS 列由各自的同步源维护，这里不覆盖（避免 NVD 全量回填把在野标记清掉）。
func (db *DB) UpsertVulnIntel(v VulnIntel, ranges []VulnIntelRange) error {
	cveID := strings.ToUpper(strings.TrimSpace(v.CVEID))
	if cveID == "" {
		return fmt.Errorf("CVE 编号不能为空")
	}
	now := time.Now()
	_, err := db.Exec(`INSERT INTO vuln_intel
		(cve_id, title, description, severity, cvss_score, cvss_vector,
		 published_at, modified_at, source, refs, cwes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			title = excluded.title,
			description = excluded.description,
			severity = CASE WHEN excluded.severity <> '' THEN excluded.severity ELSE vuln_intel.severity END,
			cvss_score = COALESCE(excluded.cvss_score, vuln_intel.cvss_score),
			cvss_vector = CASE WHEN excluded.cvss_vector <> '' THEN excluded.cvss_vector ELSE vuln_intel.cvss_vector END,
			published_at = CASE WHEN excluded.published_at <> '' THEN excluded.published_at ELSE vuln_intel.published_at END,
			modified_at = CASE WHEN excluded.modified_at <> '' THEN excluded.modified_at ELSE vuln_intel.modified_at END,
			source = CASE WHEN excluded.source <> '' THEN excluded.source ELSE vuln_intel.source END,
			refs = CASE WHEN excluded.refs <> '' THEN excluded.refs ELSE vuln_intel.refs END,
			cwes = CASE WHEN excluded.cwes <> '' THEN excluded.cwes ELSE vuln_intel.cwes END,
			updated_at = excluded.updated_at`,
		cveID, strings.TrimSpace(v.Title), v.Description, normalizeSeverity(v.Severity),
		v.CVSSScore, strings.TrimSpace(v.CVSSVector),
		strings.TrimSpace(v.PublishedAt), strings.TrimSpace(v.ModifiedAt),
		strings.TrimSpace(v.Source), strings.Join(v.Refs, "\n"), strings.Join(v.CWEs, ","),
		now, now)
	if err != nil {
		return fmt.Errorf("写入漏洞情报失败: %w", err)
	}
	if len(ranges) == 0 {
		return nil
	}
	return db.replaceVulnIntelRanges(cveID, ranges)
}

func (db *DB) replaceVulnIntelRanges(cveID string, ranges []VulnIntelRange) error {
	// 删除范围按来源区分：
	//   - osv：一个生态里可能有多条 advisory 共享同一 CVE 别名（GHSA-* 与 PYSEC-*），
	//     必须再按 (vendor, product) 收窄，否则后写的一条会把别的包的区间删掉；
	//   - nvd / ghsa：一条 CVE 的 CPE 可能有多个 vendor/product，按 source 全删，
	//     这样源里删掉的旧区间才会被清掉（否则会留下长期假 affected）。
	type scope struct{ src, vendor, product string }
	scopes := map[scope]bool{}
	for _, r := range ranges {
		src := normalizeRangeSource(r.Source)
		sc := scope{src: src}
		if src == "osv" {
			sc.vendor = strings.ToLower(strings.TrimSpace(r.Vendor))
			sc.product = strings.ToLower(strings.TrimSpace(r.Product))
		}
		scopes[sc] = true
	}
	for sc := range scopes {
		var err error
		switch {
		case sc.src == "osv" && sc.product != "":
			_, err = db.Exec(`DELETE FROM vuln_intel_range WHERE cve_id = ? AND source = ? AND LOWER(vendor) = ? AND LOWER(product) = ?`,
				cveID, sc.src, sc.vendor, sc.product)
		default:
			_, err = db.Exec(`DELETE FROM vuln_intel_range WHERE cve_id = ? AND source = ?`, cveID, sc.src)
		}
		if err != nil {
			return fmt.Errorf("清理旧版本区间失败: %w", err)
		}
	}
	for _, r := range ranges {
		if _, err := db.Exec(`INSERT OR IGNORE INTO vuln_intel_range
			(cve_id, vendor, product, criteria, start_incl, start_excl, end_incl, end_excl, source, patched_version)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			cveID,
			strings.ToLower(strings.TrimSpace(r.Vendor)), strings.ToLower(strings.TrimSpace(r.Product)),
			strings.TrimSpace(r.Criteria),
			strings.TrimSpace(r.StartIncl), strings.TrimSpace(r.StartExcl),
			strings.TrimSpace(r.EndIncl), strings.TrimSpace(r.EndExcl),
			normalizeRangeSource(r.Source), strings.TrimSpace(r.PatchedVersion)); err != nil {
			return fmt.Errorf("写入版本区间失败: %w", err)
		}
	}
	return nil
}

// KEVEntry 是 KEV 目录中的一条记录（已解析、可直接落库）。
type KEVEntry struct {
	CVEID                      string
	DateAdded                  time.Time
	Vendor                     string
	Product                    string
	Name                       string
	Description                string
	RequiredAction             string
	DueDate                    string
	KnownRansomwareCampaignUse bool
}

// UpsertKEVEntry 标记在野利用并写入 KEV 目录自带的详情。
//
// KEV 目录本身就有厂商、产品、名称、简述、修复动作与截止日期，
// 不写进来的话，NVD 未同步时页面上只剩一个 CVE 编号和空列。
// 若 NVD 已经写过更完整的标题/描述，则保留 NVD 的版本。
func (db *DB) UpsertKEVEntry(e KEVEntry) error {
	cveID := strings.ToUpper(strings.TrimSpace(e.CVEID))
	if cveID == "" {
		return nil
	}
	title := strings.TrimSpace(e.Name)
	prefix := strings.TrimSpace(strings.TrimSpace(e.Vendor) + " " + strings.TrimSpace(e.Product))
	if prefix != "" && title != "" {
		title = prefix + " — " + title
	} else if title == "" {
		title = prefix
	}
	desc := strings.TrimSpace(e.Description)
	if action := strings.TrimSpace(e.RequiredAction); action != "" {
		desc += "\n\n修复动作：" + action
	}
	if due := strings.TrimSpace(e.DueDate); due != "" {
		desc += "\n截止日期（CISA 要求）：" + due
	}
	if e.KnownRansomwareCampaignUse {
		desc += "\n已知被勒索软件利用。"
	}
	refs := "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
	now := time.Now()
	added := e.DateAdded
	if added.IsZero() {
		added = now
	}
	_, err := db.Exec(`INSERT INTO vuln_intel (cve_id, title, description, kev, kev_added_at, source, refs, created_at, updated_at)
		VALUES (?, ?, ?, 1, ?, 'kev', ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			kev = 1,
			kev_added_at = excluded.kev_added_at,
			title = CASE WHEN IFNULL(vuln_intel.title,'') = '' THEN excluded.title ELSE vuln_intel.title END,
			description = CASE WHEN IFNULL(vuln_intel.description,'') = '' THEN excluded.description ELSE vuln_intel.description END,
			refs = CASE WHEN IFNULL(vuln_intel.refs,'') = '' THEN excluded.refs ELSE vuln_intel.refs END,
			updated_at = excluded.updated_at`,
		cveID, title, desc, added, refs, now, now)
	if err != nil {
		return fmt.Errorf("标记 KEV 失败: %w", err)
	}
	return nil
}

// MarkKEV 仅标记在野利用（无详情时的兼容入口）。
func (db *DB) MarkKEV(cveID string, added time.Time) error {
	return db.UpsertKEVEntry(KEVEntry{CVEID: cveID, DateAdded: added})
}

// ClearKEV 清空在野标记（KEV 是全量覆盖，条目被移除时也要同步）。
func (db *DB) ClearKEV() error {
	if _, err := db.Exec(`UPDATE vuln_intel SET kev = 0, kev_added_at = NULL WHERE kev = 1`); err != nil {
		return fmt.Errorf("清理 KEV 标记失败: %w", err)
	}
	return nil
}

// UpdateEPSS 更新利用概率。
func (db *DB) UpdateEPSS(cveID string, score, percentile float64, at time.Time) error {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil
	}
	now := time.Now()
	_, err := db.Exec(`INSERT INTO vuln_intel (cve_id, epss, epss_percentile, epss_updated_at, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'epss', ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			epss = excluded.epss, epss_percentile = excluded.epss_percentile,
			epss_updated_at = excluded.epss_updated_at, updated_at = excluded.updated_at`,
		cveID, score, percentile, at, now, now)
	if err != nil {
		return fmt.Errorf("更新 EPSS 失败: %w", err)
	}
	return nil
}

// UpsertVulnIntelPOCs 写入 PoC 链接。
func (db *DB) UpsertVulnIntelPOCs(pocs []VulnIntelPOC) error {
	for _, p := range pocs {
		cveID := strings.ToUpper(strings.TrimSpace(p.CVEID))
		url := strings.TrimSpace(p.URL)
		if cveID == "" || url == "" {
			continue
		}
		if _, err := db.Exec(`INSERT INTO vuln_intel_poc (cve_id, url, repo, stars, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(cve_id, url) DO UPDATE SET stars = excluded.stars, repo = excluded.repo, updated_at = excluded.updated_at`,
			cveID, url, strings.TrimSpace(p.Repo), p.Stars, strings.TrimSpace(p.UpdatedAt)); err != nil {
			return fmt.Errorf("写入 PoC 失败: %w", err)
		}
	}
	return nil
}

// SearchVulnIntel 按条件检索，KEV 优先、EPSS 次之、CVSS 再次。
func (db *DB) SearchVulnIntel(f VulnIntelFilter) ([]VulnIntelHit, int, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where := []string{"1=1"}
	args := []interface{}{}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		like := "%" + strings.ToLower(kw) + "%"
		where = append(where, "(LOWER(cve_id) LIKE ? OR LOWER(title) LIKE ? OR LOWER(description) LIKE ?)")
		args = append(args, like, like, like)
	}
	if v := strings.ToUpper(strings.TrimSpace(f.Severity)); v != "" {
		where = append(where, "severity = ?")
		args = append(args, v)
	}
	if f.KEVOnly {
		where = append(where, "kev = 1")
	}
	if s := strings.TrimSpace(f.Source); s != "" {
		where = append(where, "source = ?")
		args = append(args, s)
	}
	product := strings.ToLower(strings.TrimSpace(f.Product))
	vendor := strings.ToLower(strings.TrimSpace(f.Vendor))
	if product != "" || vendor != "" {
		sub := "SELECT DISTINCT cve_id FROM vuln_intel_range WHERE 1=1"
		subArgs := []interface{}{}
		if product != "" {
			like := "%" + product + "%"
			sub += " AND (LOWER(product) LIKE ? OR LOWER(criteria) LIKE ?)"
			subArgs = append(subArgs, like, like)
		}
		if vendor != "" {
			sub += " AND LOWER(vendor) LIKE ?"
			subArgs = append(subArgs, "%"+vendor+"%")
		}
		where = append(where, "cve_id IN ("+sub+")")
		args = append(args, subArgs...)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_intel WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计漏洞情报失败: %w", err)
	}

	order := "kev DESC, COALESCE(epss, 0) DESC, COALESCE(cvss_score, 0) DESC, published_at DESC"
	if f.SortByEPSS {
		order = "COALESCE(epss, 0) DESC, kev DESC, COALESCE(cvss_score, 0) DESC"
	}
	rows, err := db.Query(`SELECT `+vulnIntelColumns+` FROM vuln_intel WHERE `+cond+
		` ORDER BY `+order+` LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("检索漏洞情报失败: %w", err)
	}
	defer rows.Close()

	hits := []VulnIntelHit{}
	for rows.Next() {
		rec, err := scanVulnIntel(rows)
		if err != nil {
			return nil, 0, err
		}
		hit := VulnIntelHit{
			CVEID: rec.CVEID, Title: rec.Title, Severity: rec.Severity,
			CVSSScore: rec.CVSSScore, KEV: rec.KEV, EPSS: rec.EPSS,
			Published: rec.PublishedAt, Source: rec.Source,
		}
		if product != "" {
			hit.Matched = db.matchedProducts(rec.CVEID, vendor, product)
		}
		if product != "" && strings.TrimSpace(f.Version) != "" {
			hit.VersionSeen = db.versionSeenInCriteria(rec.CVEID, f.Version)
			if in, comparable := db.VersionInVulnIntelRange(rec.CVEID, product, f.Version); comparable {
				v := in
				hit.VersionInRange = &v
			}
		}
		hits = append(hits, hit)
	}
	return hits, total, nil
}

func (db *DB) matchedProducts(cveID, vendor, product string) []string {
	rows, err := db.Query(`SELECT vendor, product FROM vuln_intel_range WHERE cve_id = ?`, cveID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	out := []string{}
	for rows.Next() {
		var v, p string
		if err := rows.Scan(&v, &p); err != nil {
			continue
		}
		if product != "" && !strings.Contains(strings.ToLower(p), product) &&
			!strings.Contains(strings.ToLower(v+" "+p), product) {
			continue
		}
		if vendor != "" && !strings.Contains(strings.ToLower(v), vendor) {
			continue
		}
		key := v + "/" + p
		if p == "" {
			key = v
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func (db *DB) versionSeenInCriteria(cveID, version string) bool {
	rows, err := db.Query(`SELECT criteria FROM vuln_intel_range WHERE cve_id = ?`, cveID)
	if err != nil {
		return false
	}
	defer rows.Close()
	v := strings.ToLower(strings.TrimSpace(version))
	if v == "" {
		return false
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(c), v) {
			return true
		}
	}
	return false
}

// GetVulnIntel 返回一条 CVE 的详情（含区间与 PoC）。
func (db *DB) GetVulnIntel(cveID string) (*VulnIntel, []VulnIntelRange, []VulnIntelPOC, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	row := db.QueryRow(`SELECT `+vulnIntelColumns+` FROM vuln_intel WHERE cve_id = ?`, cveID)
	rec, err := scanVulnIntel(row)
	if err == sql.ErrNoRows {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	ranges, err := db.vulnIntelRanges(cveID)
	if err != nil {
		return nil, nil, nil, err
	}
	pocs, err := db.vulnIntelPOCs(cveID)
	if err != nil {
		return nil, nil, nil, err
	}
	return rec, ranges, pocs, nil
}

func (db *DB) vulnIntelRanges(cveID string) ([]VulnIntelRange, error) {
	rows, err := db.Query(`SELECT vendor, product, criteria, start_incl, start_excl, end_incl, end_excl, source, patched_version
		FROM vuln_intel_range WHERE cve_id = ?`, cveID)
	if err != nil {
		return nil, fmt.Errorf("读取版本区间失败: %w", err)
	}
	defer rows.Close()
	out := []VulnIntelRange{}
	for rows.Next() {
		var r VulnIntelRange
		if err := rows.Scan(&r.Vendor, &r.Product, &r.Criteria, &r.StartIncl, &r.StartExcl,
			&r.EndIncl, &r.EndExcl, &r.Source, &r.PatchedVersion); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (db *DB) vulnIntelPOCs(cveID string) ([]VulnIntelPOC, error) {
	rows, err := db.Query(`SELECT cve_id, url, repo, stars, updated_at FROM vuln_intel_poc WHERE cve_id = ? ORDER BY stars DESC LIMIT 20`, cveID)
	if err != nil {
		return nil, fmt.Errorf("读取 PoC 失败: %w", err)
	}
	defer rows.Close()
	out := []VulnIntelPOC{}
	for rows.Next() {
		var p VulnIntelPOC
		var updated sql.NullString
		if err := rows.Scan(&p.CVEID, &p.URL, &p.Repo, &p.Stars, &updated); err != nil {
			return nil, err
		}
		if updated.Valid {
			p.UpdatedAt = updated.String
		}
		out = append(out, p)
	}
	return out, nil
}

// VersionInVulnIntelRange 判断某产品版本是否落在受影响区间内。
// 第二个返回值 comparable=false 表示没有可用区间，调用方必须按"无法判断"处理。
func (db *DB) VersionInVulnIntelRange(cveID, product, version string) (in bool, comparable bool) {
	product = strings.ToLower(strings.TrimSpace(product))
	version = strings.TrimSpace(version)
	if product == "" || version == "" {
		return false, false
	}
	rows, err := db.Query(`SELECT start_incl, start_excl, end_incl, end_excl FROM vuln_intel_range
		WHERE cve_id = ? AND LOWER(product) = ?`,
		strings.ToUpper(strings.TrimSpace(cveID)), product)
	if err != nil {
		return false, false
	}
	defer rows.Close()
	any := false
	for rows.Next() {
		var si, se, ei, ee string
		if err := rows.Scan(&si, &se, &ei, &ee); err != nil {
			continue
		}
		if si == "" && se == "" && ei == "" && ee == "" {
			continue
		}
		any = true
		ok := true
		if si != "" && compareVersions(version, si) < 0 {
			ok = false
		}
		if se != "" && compareVersions(version, se) <= 0 {
			ok = false
		}
		if ei != "" && compareVersions(version, ei) > 0 {
			ok = false
		}
		if ee != "" && compareVersions(version, ee) >= 0 {
			ok = false
		}
		if ok {
			return true, true
		}
	}
	return false, any
}

// compareVersions 宽松比较点分版本号：数字段按数值、非数字段按字典序；
// 缺失段按 0 处理（"1.2" == "1.2.0"）；预发布后缀（1.0b3）排在本体之前。
func compareVersions(a, b string) int {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "v")
		// dpkg epoch（1:9.6p1-3）不参与上游版本比较
		if i := strings.Index(s, ":"); i > 0 && i <= 2 {
			if _, err := strconv.Atoi(s[:i]); err == nil {
				s = s[i+1:]
			}
		}
		// 发行版修订后缀（1.1.1f-1ubuntu2.16 / 2.4.49-1.el8）不参与上游版本比较
		return stripDistroRevision(s)
	}
	as := strings.Split(norm(a), ".")
	bs := strings.Split(norm(b), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if i == len(as)-1 {
			av = trimDistroSuffix(av)
		}
		if i == len(bs)-1 {
			bv = trimDistroSuffix(bv)
		}
		if c := compareVersionSegment(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

func trimDistroSuffix(seg string) string {
	for _, mark := range []string{"-", "+", "~"} {
		if i := strings.Index(seg, mark); i > 0 {
			return seg[:i]
		}
	}
	return seg
}

// stripDistroRevision 去掉 Debian/Ubuntu/RHEL 风格的发行版修订后缀，
// 只保留上游版本：`1.1.1f-1ubuntu2.16` → `1.1.1f`、`2.4.49-1.el8` → `2.4.49`。
func stripDistroRevision(s string) string {
	lower := strings.ToLower(s)
	for _, mark := range []string{"ubuntu", "deb", "el8", "el9", "el7", ".el", "suse", "centos", ".fc", "rhs"} {
		i := strings.Index(lower, mark)
		if i <= 0 {
			continue
		}
		if j := strings.LastIndexAny(lower[:i], "-"); j > 0 {
			return strings.TrimSpace(s[:j])
		}
	}
	return s
}

func compareVersionSegment(a, b string) int {
	an, as := splitNumericPrefix(a)
	bn, bs := splitNumericPrefix(b)
	if an != bn {
		if an < bn {
			return -1
		}
		return 1
	}
	if as == bs {
		return 0
	}
	// 数字相同，比较后缀：显式预发布（alpha/beta/rc/pre/dev/snapshot）低于正式版，
	// 纯字母后缀按补丁级别处理（OpenSSL 的 1.1.1f 晚于 1.1.1），空后缀最低。
	aPre, bPre := isPrereleaseSuffix(as), isPrereleaseSuffix(bs)
	if aPre != bPre {
		if aPre {
			return -1
		}
		return 1
	}
	if as == "" {
		return -1
	}
	if bs == "" {
		return 1
	}
	if as < bs {
		return -1
	}
	return 1
}

// splitNumericPrefix 把 "1f" 拆成 (1, "f")；纯数字段后缀为空。
func splitNumericPrefix(s string) (int, string) {
	n := 0
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n, s[i:]
}

// isPrereleaseSuffix 识别显式预发布标记（rc / alpha / beta / pre / dev / snapshot）。
func isPrereleaseSuffix(s string) bool {
	if s == "" {
		return false
	}
	switch {
	case strings.HasPrefix(s, "rc"), strings.HasPrefix(s, "alpha"), strings.HasPrefix(s, "beta"),
		strings.HasPrefix(s, "pre"), strings.HasPrefix(s, "dev"), strings.HasPrefix(s, "snapshot"):
		return true
	}
	return false
}

// GetVulnIntelSync 读取某源的同步状态。
func (db *DB) GetVulnIntelSync(source string) (VulnIntelSyncState, error) {
	st := VulnIntelSyncState{Source: strings.ToLower(strings.TrimSpace(source)), Enabled: true}
	var last sql.NullString
	var enabled sql.NullInt64
	err := db.QueryRow(`SELECT cursor, last_sync_at, total_synced, last_error, enabled
		FROM vuln_intel_sync WHERE source = ?`, st.Source).
		Scan(&st.Cursor, &last, &st.TotalSynced, &st.LastError, &enabled)
	if err == sql.ErrNoRows {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("读取同步状态失败: %w", err)
	}
	if last.Valid {
		st.LastSyncAt = last.String
	}
	if enabled.Valid {
		st.Enabled = enabled.Int64 != 0
	}
	return st, nil
}

// SaveVulnIntelSync 写入同步状态。
func (db *DB) SaveVulnIntelSync(st VulnIntelSyncState) error {
	enabled := 0
	if st.Enabled {
		enabled = 1
	}
	_, err := db.Exec(`INSERT INTO vuln_intel_sync (source, cursor, last_sync_at, total_synced, last_error, enabled)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor, last_sync_at = excluded.last_sync_at,
			total_synced = excluded.total_synced, last_error = excluded.last_error, enabled = excluded.enabled`,
		strings.ToLower(strings.TrimSpace(st.Source)), st.Cursor, nullIfEmpty(st.LastSyncAt),
		st.TotalSynced, st.LastError, enabled)
	if err != nil {
		return fmt.Errorf("保存同步状态失败: %w", err)
	}
	return nil
}

// ListVulnIntelSync 返回全部同步源状态。
func (db *DB) ListVulnIntelSync() ([]VulnIntelSyncState, error) {
	rows, err := db.Query(`SELECT source, cursor, last_sync_at, total_synced, last_error, enabled
		FROM vuln_intel_sync ORDER BY source`)
	if err != nil {
		return nil, fmt.Errorf("读取同步状态失败: %w", err)
	}
	defer rows.Close()
	out := []VulnIntelSyncState{}
	for rows.Next() {
		var st VulnIntelSyncState
		var last sql.NullString
		var enabled sql.NullInt64
		if err := rows.Scan(&st.Source, &st.Cursor, &last, &st.TotalSynced, &st.LastError, &enabled); err != nil {
			return nil, err
		}
		if last.Valid {
			st.LastSyncAt = last.String
		}
		st.Enabled = !enabled.Valid || enabled.Int64 != 0
		out = append(out, st)
	}
	return out, nil
}

// CountVulnIntel 返回总条数与 KEV 条数。
func (db *DB) CountVulnIntel() (total int, kev int, err error) {
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(kev), 0) FROM vuln_intel`).Scan(&total, &kev); err != nil {
		return 0, 0, fmt.Errorf("统计漏洞情报失败: %w", err)
	}
	return total, kev, nil
}

// CountVulnIntelRanges 返回区间条数（同步健康度检查用）。
func (db *DB) CountVulnIntelRanges() (int, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_intel_range`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ecosystemBySource 把清单来源映射成 OSV/GHSA 的生态名（小写）。
// 非空表示这是语言生态包：只允许按 (生态, 精确包名) 匹配，不做 CPE 产品名推导——
// 否则 ruby-sdbm 会命中 ruby 解释器、@scope/pkg 会命中 pkg 之类的同名包。
func ecosystemBySource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "pip", "pypi", "python",
		"npm", "node", "yarn", "pnpm",
		"gem", "rubygems", "ruby",
		"go", "gomod", "golang",
		"cargo", "crates", "crates.io",
		"composer", "packagist",
		"maven", "nuget":
		return NormalizeEcosystem(source)
	}
	return ""
}

// isEcosystemVendor 判断区间里的 vendor 是不是语言生态名（而不是 CPE 厂商）。
func isEcosystemVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "pypi", "npm", "rubygems", "go", "crates.io", "packagist", "maven", "nuget", "hex", "pub", "composer":
		return true
	}
	return false
}

// MatchPackages 把主机软件清单与情报库做保守匹配。
//
// 规则（刻意保守）：
//   - 只有同产品且存在结构化区间时才可能给出 affected / not_affected；
//   - 版本带发行版后缀时置 NeedsPatchCheck，且不直接判 affected（发行版可能已回移补丁）；
//   - 其余一律 unknown，由调用方决定下一步补证。
func (db *DB) MatchPackages(pkgs []Package) ([]PackageMatch, error) {
	// 先把包名归一并推导候选产品名（openssh-client -> openssh、@scope/pkg -> pkg）。
	// 候选名在 Go 里算，SQL 只做等值 IN —— 这样能吃到 idx_vuln_intel_range_product，
	// 避免"每个包一次 LOWER(product) 全表扫描"（800 个包时会直接超时）。
	type candidate struct {
		pkg   Package
		names []string
		eco   string // 非空表示语言生态包，只认 vendor == eco 的精确匹配
	}
	candidates := make([]candidate, 0, len(pkgs))
	productToCands := map[string][]int{}
	for _, pkg := range pkgs {
		version := strings.TrimSpace(pkg.Version)
		name := strings.ToLower(strings.TrimSpace(pkg.Name))
		if name == "" || version == "" || !startsWithDigit(version) {
			// docker 的 latest / <none>、非版本号标签无法比较，直接跳过
			continue
		}
		if strings.EqualFold(strings.TrimSpace(pkg.Source), "docker") {
			// 镜像 tag 不是包版本（8.2-apache、latest、alpine），拿它比区间必然误判；
			// 容器里的真实包要看镜像内的包管理器，那是另一条采集路径。
			continue
		}
		eco := ecosystemBySource(pkg.Source)
		var names []string
		if eco != "" {
			names = []string{name}
		} else {
			names = productCandidates(name)
		}
		if len(names) == 0 {
			continue
		}
		idx := len(candidates)
		candidates = append(candidates, candidate{pkg: pkg, names: names, eco: eco})
		for _, n := range names {
			productToCands[n] = append(productToCands[n], idx)
		}
	}
	if len(candidates) == 0 {
		return []PackageMatch{}, nil
	}

	out := []PackageMatch{}
	seen := map[string]int{} // key -> out 下标，便于同键升级为更强状态

	// 分批查询：一次拿回一批候选产品的全部区间。
	names := make([]string, 0, len(productToCands))
	for n := range productToCands {
		names = append(names, n)
	}
	sort.Strings(names)
	const chunk = 300
	for start := 0; start < len(names); start += chunk {
		end := start + chunk
		if end > len(names) {
			end = len(names)
		}
		batch := names[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")
		args := make([]interface{}, 0, len(batch))
		for _, n := range batch {
			args = append(args, n)
		}
		rows, err := db.Query(`SELECT r.cve_id, v.severity, v.kev, v.epss, COALESCE(v.published_at,''), r.vendor, r.product,
			r.start_incl, r.start_excl, r.end_incl, r.end_excl, r.patched_version
			FROM vuln_intel_range r JOIN vuln_intel v ON v.cve_id = r.cve_id
			WHERE r.product IN (`+placeholders+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("匹配软件包失败: %w", err)
		}
		for rows.Next() {
			var cveID, severity, published, vendor, product, si, se, ei, ee, patched string
			var kev bool
			var epss *float64
			if err := rows.Scan(&cveID, &severity, &kev, &epss, &published, &vendor, &product, &si, &se, &ei, &ee, &patched); err != nil {
				rows.Close()
				return nil, err
			}
			if si == "" && se == "" && ei == "" && ee == "" {
				continue
			}
			matched, ok := productToCands[strings.ToLower(product)]
			if !ok {
				continue
			}
			for _, ci := range matched {
				cand := candidates[ci]
				// vendor 可能是 CPE 厂商（pallets / ruby-lang），也可能是生态名（pypi）。
				vNorm := NormalizeEcosystem(vendor)
				// 语言生态包：只接受同生态的区间，或 CPE 区间（NVD 走厂商库也能覆盖到语言包）。
				if cand.eco != "" && isEcosystemVendor(vendor) && vNorm != cand.eco {
					continue
				}
				// 反过来：OS 包不该命中语言生态的区间（同名的 pip/npm 包不是系统包）。
				if cand.eco == "" && isEcosystemVendor(vendor) {
					continue
				}
				version := strings.TrimSpace(cand.pkg.Version)
				bounds := rangeBounds{startIncl: si, startExcl: se, endIncl: ei, endExcl: ee}
				upstreamIn := matchRangeDual(version, bounds, compareUpstream)
				revisionIn := matchRangeDual(version, bounds, compareRevision)
				distro := hasDistroSuffix(version)
				fuzzy := packageNeedsManual(cand.pkg.Name, product)
				eraOld := cveEraTooOld(published)

				// 四态：affected / needs_manual / not_affected / unknown。
				// needs_manual 表示"版本落在区间，但这里有不确定因素，必须人看"：
				// 两种比较器打架、版本带发行版修订、包名与产品名对不上、CVE 年代过久。
				status := "not_affected"
				needsPatch := false
				switch {
				case !upstreamIn && !revisionIn:
					status = "not_affected"
				case upstreamIn != revisionIn:
					status = "needs_manual"
					needsPatch = distro
				case distro:
					status = "needs_manual"
					needsPatch = true
				case fuzzy || eraOld:
					status = "needs_manual"
				default:
					status = "affected"
				}
				key := strings.ToLower(strings.TrimSpace(cand.pkg.Name)) + "|" + cveID + "|" + version
				entry := PackageMatch{
					Package: cand.pkg, CVEID: cveID, Severity: severity, KEV: kev, EPSS: epss,
					Status: status, MatchedProduct: product,
					Range:           formatRange(si, se, ei, ee),
					NeedsPatchCheck: needsPatch,
					PatchedVersion:  patched,
				}
				if idx, ok := seen[key]; ok {
					// 同一个包对同一 CVE 可能命中多条区间：状态取"更强"的那个。
					if packageMatchRank(entry.Status) > packageMatchRank(out[idx].Status) {
						out[idx] = entry
					} else if entry.NeedsPatchCheck {
						out[idx].NeedsPatchCheck = true
					}
					continue
				}
				seen[key] = len(out)
				out = append(out, entry)
			}
		}
		rows.Close()
	}

	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := packageMatchRank(out[i].Status), packageMatchRank(out[j].Status)
		if ri != rj {
			return ri > rj
		}
		if out[i].KEV != out[j].KEV {
			return out[i].KEV
		}
		ei, ej := 0.0, 0.0
		if out[i].EPSS != nil {
			ei = *out[i].EPSS
		}
		if out[j].EPSS != nil {
			ej = *out[j].EPSS
		}
		return ei > ej
	})
	return out, nil
}

// productCandidates 由包名推导可能的 CPE product 名（全部小写、去重）。
//
// 规则刻意保守：只按分隔符截断，不做任意子串匹配——
// `openssh-client` → {openssh-client, openssh}；`@scope/pkg` → {@scope/pkg, pkg}；
// `gitlab` 不会产生 `git`，`7-zip` 不会产生 `zip`。
func productCandidates(name string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil
	}
	set := map[string]bool{name: true}
	if i := strings.LastIndex(name, "/"); i >= 0 && i+1 < len(name) {
		set[name[i+1:]] = true
	}
	parts := strings.Split(name, "-")
	for i := 1; i < len(parts); i++ {
		if cand := strings.Join(parts[:i], "-"); cand != "" {
			set[cand] = true
		}
	}
	if strings.HasPrefix(name, "lib") && len(name) > 5 {
		if cand := strings.TrimPrefix(name, "lib"); cand != "" {
			set[cand] = true
		}
	}
	// 显式排除：linux-base 不是内核、python3-xxx 不是 CPython。
	for _, denied := range denyProductByPackage[name] {
		delete(set, strings.ToLower(denied))
	}
	// 语言生态包（python3-requests 这类）一律不映射到解释器本体。
	if strings.HasPrefix(name, "python3-") || strings.HasPrefix(name, "python-") {
		for _, p := range []string{"python", "python2", "python3"} {
			delete(set, p)
		}
	}
	// 同理：ruby-sdbm 是 gem，不是 ruby 解释器；rubygems-* 也不是 rubygems 本体。
	if strings.HasPrefix(name, "ruby-") || strings.HasPrefix(name, "rubygems") {
		for _, p := range []string{"ruby", "gem", "rubygems"} {
			delete(set, p)
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func formatRange(si, se, ei, ee string) string {
	parts := []string{}
	if si != "" {
		parts = append(parts, ">="+si)
	}
	if se != "" {
		parts = append(parts, ">"+se)
	}
	if ei != "" {
		parts = append(parts, "<="+ei)
	}
	if ee != "" {
		parts = append(parts, "<"+ee)
	}
	return strings.Join(parts, " ")
}

func scanVulnIntel(scanner interface {
	Scan(dest ...interface{}) error
}) (*VulnIntel, error) {
	rec := &VulnIntel{}
	var cvss, epss, pct sql.NullFloat64
	var published, modified, kevAdded, epssAt, source, refs, cwes sql.NullString
	var created, updated time.Time
	err := scanner.Scan(&rec.CVEID, &rec.Title, &rec.Description, &rec.Severity, &cvss, &rec.CVSSVector,
		&published, &modified, &rec.KEV, &kevAdded, &epss, &pct, &epssAt, &source, &refs, &cwes, &created, &updated)
	if err != nil {
		return nil, err
	}
	if cvss.Valid {
		v := cvss.Float64
		rec.CVSSScore = &v
	}
	if epss.Valid {
		v := epss.Float64
		rec.EPSS = &v
	}
	if pct.Valid {
		v := pct.Float64
		rec.EPSSPercentile = &v
	}
	rec.PublishedAt = published.String
	rec.ModifiedAt = modified.String
	rec.KEVAddedAt = kevAdded.String
	rec.EPSSUpdatedAt = epssAt.String
	rec.Source = source.String
	if refs.String != "" {
		rec.Refs = strings.Split(refs.String, "\n")
	}
	if cwes.String != "" {
		rec.CWEs = strings.Split(cwes.String, ",")
	}
	rec.CreatedAt = created
	rec.UpdatedAt = updated
	return rec, nil
}


// normalizeSeverity 统一严重度取值：GHSA 的 MODERATE 归一到 MEDIUM，未知归 NONE。
func normalizeSeverity(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "":
		return ""
	default:
		return "NONE"
	}
}

func startsWithDigit(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c >= '0' && c <= '9'
}


// normalizeRangeSource 统一区间来源标记（空值按 nvd 处理，与删除口径保持一致）。
func normalizeRangeSource(src string) string {
	if v := strings.ToLower(strings.TrimSpace(src)); v != "" {
		return v
	}
	return "nvd"
}

// NormalizeEcosystem 把各来源的生态写法收敛成同一套键。
//
// 必要性：GitHub 写 "pip"/"rust"/"composer"，OSV 转储目录写 "PyPI"/"crates.io"/"Packagist"，
// 主机清单写 "pip"/"npm"/"gem"。不归一化的话，GHSA 的 pip 区间永远匹配不到 pip 包。
func NormalizeEcosystem(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pip", "pypi", "python":
		return "pypi"
	case "npm", "node", "nodejs":
		return "npm"
	case "rubygems", "gem", "ruby":
		return "rubygems"
	case "go", "gomod", "golang":
		return "go"
	case "crates.io", "cargo", "rust", "crates":
		return "crates.io"
	case "packagist", "composer", "php":
		return "packagist"
	case "maven", "java":
		return "maven"
	case "nuget", "dotnet":
		return "nuget"
	}
	return strings.ToLower(strings.TrimSpace(s))
}
