package vulnintel

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"trail/internal/database"
)

// OSV 生态转储导入。
//
// 为什么要有这条路：GHSA 只带语言生态的 advisory，而 GitHub 的列表接口是增量的
// （最多回看 30 天），历史 advisory 拉不到；OSV 是 GHSA 的上游，且按生态提供全量快照：
//
//	https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip
//
// 关键价值是"包名、生态、版本三者自洽"：语言包实现精确匹配靠的就是这里的
// (ecosystem, package name)，不经过 NVD 的 CPE 产品名推导。

// osvArchiveBase 是 OSV 官方转储地址，可在配置里覆盖（内网镜像）。
const osvArchiveBase = "https://osv-vulnerabilities.storage.googleapis.com"

// osvEcosystem 是 OSV 转储目录名与内部生态键的对应关系。
// 只收语言生态：OS 发行版（Debian/Alpine/Ubuntu）已由 NVD 的 CPE 路径覆盖，
// 再导一份只会和 dpkg/rpm 的匹配打对台。
type osvEcosystem struct {
	Archive  string // 转储目录名，如 PyPI
	Key      string // 内部生态键（小写），与 ecosystemBySource 对齐
	Label    string
	Estimate int64 // 粗略体积（MB），仅用于日志
}

var osvEcosystems = []osvEcosystem{
	{Archive: "PyPI", Key: "pypi", Label: "PyPI"},
	{Archive: "npm", Key: "npm", Label: "npm"},
	{Archive: "Go", Key: "go", Label: "Go"},
	{Archive: "RubyGems", Key: "rubygems", Label: "RubyGems"},
	{Archive: "crates.io", Key: "crates.io", Label: "crates.io"},
	{Archive: "Packagist", Key: "packagist", Label: "Packagist"},
	{Archive: "Maven", Key: "maven", Label: "Maven"},
	{Archive: "NuGet", Key: "nuget", Label: "NuGet"},
}

// OSVArchiveURL 返回某生态全量包的地址。
func OSVArchiveURL(base, archive string) string {
	if strings.TrimSpace(base) == "" {
		base = osvArchiveBase
	}
	return strings.TrimRight(base, "/") + "/" + archive + "/all.zip"
}

// OSEcosystems 暴露给调用方（日志/统计）。
func OSEcosystems() []string {
	out := make([]string, 0, len(osvEcosystems))
	for _, e := range osvEcosystems {
		out = append(out, e.Label)
	}
	return out
}

// osvEvent 是 OSV 版本区间的单个事件。
type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// osvPair 是一条可比较的区间。
type osvPair struct {
	startIncl string
	endExcl   string
	endIncl   string
}

// osvEventPairs 把事件序列拆成多条区间。
//
// 一个 range 里可能有多个 (introduced, fixed) 对，例如
// [{introduced:"0"},{fixed:"1.2"},{introduced:"1.4"}]：
// 直接"取最后一个 introduced + 最后一个 fixed"会得到 1.4 ≤ v < 1.2 的倒置区间，
// 任何版本都匹配不上，真受影响的 1.1 会被判成安全。
func osvEventPairs(events []osvEvent) []osvPair {
	out := []osvPair{}
	cur := osvPair{}
	open := false
	for _, ev := range events {
		if v := strings.TrimSpace(ev.Introduced); v != "" {
			if open {
				out = append(out, cur)
			}
			cur = osvPair{}
			if !strings.EqualFold(v, "0") {
				cur.startIncl = v
			}
			open = true
			continue
		}
		if !open {
			continue
		}
		if v := strings.TrimSpace(ev.Fixed); v != "" {
			cur.endExcl = v
			out = append(out, cur)
			open = false
			continue
		}
		if v := strings.TrimSpace(ev.LastAffected); v != "" {
			cur.endIncl = v
			out = append(out, cur)
			open = false
		}
	}
	if open {
		out = append(out, cur)
	}
	// 丢掉完全空的区间（既无下界也无上界）
	res := make([]osvPair, 0, len(out))
	for _, p := range out {
		if p.startIncl != "" || p.endExcl != "" || p.endIncl != "" {
			res = append(res, p)
		}
	}
	return res
}

// osvAdvisory 是 OSV 单条 advisory（只声明用得到的字段）。
type osvAdvisory struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string     `json:"type"`
			Events []osvEvent `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// osvToIntel 把一条 OSV advisory 转成漏洞情报。
//
// 编号优先用 CVE 别名（与 NVD/EPSS/KEV 对齐），没有则用 OSV 自己的 ID（GHSA-/PYSEC- 等）。
func osvToIntel(a osvAdvisory, ecoKey string) (database.VulnIntel, []database.VulnIntelRange, bool) {
	id := ""
	for _, alias := range a.Aliases {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(alias)), "CVE-") {
			id = strings.ToUpper(strings.TrimSpace(alias))
			break
		}
	}
	if id == "" {
		id = strings.ToUpper(strings.TrimSpace(a.ID))
	}
	if id == "" {
		return database.VulnIntel{}, nil, false
	}

	ranges := []database.VulnIntelRange{}
	for _, aff := range a.Affected {
		name := strings.ToLower(strings.TrimSpace(aff.Package.Name))
		if name == "" {
			continue
		}
		eco := database.NormalizeEcosystem(aff.Package.Ecosystem)
		if eco == "" {
			eco = database.NormalizeEcosystem(ecoKey)
		}
		for _, r := range aff.Ranges {
			// 只取版本区间型；GIT 区间用的是 commit，无法与包版本比较。
			if !strings.EqualFold(r.Type, "ECOSYSTEM") && !strings.EqualFold(r.Type, "SEMVER") {
				continue
			}
			for _, pair := range osvEventPairs(r.Events) {
				ranges = append(ranges, database.VulnIntelRange{
					Vendor:    eco,
					Product:   name,
					Criteria:  strings.TrimSpace(a.ID) + " " + name,
					StartIncl: pair.startIncl,
					EndExcl:   pair.endExcl,
					EndIncl:   pair.endIncl,
					Source:    "osv",
				})
			}
		}
	}
	if len(ranges) == 0 {
		return database.VulnIntel{}, nil, false
	}

	severity := strings.ToUpper(strings.TrimSpace(a.DatabaseSpecific.Severity))
	if severity == "" {
		severity = osvSeverityFromCVSS(a.Severity)
	}
	refs := []string{}
	for _, r := range a.References {
		if u := strings.TrimSpace(r.URL); u != "" && len(refs) < 20 {
			refs = append(refs, u)
		}
	}
	title := strings.TrimSpace(a.Summary)
	if title == "" {
		title = firstLine(a.Details)
	}
	desc := strings.TrimSpace(a.Details)
	if desc == "" {
		desc = a.Summary
	}
	return database.VulnIntel{
		CVEID:       id,
		Title:       truncate(title, 200),
		Description: desc,
		Severity:    severity,
		PublishedAt: strings.TrimSpace(a.Published),
		ModifiedAt:  strings.TrimSpace(a.Modified),
		Source:      "osv",
		Refs:        refs,
	}, ranges, true
}

func osvSeverityFromCVSS(items []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, s := range items {
		score := parseCVSSVectorScore(s.Score)
		if score <= 0 {
			continue
		}
		switch {
		case score >= 9.0:
			return "CRITICAL"
		case score >= 7.0:
			return "HIGH"
		case score >= 4.0:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}
	return ""
}

// parseCVSSVectorScore 从 "CVSS:3.1/AV:N/.../9.8" 这类向量里取基础分。
// OSV 的 score 字段可能是向量，也可能是纯数字。
func parseCVSSVectorScore(score string) float64 {
	s := strings.TrimSpace(score)
	if s == "" {
		return 0
	}
	if f, err := parseFloat(s); err == nil {
		return f
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		if f, err := parseFloat(strings.TrimSpace(s[i+1:])); err == nil {
			return f
		}
	}
	return 0
}

func firstLine(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			return t
		}
	}
	return ""
}

// importOSVArchive 下载并导入某个生态的全量包。
//
// 逐条解析：单条 advisory 结构异常只跳过该条，不打断整包导入
// （Osv 的库很大，一条脏数据不该让整轮白跑）。
func (s *Syncer) importOSVArchive(ctx context.Context, eco osvEcosystem) (imported, skipped int, err error) {
	url := OSVArchiveURL(s.cfg.OSVBaseURL, eco.Archive)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	// 转储体积可能上百 MB，不能用带 90s 总超时的共享 client（它会连带响应体读取一起掐断）；
	// 这里只借用 Transport，超时交给 ctx。
	dl := &http.Client{Transport: s.c.http.Transport}
	resp, err := dl.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("下载 %s 失败: %w", eco.Label, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("下载 %s 失败: HTTP %d", eco.Label, resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "osv-*-"+sanitizeFile(eco.Key)+".zip")
	if err != nil {
		return 0, 0, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	size, err := io.Copy(tmp, resp.Body)
	tmp.Close()
	if err != nil {
		return 0, 0, fmt.Errorf("保存 %s 转储失败: %w", eco.Label, err)
	}
	s.logf("osv: %s 转储 %.1f MB", eco.Label, float64(size)/(1<<20))

	zr, err := zip.OpenReader(tmpPath)
	if err != nil {
		return 0, 0, fmt.Errorf("打开 %s 转储失败: %w", eco.Label, err)
	}
	defer zr.Close()

	writeFails := 0
	for _, f := range zr.File {
		if ctx.Err() != nil {
			return imported, skipped, ctx.Err()
		}
		if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			skipped++
			continue
		}
		raw, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr != nil {
			skipped++
			continue
		}
		var adv osvAdvisory
		if err := json.Unmarshal(raw, &adv); err != nil {
			skipped++
			continue
		}
		intel, ranges, ok := osvToIntel(adv, eco.Key)
		if !ok {
			skipped++
			continue
		}
		if err := s.db.UpsertVulnIntel(intel, ranges); err != nil {
			skipped++
			writeFails++
			if writeFails <= 3 {
				s.logf("osv: %s 写入失败（%s）: %v", eco.Label, intel.CVEID, err)
			}
			continue
		}
		imported++
	}
	return imported, skipped, nil
}

func sanitizeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// syncOSV 依次导入各生态全量包；游标记录"已完成的生态"，中断后可续。
func (s *Syncer) syncOSV(ctx context.Context) (int, error) {
	state, err := s.db.GetVulnIntelSync("osv")
	if err != nil {
		return 0, err
	}
	done := map[string]bool{}
	// 手动触发时忽略游标：OSV 是"全量快照"，增量语义不适用；
	// 只靠游标的话，首轮成功后就永久空转，后续新增 advisory 永远不会进来。
	force := s.cfg.OSVForce
	if !force && state.LastSyncAt != "" {
		// 快照有保质期：超过 7 天就重导一遍，否则自动同步永远拿不到新增 advisory。
		if ts, err := time.Parse(time.RFC3339, state.LastSyncAt); err == nil && time.Since(ts) > 7*24*time.Hour {
			force = true
		}
	}
	if !force {
		for _, name := range strings.Split(state.Cursor, ",") {
			if n := strings.TrimSpace(name); n != "" {
				done[n] = true
			}
		}
	}
	total, skippedTotal := 0, 0
	for _, eco := range osvEcosystems {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		if done[eco.Key] {
			continue
		}
		imported, skipped, err := s.importOSVArchive(ctx, eco)
		total += imported
		skippedTotal += skipped
		if err != nil {
			_ = s.recordError("osv", err)
			return total, err
		}
		done[eco.Key] = true
		cursor := make([]string, 0, len(done))
		for _, e := range osvEcosystems {
			if done[e.Key] {
				cursor = append(cursor, e.Key)
			}
		}
		_ = s.db.SaveVulnIntelSync(database.VulnIntelSyncState{
			Source: "osv", Cursor: strings.Join(cursor, ","),
			LastSyncAt: time.Now().UTC().Format(time.RFC3339),
			TotalSynced: imported, Enabled: true,
		})
		s.logf("osv: %s 导入 %d 条（跳过 %d）", eco.Label, imported, skipped)
	}
	s.logf("osv: 本轮共导入 %d 条，跳过 %d 条", total, skippedTotal)
	return total, nil
}
