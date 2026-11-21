package vulnintel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"trail/internal/database"
)

// Summary 是一次同步的结果概览。
type Summary struct {
	KEV   int      `json:"kev"`
	NVD   int      `json:"nvd"`
	EPSS  int      `json:"epss"`
	GHSA  int      `json:"ghsa"`
	OSV   int      `json:"osv"`
	POC   int      `json:"poc"`
	Errors []string `json:"errors,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Syncer 执行一次同步。单源失败不影响其它源，错误汇总后一起返回。
type Syncer struct {
	db   *database.DB
	cfg  Config
	c    *client
	logf func(format string, args ...interface{})
}

// New 构造同步器。
func New(db *database.DB, cfg Config, logf func(string, ...interface{})) *Syncer {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &Syncer{db: db, cfg: cfg, c: newClient(cfg), logf: logf}
}

// Run 执行一次完整同步。
func (s *Syncer) Run(ctx context.Context) (Summary, error) {
	sum := Summary{StartedAt: time.Now()}
	if s.cfg.MaxRuntime <= 0 {
		s.cfg.MaxRuntime = 30 * time.Minute
	}
	deadline := time.Now().Add(s.cfg.MaxRuntime)
	if d, ok := ctx.Deadline(); !ok || d.After(deadline) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	var errs []error
	if err := s.syncKEV(ctx, &sum); err != nil {
		s.logf("[vulnintel] KEV 同步失败: %v", err)
		errs = append(errs, fmt.Errorf("kev: %w", err))
	}
	if s.cfg.EPSSEnabled {
		if err := s.syncEPSS(ctx, &sum); err != nil {
			s.logf("[vulnintel] EPSS 同步失败: %v", err)
			errs = append(errs, fmt.Errorf("epss: %w", err))
		}
	}
	if s.cfg.nvdOn() {
		if err := s.syncNVD(ctx, &sum); err != nil {
			s.logf("[vulnintel] NVD 同步失败: %v", err)
			errs = append(errs, fmt.Errorf("nvd: %w", err))
		}
	}
	if s.cfg.GHSAEnabled {
		if err := s.syncGHSA(ctx, &sum); err != nil {
			s.logf("[vulnintel] GHSA 同步失败: %v", err)
			errs = append(errs, fmt.Errorf("ghsa: %w", err))
		}
	}
	if s.cfg.OSVEnabled {
		if n, err := s.syncOSV(ctx); err != nil {
			s.logf("[vulnintel] OSV 导入失败: %v", err)
			errs = append(errs, fmt.Errorf("osv: %w", err))
		} else {
			sum.OSV = n
		}
	}
	if s.cfg.POCEnabled {
		if err := s.syncPoCs(ctx, &sum); err != nil {
			s.logf("[vulnintel] PoC 同步失败: %v", err)
			errs = append(errs, fmt.Errorf("poc: %w", err))
		}
	}

	sum.FinishedAt = time.Now()
	for _, e := range errs {
		sum.Errors = append(sum.Errors, e.Error())
	}
	return sum, errors.Join(errs...)
}

// ---------- KEV ----------

func (s *Syncer) syncKEV(ctx context.Context, sum *Summary) error {
	cat, err := fetchKEV(ctx, s.c, s.cfg.kevURL())
	if err != nil {
		_ = s.recordError("kev", err)
		return err
	}
	// 全量覆盖：先清标记，再按目录打标（条目被移除时不会残留）。
	if err := s.db.ClearKEV(); err != nil {
		_ = s.recordError("kev", err)
		return err
	}
	marked := 0
	var markErr error
	for _, v := range cat.Vulnerabilities {
		if ctx.Err() != nil {
			markErr = ctx.Err()
			break
		}
		added, _ := time.Parse("2006-01-02", strings.TrimSpace(v.DateAdded))
		if err := s.db.UpsertKEVEntry(database.KEVEntry{
			CVEID: v.CVEID, DateAdded: added,
			Vendor: v.VendorProject, Product: v.Product,
			Name: v.VulnerabilityName, Description: v.ShortDescription,
			RequiredAction: v.RequiredAction, DueDate: v.DueDate,
			KnownRansomwareCampaignUse: strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known"),
		}); err != nil {
			markErr = err
			continue
		}
		marked++
	}
	sum.KEV = marked
	if markErr != nil {
		// 标记不完整时如实记录，不把"清空后只补了一半"当成成功。
		_ = s.saveState("kev", cat.DateReleased, marked, markErr.Error())
		return markErr
	}
	return s.saveState("kev", cat.DateReleased, marked, "")
}

// ---------- EPSS ----------

func (s *Syncer) syncEPSS(ctx context.Context, sum *Summary) error {
	const pageSize = 10000
	updated := 0
	latestDate := ""
	state, err := s.db.GetVulnIntelSync("epss")
	if err != nil {
		return err
	}
	offset := 0
	completed := false
	if state.Cursor != "" {
		if n, convErr := strconv.Atoi(state.Cursor); convErr == nil && n > 0 {
			offset = n
		}
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		page, err := fetchEPSSPage(ctx, s.c, s.cfg.epssBase(), offset, pageSize)
		if err != nil {
			_ = s.recordError("epss", err)
			return err
		}
		if len(page.Data) == 0 {
			break
		}
		for _, row := range page.Data {
			score, err1 := parseFloat(row.EPSS)
			pct, err2 := parseFloat(row.Percentile)
			if err1 != nil || err2 != nil {
				continue
			}
			at, _ := time.Parse("2006-01-02", strings.TrimSpace(row.Date))
			if err := s.db.UpdateEPSS(row.CVE, score, pct, at); err != nil {
				continue
			}
			updated++
			if row.Date > latestDate {
				latestDate = row.Date
			}
		}
		offset += len(page.Data)
		// cursor 记 offset：被截断后从断点继续，而不是每次从 0 重来
		if err := s.saveState("epss", strconv.Itoa(offset), len(page.Data), ""); err != nil {
			return err
		}
		if offset >= page.Total {
			completed = true
			break
		}
	}
	sum.EPSS = updated
	// 只有"确实翻到末尾"才重置 offset：否则（首页为空、快照缩小、cursor 被写大）
	// 会每轮只发一个请求且写 0 条，形成静默停摆。
	if completed {
		return s.saveState("epss", "0", 0, "")
	}
	return nil
}

// ---------- NVD ----------

// syncNVD 按 lastModified 增量拉取；首跑从 1988 年起回填。
// 游标按"完成的窗口"推进，运行被 MaxRuntime 截断时下次从下一个窗口继续。
func (s *Syncer) syncNVD(ctx context.Context, sum *Summary) error {
	state, err := s.db.GetVulnIntelSync("nvd")
	if err != nil {
		return err
	}
	now := time.Now()
	var from time.Time
	if state.Cursor != "" {
		if t, e := time.Parse(time.RFC3339, state.Cursor); e == nil {
			from = t.Add(-24 * time.Hour) // 回退吸收 NVD 侧索引延迟
		}
	}
	if from.IsZero() && s.cfg.BackfillDays > 0 {
		from = now.AddDate(0, 0, -s.cfg.BackfillDays)
	}
	if from.IsZero() {
		from = time.Date(1988, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	total := 0
	for from.Before(now) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		to := from.AddDate(0, 0, 120)
		if to.After(now) {
			to = now
		}
		n, err := fetchNVDWindow(ctx, s.c, s.cfg.nvdBase(), s.cfg.NVDAPIKey, from, to, 2000, func(batch []nvdCVE) error {
			for _, v := range batch {
				intel, ranges := nvdToIntel(v)
				if intel.CVEID == "" {
					continue
				}
				if err := s.db.UpsertVulnIntel(intel, ranges); err != nil {
					s.logf("[vulnintel] 写入 %s 失败: %v", intel.CVEID, err)
				}
			}
			return nil
		})
		if err != nil {
			_ = s.recordError("nvd", err)
			// 已拉到的窗口仍然保留，游标停在 from（下次重试本窗口）
			return err
		}
		total += n
		if err := s.saveState("nvd", to.UTC().Format(time.RFC3339), total, ""); err != nil {
			return err
		}
		from = to
	}
	sum.NVD = total
	return nil
}

// ---------- GHSA ----------

func (s *Syncer) syncGHSA(ctx context.Context, sum *Summary) error {
	state, err := s.db.GetVulnIntelSync("ghsa")
	if err != nil {
		return err
	}
	var since time.Time
	if state.Cursor != "" {
		since, _ = time.Parse(time.RFC3339, state.Cursor)
	}
	if since.IsZero() {
		days := s.cfg.BackfillDays
		if days <= 0 {
			days = 30
		}
		since = time.Now().AddDate(0, 0, -days)
	}

	total := 0
	for page := 1; page <= 20; page++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		items, skipped, err := fetchGHSA(ctx, s.c, s.cfg.githubBase(), s.cfg.GitHubToken, since, page, 100)
		if err != nil {
			_ = s.recordError("ghsa", err)
			return err
		}
		if skipped > 0 {
			// 形状不认识的公告只跳过这一条：不能让一页里的个别脏数据把整轮同步打回原点。
			s.logf("ghsa: 本页跳过 %d 条无法解析的公告", skipped)
		}
		if len(items) == 0 {
			break
		}
		for _, a := range items {
			intel, ranges, ok := ghsaToIntel(a)
			if !ok {
				continue
			}
			if err := s.db.UpsertVulnIntel(intel, ranges); err != nil {
				continue
			}
			total++
		}
		if len(items) < 100 {
			break
		}
	}
	sum.GHSA = total
	// cursor 只在整轮翻页完成后推进：否则被 MaxRuntime 截断时，
	// since 已前移但中间页没拉到，会永久漏掉那段公告。
	return s.saveState("ghsa", time.Now().UTC().Format(time.RFC3339), total, "")
}

// ---------- PoC ----------

// syncPoCs 只为 KEV 条目聚合公开 PoC（全库 40 万条 × 1 次搜索既不可行也没意义）。
func (s *Syncer) syncPoCs(ctx context.Context, sum *Summary) error {
	hits, _, err := s.db.SearchVulnIntel(database.VulnIntelFilter{KEVOnly: true, Limit: 50})
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(hits))
	for _, h := range hits {
		ids = append(ids, h.CVEID)
	}
	sort.Strings(ids)
	found := 0
	for _, cve := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pocs, err := fetchPoC(ctx, s.c, s.cfg.githubBase(), s.cfg.GitHubToken, cve)
		if err != nil {
			// 单条失败不终止整轮
			s.logf("[vulnintel] 查询 %s 的 PoC 失败: %v", cve, err)
			continue
		}
		if len(pocs) == 0 {
			continue
		}
		if err := s.db.UpsertVulnIntelPOCs(pocs); err != nil {
			continue
		}
		found += len(pocs)
		if found%10 == 0 {
			if err := s.saveState("poc", time.Now().UTC().Format(time.RFC3339), 10, ""); err != nil {
				return err
			}
		}
	}
	sum.POC = found
	return s.saveState("poc", time.Now().UTC().Format(time.RFC3339), 0, "")
}

// ---------- 状态 ----------

func (s *Syncer) saveState(source, cursor string, total int, lastErr string) error {
	st, err := s.db.GetVulnIntelSync(source)
	if err != nil {
		return err
	}
	if cursor != "" {
		st.Cursor = cursor
	}
	if total > 0 {
		st.TotalSynced += total
	}
	st.LastSyncAt = time.Now().UTC().Format(time.RFC3339)
	st.LastError = lastErr
	st.Enabled = true
	return s.db.SaveVulnIntelSync(st)
}

func (s *Syncer) recordError(source string, cause error) error {
	st, err := s.db.GetVulnIntelSync(source)
	if err != nil {
		return err
	}
	st.LastError = cause.Error()
	st.Enabled = true
	return s.db.SaveVulnIntelSync(st)
}

func parseFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var f float64
	_, err := fmt.Sscanf(s, "%g", &f)
	return f, err
}
