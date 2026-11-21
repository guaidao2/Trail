package vulnintel

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trail/internal/database"
)

// 各源端点（公开、无需私有凭据；NVD 与 GitHub 的 token 只用于提速）。
const (
	kevFeedURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	nvdAPIBase   = "https://services.nvd.nist.gov"
	epssAPIBase  = "https://api.first.org"
	githubAPIURL = "https://api.github.com"
)

// ---------- CISA KEV ----------

type kevCatalog struct {
	CatalogVersion string `json:"catalogVersion"`
	DateReleased   string `json:"dateReleased"`
	Count          int    `json:"count"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

// kevEntry 是 KEV 目录里的一条记录。目录本身带齐了厂商、产品、名称、
// 简述、修复动作与截止日期，这些信息不依赖 NVD 就能展示。
type kevEntry struct {
	CVEID                       string `json:"cveID"`
	DateAdded                   string `json:"dateAdded"`
	VendorProject               string `json:"vendorProject"`
	Product                     string `json:"product"`
	VulnerabilityName           string `json:"vulnerabilityName"`
	ShortDescription            string `json:"shortDescription"`
	RequiredAction              string `json:"requiredAction"`
	DueDate                     string `json:"dueDate"`
	KnownRansomwareCampaignUse  string `json:"knownRansomwareCampaignUse"`
}

// fetchKEV 拉取完整 KEV 目录（量小、信号最强，每次全量覆盖）。
func fetchKEV(ctx context.Context, c *client, feedURL string) (*kevCatalog, error) {
	var cat kevCatalog
	if err := c.getJSON(ctx, feedURL, nil, &cat); err != nil {
		return nil, err
	}
	if len(cat.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("KEV 目录为空（count=%d）", cat.Count)
	}
	return &cat, nil
}

// ---------- NVD 2.0 ----------

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []nvdMetric `json:"cvssMetricV31"`
		CvssMetricV30 []nvdMetric `json:"cvssMetricV30"`
		CvssMetricV2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// nvdWindowURL 组一个 120 天以内的增量窗口。
func nvdWindowURL(base string, from, to time.Time, startIndex, pageSize int) string {
	q := url.Values{}
	q.Set("lastModStartDate", from.UTC().Format("2006-01-02T15:04:05.000+00:00"))
	q.Set("lastModEndDate", to.UTC().Format("2006-01-02T15:04:05.000+00:00"))
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(pageSize))
	return strings.TrimRight(base, "/") + "/rest/json/cves/2.0?" + q.Encode()
}

// fetchNVDWindow 拉一个窗口的全部分页。
func fetchNVDWindow(ctx context.Context, c *client, base, apiKey string, from, to time.Time, pageSize int, onPage func([]nvdCVE) error) (int, error) {
	if pageSize <= 0 || pageSize > 2000 {
		pageSize = 2000
	}
	headers := map[string]string{}
	if key := strings.TrimSpace(apiKey); key != "" {
		headers["apiKey"] = key
	}
	total := 0
	for start := 0; ; {
		var resp nvdResponse
		if err := c.getJSON(ctx, nvdWindowURL(base, from, to, start, pageSize), headers, &resp); err != nil {
			return total, err
		}
		batch := make([]nvdCVE, 0, len(resp.Vulnerabilities))
		for _, v := range resp.Vulnerabilities {
			batch = append(batch, v.CVE)
		}
		if len(batch) == 0 {
			return total, nil
		}
		if err := onPage(batch); err != nil {
			return total, err
		}
		total += len(batch)
		start += len(batch)
		if start >= resp.TotalResults {
			return total, nil
		}
	}
}

// nvdToIntel 把一条 NVD 记录映射成存储层结构。
func nvdToIntel(v nvdCVE) (database.VulnIntel, []database.VulnIntelRange) {
	desc := ""
	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	severity, score, vector := "", (*float64)(nil), ""
	for _, metrics := range [][]nvdMetric{v.Metrics.CvssMetricV31, v.Metrics.CvssMetricV30, v.Metrics.CvssMetricV2} {
		if len(metrics) == 0 {
			continue
		}
		m := metrics[0]
		score = &m.CVSSData.BaseScore
		vector = m.CVSSData.VectorString
		severity = m.CVSSData.BaseSeverity
		if severity == "" {
			severity = m.BaseSeverity
		}
		break
	}
	cwes := []string{}
	for _, w := range v.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				cwes = append(cwes, d.Value)
			}
		}
	}
	refs := []string{}
	for _, r := range v.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	if len(refs) > 20 {
		refs = refs[:20]
	}
	ranges := []database.VulnIntelRange{}
	for _, cfg := range v.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				vendor, product := parseCPE(m.Criteria)
				ranges = append(ranges, database.VulnIntelRange{
					Vendor: vendor, Product: product, Criteria: m.Criteria,
					StartIncl: m.VersionStartIncluding, StartExcl: m.VersionStartExcluding,
					EndIncl: m.VersionEndIncluding, EndExcl: m.VersionEndExcluding,
					Source: "nvd",
				})
			}
		}
	}
	title := v.ID
	if desc != "" {
		title = truncate(strings.SplitN(desc, ".", 2)[0], 200)
	}
	return database.VulnIntel{
		CVEID: v.ID, Title: title, Description: desc,
		Severity: severity, CVSSScore: score, CVSSVector: vector,
		PublishedAt: v.Published, ModifiedAt: v.LastModified,
		Source: "nvd", Refs: refs, CWEs: cwes,
	}, ranges
}

// parseCPE 从 cpe:2.3:a:vendor:product:version:... 里取 vendor/product。
//
// CPE 2.3 允许组件里出现转义冒号（`vendor\:name`），所以不能直接按 ":" 切分。
func parseCPE(criteria string) (vendor, product string) {
	parts := splitUnescapedColons(criteria)
	if len(parts) < 5 {
		return "", ""
	}
	clean := func(s string) string {
		s = strings.ReplaceAll(s, "\\:", "\x00")
		s = strings.ReplaceAll(s, "\\\\", "\\")
		s = strings.ReplaceAll(s, "\x00", ":")
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "*" || s == "-" {
			return ""
		}
		return s
	}
	return clean(parts[3]), clean(parts[4])
}

// splitUnescapedColons 按未转义的冒号切分。
func splitUnescapedColons(s string) []string {
	out := []string{}
	var b strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			b.WriteRune(r)
			escaped = true
		case r == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	out = append(out, b.String())
	return out
}

// ---------- EPSS ----------

type epssResponse struct {
	Total int `json:"total"`
	Data  []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// fetchEPSSPage 拉一页 EPSS（每日全量，按 offset 翻页）。
func fetchEPSSPage(ctx context.Context, c *client, base string, offset, limit int) (*epssResponse, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	u := fmt.Sprintf("%s/data/v1/epss?limit=%d&offset=%d", strings.TrimRight(base, "/"), limit, offset)
	var resp epssResponse
	if err := c.getJSON(ctx, u, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ---------- GHSA ----------

type ghsaAdvisory struct {
	GHSAID    string `json:"ghsa_id"`
	CVEID     string `json:"cve_id"`
	Summary   string `json:"summary"`
	Severity  string `json:"severity"`
	Published string `json:"published_at"`
	Updated   string `json:"updated_at"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"vulnerabilities"`
	CWEs []struct {
		CWEID string `json:"cwe_id"`
	} `json:"cwes"`
}

// fetchGHSA 拉一页 GHSA 公告（since 之后，按发布顺序）。
func fetchGHSA(ctx context.Context, c *client, base, token string, since time.Time, page, perPage int) ([]ghsaAdvisory, error) {
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	q := url.Values{}
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))
	q.Set("direction", "asc")
	if !since.IsZero() {
		q.Set("since", since.UTC().Format(time.RFC3339))
	}
	headers := map[string]string{"X-GitHub-Api-Version": "2022-11-28"}
	if t := strings.TrimSpace(token); t != "" {
		headers["Authorization"] = "Bearer " + t
	}
	var out []ghsaAdvisory
	if err := c.getJSON(ctx, strings.TrimRight(base, "/")+"/advisories?"+q.Encode(), headers, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ghsaToIntel 把 GHSA 公告映射成存储层结构（没有 CVE 编号的公告跳过）。
// GHSA 的 vulnerable_version_range 是必填的，因此版本判定可信度更高。
func ghsaToIntel(a ghsaAdvisory) (database.VulnIntel, []database.VulnIntelRange, bool) {
	cve := strings.TrimSpace(a.CVEID)
	if cve == "" || len(a.Vulnerabilities) == 0 {
		return database.VulnIntel{}, nil, false
	}
	ranges := []database.VulnIntelRange{}
	for _, v := range a.Vulnerabilities {
		name := strings.ToLower(strings.TrimSpace(v.Package.Name))
		if name == "" {
			continue
		}
		startIncl, startExcl, endIncl, endExcl := parseGHSAVulnerableRange(v.VulnerableVersionRange)
		ranges = append(ranges, database.VulnIntelRange{
			Product:        name,
			Criteria:       a.GHSAID + " " + v.VulnerableVersionRange,
			StartIncl:      startIncl,
			StartExcl:      startExcl,
			EndIncl:        endIncl,
			EndExcl:        endExcl,
			Source:         "ghsa",
			PatchedVersion: strings.TrimSpace(v.FirstPatchedVersion.Identifier),
		})
	}
	if len(ranges) == 0 {
		return database.VulnIntel{}, nil, false
	}
	refs := []string{"https://github.com/advisories/" + strings.TrimSpace(a.GHSAID)}
	for _, r := range a.References {
		if r.URL != "" && len(refs) < 20 {
			refs = append(refs, r.URL)
		}
	}
	cwes := []string{}
	for _, c := range a.CWEs {
		if c.CWEID != "" {
			cwes = append(cwes, c.CWEID)
		}
	}
	return database.VulnIntel{
		CVEID: cve, Title: truncate(a.Summary, 200), Description: a.Summary,
		Severity: strings.ToUpper(strings.TrimSpace(a.Severity)),
		PublishedAt: a.Published, ModifiedAt: a.Updated,
		Source: "ghsa", Refs: refs, CWEs: cwes,
	}, ranges, true
}

// parseGHSAVulnerableRange 解析 ">= 1.0.0, < 1.2.3" 这类区间。
func parseGHSAVulnerableRange(raw string) (startIncl, startExcl, endIncl, endExcl string) {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, ">="):
			startIncl = strings.TrimSpace(strings.TrimPrefix(part, ">="))
		case strings.HasPrefix(part, ">"):
			startExcl = strings.TrimSpace(strings.TrimPrefix(part, ">"))
		case strings.HasPrefix(part, "<="):
			endIncl = strings.TrimSpace(strings.TrimPrefix(part, "<="))
		case strings.HasPrefix(part, "<"):
			endExcl = strings.TrimSpace(strings.TrimPrefix(part, "<"))
		case strings.HasPrefix(part, "="):
			v := strings.TrimSpace(strings.TrimPrefix(part, "="))
			startIncl, endIncl = v, v
		}
	}
	return
}

// ---------- PoC（GitHub 搜索）----------

type githubSearch struct {
	Items []struct {
		FullName        string `json:"full_name"`
		HTMLURL         string `json:"html_url"`
		StargazersCount int    `json:"stargazers_count"`
		UpdatedAt       string `json:"updated_at"`
	} `json:"items"`
}

// fetchPoC 为一个 CVE 搜公开 PoC 仓库（只取前几个，避免刷爆额度）。
func fetchPoC(ctx context.Context, c *client, base, token, cveID string) ([]database.VulnIntelPOC, error) {
	q := url.Values{}
	q.Set("q", cveID+" in:name,description,readme")
	q.Set("sort", "stars")
	q.Set("order", "desc")
	q.Set("per_page", "5")
	headers := map[string]string{"X-GitHub-Api-Version": "2022-11-28"}
	if t := strings.TrimSpace(token); t != "" {
		headers["Authorization"] = "Bearer " + t
	}
	var resp githubSearch
	if err := c.getJSON(ctx, strings.TrimRight(base, "/")+"/search/repositories?"+q.Encode(), headers, &resp); err != nil {
		return nil, err
	}
	out := []database.VulnIntelPOC{}
	for _, item := range resp.Items {
		if item.HTMLURL == "" {
			continue
		}
		out = append(out, database.VulnIntelPOC{
			CVEID: cveID, URL: item.HTMLURL, Repo: item.FullName,
			Stars: item.StargazersCount, UpdatedAt: item.UpdatedAt,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Stars > out[j].Stars })
	if len(out) > 5 {
		out = out[:5]
	}
	return out, nil
}
