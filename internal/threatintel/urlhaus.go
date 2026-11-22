package threatintel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"trail/internal/database"
)

// URLhaus 是恶意 URL 分发点的订阅源。abuse.ch 2025 年改版后必须带 Auth-Key：
//
//	https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv
//
// 旧路径 /downloads/csv_recent/ 已返回 410，不要再用。
type URLhaus struct {
	doer *HTTPDoer
	base string
}

// NewURLhaus 构造 URLhaus 源。
func NewURLhaus(doer *HTTPDoer, endpoint string) *URLhaus {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = "https://urlhaus-api.abuse.ch"
	}
	return &URLhaus{doer: doer, base: strings.TrimRight(strings.TrimSpace(endpoint), "/")}
}

func (p *URLhaus) Name() string { return "urlhaus" }

func (p *URLhaus) RequiresKey() bool { return true }

// exportURL 拼出带 key 的导出地址。
func (p *URLhaus) exportURL(key string) string {
	return p.base + "/v2/files/exports/" + key + "/recent.csv"
}

func (p *URLhaus) Fetch(ctx context.Context, key string) ([]database.ThreatIntelFeedEntry, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, ErrMissingKey
	}
	status, body, err := p.doer.getRaw(ctx, p.exportURL(key), nil)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, fmt.Errorf("urlhaus 拒绝了 Auth-Key（HTTP %d），请到 auth.abuse.ch 重新获取", status)
	}
	if status != 200 {
		return nil, fmt.Errorf("urlhaus 返回 HTTP %d", status)
	}

	records, err := parseCSVRecords(body)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("urlhaus 导出为空")
	}

	idx := csvHeaderIndex(records[0])
	// 表头必须能定位到 URL 列，否则说明格式变了，宁可报错也不入库垃圾。
	if _, ok := idx["url"]; !ok {
		return nil, fmt.Errorf("urlhaus 导出缺少 url 列，表头为: %v", records[0])
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	entries := make([]database.ThreatIntelFeedEntry, 0, len(records))
	for _, rec := range records[1:] {
		url := pick(rec, idx, "url")
		if url == "" {
			continue
		}
		// 与查询侧同口径：NormalizeIOCValue 会小写化并去掉 # 片段，
		// 入库不归一会导致大小写不同的同一个 URL 匹配不上订阅数据。
		normalized := database.NormalizeIOCValue("url", url)
		if normalized == "" {
			continue
		}
		entries = append(entries, database.ThreatIntelFeedEntry{
			Source:        p.Name(),
			IndicatorType: "url",
			Normalized:    normalized,
			Category:      "malware_url",
			Malware:       pick(rec, idx, "threat", "threat_type"),
			Confidence:    85,
			FirstSeen:     pick(rec, idx, "dateadded", "firstseen", "first_seen"),
			LastSeen:      pick(rec, idx, "last_online", "lastseen", "last_seen"),
			Tags:          pick(rec, idx, "tags"),
			FetchedAt:     now,
		})
	}
	return entries, nil
}
