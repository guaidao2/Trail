package threatintel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"trail/internal/database"
)

const defaultFeodoURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

// FeodoTracker 是免 Key 的 C2 IP 列表，误报极低：里面每一条都是已确认的
// 银行木马 / 加载器 C2。它比网段类源更适合直接做命中告警。
type FeodoTracker struct {
	doer *HTTPDoer
	url  string
}

// NewFeodoTracker 构造 Feodo Tracker 源。
func NewFeodoTracker(doer *HTTPDoer, endpoint string) *FeodoTracker {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = defaultFeodoURL
	}
	return &FeodoTracker{doer: doer, url: strings.TrimSpace(endpoint)}
}

func (p *FeodoTracker) Name() string { return "feodo" }

func (p *FeodoTracker) RequiresKey() bool { return false }

// Fetch 拉取 C2 IP 列表。实测格式：注释行以 # 开头，数据行每行一个 IP。
func (p *FeodoTracker) Fetch(ctx context.Context, _ string) ([]database.ThreatIntelFeedEntry, error) {
	status, body, err := p.doer.getRaw(ctx, p.url, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("feodo 返回 HTTP %d", status)
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	entries := make([]database.ThreatIntelFeedEntry, 0, 256)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 只收合法 IP，避免把格式变化后的说明文字当成指标入库。
		if net.ParseIP(line) == nil {
			continue
		}
		entries = append(entries, database.ThreatIntelFeedEntry{
			Source:        p.Name(),
			IndicatorType: "ip",
			Normalized:    line,
			Category:      "c2",
			Malware:       "Feodo Tracker C2",
			Confidence:    95,
			FetchedAt:     now,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 feodo 列表失败: %w", err)
	}
	// 列表可能为空（当天没有在线的 C2），这是合法状态，不当错误。
	return entries, nil
}
