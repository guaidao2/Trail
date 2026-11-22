package threatintel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"trail/internal/database"
)

const defaultSpamhausDropURL = "https://www.spamhaus.org/drop/drop.txt"

// SpamhausDROP 是免 Key 的网段级订阅源：已知被控网段。
// 它给的是 CIDR 而不是单个 IP，落地时按 cidr 类型存，匹配时由上层做网段判断。
type SpamhausDROP struct {
	doer *HTTPDoer
	url  string
}

// NewSpamhausDROP 构造 Spamhaus DROP 源。
func NewSpamhausDROP(doer *HTTPDoer, endpoint string) *SpamhausDROP {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = defaultSpamhausDropURL
	}
	return &SpamhausDROP{doer: doer, url: strings.TrimSpace(endpoint)}
}

func (p *SpamhausDROP) Name() string { return "spamhaus_drop" }

func (p *SpamhausDROP) RequiresKey() bool { return false }

// Fetch 拉取 DROP 列表。实测格式：
//
//	; Spamhaus DROP List 2026/11/21 - (c) 2026 The Spamhaus Project SLU
//	1.10.16.0/20 ; SBL256894
func (p *SpamhausDROP) Fetch(ctx context.Context, _ string) ([]database.ThreatIntelFeedEntry, error) {
	status, body, err := p.doer.getRaw(ctx, p.url, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("spamhaus drop 返回 HTTP %d", status)
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	entries := make([]database.ThreatIntelFeedEntry, 0, 1024)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	// DROP 单行很短，但给足缓冲，避免异常行触发错误。
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// 形式为 "<cidr> ; <SBL 编号>"，注释列可能缺失。
		cidr := line
		sbl := ""
		if idx := strings.Index(line, ";"); idx >= 0 {
			cidr = strings.TrimSpace(line[:idx])
			sbl = strings.TrimSpace(line[idx+1:])
		}
		if cidr == "" {
			continue
		}
		entries = append(entries, database.ThreatIntelFeedEntry{
			Source:        p.Name(),
			IndicatorType: "cidr",
			Normalized:    cidr,
			Category:      "cidr",
			Confidence:    90,
			Tags:          sbl,
			FetchedAt:     now,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 spamhaus drop 失败: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("spamhaus drop 返回了 0 条记录，疑似内容异常")
	}
	return entries, nil
}
