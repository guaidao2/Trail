package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"trail/internal/database"
)

const defaultAbuseIPDBBase = "https://api.abuseipdb.com"

// AbuseIPDB 需要 Key（免费 1000 次/天）。它给的是"最近 90 天被多少人举报"，
// 和 GreyNoise 的扫描器分类互补：前者看举报量，后者看是否为全网噪声。
type AbuseIPDB struct {
	doer *HTTPDoer
	base string
}

// NewAbuseIPDB 构造 AbuseIPDB 源。
func NewAbuseIPDB(doer *HTTPDoer, base string) *AbuseIPDB {
	if strings.TrimSpace(base) == "" {
		base = defaultAbuseIPDBBase
	}
	return &AbuseIPDB{doer: doer, base: strings.TrimRight(strings.TrimSpace(base), "/")}
}

func (p *AbuseIPDB) Name() string { return "abuseipdb" }

func (p *AbuseIPDB) Category() string { return database.ThreatCategoryReputation }

func (p *AbuseIPDB) RequiresKey() bool { return true }

func (p *AbuseIPDB) Supports(indicatorType string) bool {
	return strings.EqualFold(indicatorType, "ip")
}

// DefaultDailyQuota / DefaultRateLimitPerMinute 是免费档的保守默认值，
// 避免默认配置下把客户一天的配额打光。
//
// 注意：两个方法必须同时实现，QuotaHint 是整体断言；只写一个会导致
// 类型断言失败且没有任何报错，配额就悄悄停在 0（不限量）。
func (p *AbuseIPDB) DefaultDailyQuota() int { return 1000 }

func (p *AbuseIPDB) DefaultRateLimitPerMinute() int { return 60 }

// abuseIPDBResponse 只取判定需要的字段。
type abuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		NumDistinctUsers     int    `json:"numDistinctUsers"`
		LastReportedAt       string `json:"lastReportedAt"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		UsageType            string `json:"usageType"`
	} `json:"data"`
	Errors []struct {
		Detail string `json:"detail"`
		Status int    `json:"status"`
	} `json:"errors"`
}

func (p *AbuseIPDB) Query(ctx context.Context, ind Indicator, key string) (*Result, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, ErrMissingKey
	}
	ip := strings.TrimSpace(ind.Normalized)
	if ip == "" {
		ip = strings.TrimSpace(ind.Value)
	}
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%w: abuseipdb 只接受 IP，收到 %q", ErrUnsupported, ind.Value)
	}

	url := p.base + "/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90"
	status, body, err := p.doer.getRaw(ctx, url, map[string]string{
		"Key":    key,
		"Accept": "application/json",
	})
	if err != nil {
		return nil, err
	}

	res := &Result{
		Source:        p.Name(),
		IndicatorType: "ip",
		Normalized:    ip,
		Category:      p.Category(),
		HTTPStatus:    status,
		Payload:       truncatePayload(body),
	}

	switch status {
	case 200:
		var data abuseIPDBResponse
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("解析 AbuseIPDB 响应失败: %w", err)
		}
		if !data.Data.IsPublic {
			res.Verdict = database.ThreatVerdictUnknown
			res.Summary = "AbuseIPDB 不覆盖非公网地址"
			res.ExpiresAt = expiryIn(12 * time.Hour)
			return res, nil
		}
		res.Verdict, res.Summary = classifyAbuseIPDB(data)
		res.ExpiresAt = expiryIn(6 * time.Hour)
	case 429:
		return nil, fmt.Errorf("abuseipdb 限速或配额用尽（HTTP 429）")
	default:
		var data abuseIPDBResponse
		_ = json.Unmarshal(body, &data)
		if len(data.Errors) > 0 {
			return nil, fmt.Errorf("abuseipdb 返回 HTTP %d：%s", status, data.Errors[0].Detail)
		}
		return nil, fmt.Errorf("abuseipdb 返回 HTTP %d", status)
	}
	return res, nil
}

func classifyAbuseIPDB(d abuseIPDBResponse) (verdict, summary string) {
	score := d.Data.AbuseConfidenceScore
	reports := d.Data.TotalReports
	switch {
	case score >= 75:
		line := fmt.Sprintf("AbuseIPDB 滥用置信度 %d%%，近 90 天被举报 %d 次", score, reports)
		if d.Data.LastReportedAt != "" {
			line += "，最后举报 " + d.Data.LastReportedAt
		}
		return database.ThreatVerdictMalicious, line
	case score >= 25:
		return database.ThreatVerdictSuspicious,
			fmt.Sprintf("AbuseIPDB 滥用置信度 %d%%，近 90 天被举报 %d 次", score, reports)
	case reports > 0:
		return database.ThreatVerdictClean,
			fmt.Sprintf("AbuseIPDB 有 %d 次历史举报，但置信度仅 %d%%", reports, score)
	default:
		line := "AbuseIPDB 近 90 天无滥用举报"
		if d.Data.CountryCode != "" {
			line += "（归属 " + d.Data.CountryCode + "，ISP " + d.Data.ISP + "）"
		}
		return database.ThreatVerdictClean, line
	}
}
