package threatintel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"trail/internal/database"
)

const defaultVirusTotalBase = "https://www.virustotal.com"

// VirusTotal 需要 Key，免费额度 4 次/分、500 次/天，是所有源里最紧的。
// 所以它必须靠缓存和配额兜底：一次批量任务就能把一天的额度打光。
type VirusTotal struct {
	doer *HTTPDoer
	base string
}

// NewVirusTotal 构造 VirusTotal 源。
func NewVirusTotal(doer *HTTPDoer, base string) *VirusTotal {
	if strings.TrimSpace(base) == "" {
		base = defaultVirusTotalBase
	}
	return &VirusTotal{doer: doer, base: strings.TrimRight(strings.TrimSpace(base), "/")}
}

func (p *VirusTotal) Name() string { return "virustotal" }

func (p *VirusTotal) Category() string { return database.ThreatCategoryReputation }

func (p *VirusTotal) RequiresKey() bool { return true }

func (p *VirusTotal) Supports(indicatorType string) bool {
	switch strings.ToLower(strings.TrimSpace(indicatorType)) {
	case "ip", "domain", "md5", "sha1", "sha256", "url":
		return true
	}
	return false
}

// DefaultDailyQuota / DefaultRateLimitPerMinute 对应 VT 免费档：500/天、4/分。
func (p *VirusTotal) DefaultDailyQuota() int         { return 500 }
func (p *VirusTotal) DefaultRateLimitPerMinute() int { return 4 }

// vtResponse 只取判定需要的字段。
type vtResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Reputation int    `json:"reputation"`
			Country    string `json:"country"`
			ASOwner    string `json:"as_owner"`
			ASN        int    `json:"asn"`
			Meaningful string `json:"meaningful_name"`
		} `json:"attributes"`
	} `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (p *VirusTotal) Query(ctx context.Context, ind Indicator, key string) (*Result, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, ErrMissingKey
	}
	value := strings.TrimSpace(ind.Normalized)
	if value == "" {
		value = strings.TrimSpace(ind.Value)
	}
	path, err := vtPath(ind.Type, value)
	if err != nil {
		return nil, err
	}

	status, body, err := p.doer.getRaw(ctx, p.base+path, map[string]string{
		"x-apikey": key,
		"Accept":   "application/json",
	})
	if err != nil {
		return nil, err
	}

	res := &Result{
		Source:        p.Name(),
		IndicatorType: strings.ToLower(strings.TrimSpace(ind.Type)),
		Normalized:    value,
		Category:      p.Category(),
		HTTPStatus:    status,
		Payload:       truncatePayload(body),
	}

	switch status {
	case 200:
		var data vtResponse
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("解析 VirusTotal 响应失败: %w", err)
		}
		res.Verdict, res.Summary = classifyVirusTotal(data)
		res.ExpiresAt = expiryIn(12 * time.Hour)
	case 404:
		res.Verdict = database.ThreatVerdictUnknown
		res.Summary = "VirusTotal 没有该指标的记录"
		res.ExpiresAt = expiryIn(24 * time.Hour)
	case 429:
		return nil, fmt.Errorf("virustotal 触发限速（HTTP 429），免费档为 4 次/分钟")
	default:
		var data vtResponse
		_ = json.Unmarshal(body, &data)
		if data.Error.Message != "" {
			return nil, fmt.Errorf("virustotal 返回 HTTP %d：%s", status, data.Error.Message)
		}
		return nil, fmt.Errorf("virustotal 返回 HTTP %d", status)
	}
	return res, nil
}

// vtPath 按指标类型映射到 v3 的不同资源路径。
// URL 必须先做 base64url（无 padding），这是 VT 的硬要求。
func vtPath(indicatorType, value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(indicatorType)) {
	case "ip":
		return "/api/v3/ip_addresses/" + value, nil
	case "domain":
		return "/api/v3/domains/" + value, nil
	case "md5", "sha1", "sha256":
		return "/api/v3/files/" + value, nil
	case "url":
		id := base64.RawURLEncoding.EncodeToString([]byte(value))
		return "/api/v3/urls/" + id, nil
	}
	return "", fmt.Errorf("%w: virustotal 不支持 %q", ErrUnsupported, indicatorType)
}

func classifyVirusTotal(d vtResponse) (verdict, summary string) {
	s := d.Data.Attributes.LastAnalysisStats
	mal, susp := s.Malicious, s.Suspicious
	total := mal + susp + s.Harmless + s.Undetected + s.Timeout
	switch {
	case mal > 0:
		line := fmt.Sprintf("VirusTotal %d/%d 引擎判定恶意", mal, total)
		if susp > 0 {
			line += fmt.Sprintf("，另有 %d 个可疑", susp)
		}
		return database.ThreatVerdictMalicious, line
	case susp > 0:
		return database.ThreatVerdictSuspicious,
			fmt.Sprintf("VirusTotal %d/%d 引擎判定可疑，无引擎判恶意", susp, total)
	default:
		line := fmt.Sprintf("VirusTotal %d 个引擎均未报恶意", total)
		if d.Data.Attributes.Country != "" {
			line += "（归属 " + d.Data.Attributes.Country
			if d.Data.Attributes.ASOwner != "" {
				line += "，" + d.Data.Attributes.ASOwner
			}
			line += "）"
		}
		return database.ThreatVerdictClean, line
	}
}
