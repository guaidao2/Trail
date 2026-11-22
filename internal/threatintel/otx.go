package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"time"

	"trail/internal/database"
)

const defaultOTXBase = "https://otx.alienvault.com"

// OTX（AlienVault Open Threat Exchange）的 indicators 接口实测免 Key 可读，
// 给的是社区 pulse 里有没有收录这个指标，以及地理/ASN 等上下文。
type OTX struct {
	doer *HTTPDoer
	base string
}

// NewOTX 构造 OTX 源。
func NewOTX(doer *HTTPDoer, base string) *OTX {
	if strings.TrimSpace(base) == "" {
		base = defaultOTXBase
	}
	return &OTX{doer: doer, base: strings.TrimRight(strings.TrimSpace(base), "/")}
}

func (p *OTX) Name() string { return "otx" }

func (p *OTX) Category() string { return database.ThreatCategoryReputation }

func (p *OTX) RequiresKey() bool { return false }

func (p *OTX) Supports(indicatorType string) bool {
	switch strings.ToLower(strings.TrimSpace(indicatorType)) {
	case "ip", "domain", "url", "md5", "sha1", "sha256":
		return true
	}
	return false
}

// otxResponse 只取需要的字段。pulse 列表可能很长，只留计数与前几条名字，
// 避免把几十 KB 原始数据塞进缓存行。
type otxResponse struct {
	Reputation int    `json:"reputation"`
	Indicator  string `json:"indicator"`
	TypeTitle  string `json:"type_title"`
	Country    string `json:"country_code3"`
	ASN        string `json:"asn"`
	PulseInfo  struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name     string   `json:"name"`
			Tags     []string `json:"tags"`
			Modified string   `json:"modified"`
		} `json:"pulses"`
	} `json:"pulse_info"`
}

func (p *OTX) Query(ctx context.Context, ind Indicator, key string) (*Result, error) {
	section := otxSection(ind.Type)
	value := strings.TrimSpace(ind.Normalized)
	if value == "" {
		value = strings.TrimSpace(ind.Value)
	}
	if section == "" || value == "" {
		return nil, fmt.Errorf("%w: otx 不支持 %q", ErrUnsupported, ind.Type)
	}

	headers := map[string]string{}
	if strings.TrimSpace(key) != "" {
		headers["X-OTX-API-KEY"] = strings.TrimSpace(key)
	}
	// IPv4 / IPv6 需要先判断，否则 v6 地址会被当成 IPv4 路径查空。
	if section == "IPv4" {
		if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
			section = "IPv6"
		}
	}

	// URL 类型的 value 里带 ? 和 /，不转义会破坏路径，还可能拼到别的子路径上。
	url := p.base + "/api/v1/indicators/" + section + "/" + neturl.PathEscape(value) + "/general"
	status, body, err := p.doer.getRaw(ctx, url, headers)
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
		var data otxResponse
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("解析 OTX 响应失败: %w", err)
		}
		res.Verdict, res.Summary = classifyOTX(data)
		res.ExpiresAt = expiryIn(6 * time.Hour)
	case 404:
		res.Verdict = database.ThreatVerdictUnknown
		res.Summary = "OTX 没有该指标的记录"
		res.ExpiresAt = expiryIn(12 * time.Hour)
	default:
		return nil, fmt.Errorf("otx 返回 HTTP %d", status)
	}
	return res, nil
}

func otxSection(indicatorType string) string {
	switch strings.ToLower(strings.TrimSpace(indicatorType)) {
	case "ip":
		return "IPv4"
	case "domain":
		return "domain"
	case "url":
		return "url"
	case "md5", "sha1", "sha256":
		return "file"
	}
	return ""
}

// classifyOTX：被社区 pulse 收录说明"有人把它当威胁情报"，是可疑证据，
// 但 pulse 质量参差，不足以直接判恶意；只有负信誉才升到恶意。
func classifyOTX(d otxResponse) (verdict, summary string) {
	count := d.PulseInfo.Count
	if d.Reputation < 0 && count > 0 {
		return database.ThreatVerdictMalicious,
			fmt.Sprintf("OTX 收录于 %d 个 pulse，且社区信誉为负（%d）", count, d.Reputation)
	}
	if count > 0 {
		line := fmt.Sprintf("OTX 收录于 %d 个社区 pulse", count)
		names := make([]string, 0, 3)
		for _, pulse := range d.PulseInfo.Pulses {
			if strings.TrimSpace(pulse.Name) != "" {
				names = append(names, pulse.Name)
			}
			if len(names) >= 3 {
				break
			}
		}
		if len(names) > 0 {
			line += "：" + strings.Join(names, "、")
		}
		return database.ThreatVerdictSuspicious, line
	}
	line := "OTX 未收录进任何 pulse"
	if d.Country != "" {
		line += "（归属 " + d.Country + "）"
	}
	return database.ThreatVerdictClean, line
}
