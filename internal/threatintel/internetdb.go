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

// defaultInternetDBBase 是 Shodan InternetDB 的公开入口。按官方说明：
// 无需账号与 API Key，非商业用途免费，数据每周更新一次，只返回
// 端口、CPE、主机名、标签与已知漏洞，不含 banner。
const defaultInternetDBBase = "https://internetdb.shodan.io"

// InternetDB 是唯一一个「不填 key 就能跑」的查询式源，因此它是整条链路的基线：
// 就算客户一个 key 都不配，威胁情报页也应该有东西可看。
type InternetDB struct {
	doer *HTTPDoer
	base string
}

// NewInternetDB 构造 Shodan InternetDB 源。base 留空用官方入口，
// 内网环境可以指向自建镜像。
func NewInternetDB(doer *HTTPDoer, base string) *InternetDB {
	if strings.TrimSpace(base) == "" {
		base = defaultInternetDBBase
	}
	return &InternetDB{doer: doer, base: strings.TrimRight(strings.TrimSpace(base), "/")}
}

func (p *InternetDB) Name() string { return "internetdb" }

// Category 是 exposure：它报的是「这个地址在公网上露出什么」，不是「它坏不坏」。
func (p *InternetDB) Category() string { return database.ThreatCategoryExposure }

func (p *InternetDB) RequiresKey() bool { return false }

func (p *InternetDB) Supports(indicatorType string) bool {
	return strings.EqualFold(indicatorType, "ip")
}

// internetDBResponse 对应官方返回体。已实测：
//
//	200 {"cpes":[],"hostnames":["dns.google"],"ip":"8.8.8.8","ports":[53,443],"tags":["pqc"],"vulns":[]}
//	404 {"detail":"No information available"}
type internetDBResponse struct {
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
	Detail    string   `json:"detail"`
}

// Query 查询单个 IP 的暴露面。
//
// 404 不是错误：它表示「这个地址没有公开观测记录」（内网地址、CDN 后、
// 或确实没被扫到），按 negative cache 处理，避免反复请求。
func (p *InternetDB) Query(ctx context.Context, ind Indicator, _ string) (*Result, error) {
	ip := strings.TrimSpace(ind.Normalized)
	if ip == "" {
		ip = strings.TrimSpace(ind.Value)
	}
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%w: internetdb 只接受 IP，收到 %q", ErrUnsupported, ind.Value)
	}

	status, body, err := p.doer.getRaw(ctx, p.base+"/"+ip, nil)
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
		var data internetDBResponse
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("解析 internetdb 响应失败: %w", err)
		}
		res.Verdict = VerdictExposure
		res.Tags = append(res.Tags, data.Tags...)
		res.Summary = summarizeInternetDB(data)
		// 官方每周更新，7 天 TTL 足够；负结果短一些，IP 状态变化后能较快重查。
		res.ExpiresAt = expiryIn(7 * 24 * time.Hour)
	case 404:
		var data internetDBResponse
		_ = json.Unmarshal(body, &data)
		res.Verdict = database.ThreatVerdictUnknown
		res.Summary = "Shodan InternetDB 没有这个地址的公开观测记录"
		res.ExpiresAt = expiryIn(6 * time.Hour)
	default:
		return nil, fmt.Errorf("internetdb 返回 HTTP %d", status)
	}
	return res, nil
}

// summarizeInternetDB 把响应压成一句人读结论。顺序按"越能说明问题越靠前"：
// 漏洞 > 端口 > 服务指纹 > 标签 > 主机名。
func summarizeInternetDB(d internetDBResponse) string {
	var parts []string
	if len(d.Ports) > 0 {
		ports := make([]string, 0, len(d.Ports))
		for _, p := range d.Ports {
			ports = append(ports, fmt.Sprintf("%d", p))
		}
		parts = append(parts, "开放端口 "+strings.Join(ports, "/"))
	}
	if len(d.Vulns) > 0 {
		v := d.Vulns
		shown := v
		if len(shown) > 5 {
			shown = shown[:5]
		}
		line := fmt.Sprintf("已知漏洞 %d 个：%s", len(v), strings.Join(shown, "、"))
		if len(v) > len(shown) {
			line += " 等"
		}
		parts = append(parts, line)
	}
	if len(d.CPEs) > 0 {
		cpes := d.CPEs
		if len(cpes) > 4 {
			cpes = cpes[:4]
		}
		parts = append(parts, "服务指纹 "+strings.Join(cpes, "、"))
	}
	if len(d.Tags) > 0 {
		parts = append(parts, "标签 "+strings.Join(d.Tags, "、"))
	}
	if len(parts) == 0 {
		return "Shodan InternetDB 有记录，但未发现开放端口、漏洞或服务指纹"
	}
	return strings.Join(parts, "；")
}
