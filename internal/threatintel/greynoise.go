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

const defaultGreyNoiseBase = "https://api.greynoise.io"

// GreyNoise 的 community 接口实测不需要 Key 也能查（匿名有限速）。
// 它的价值不是"这 IP 坏不坏"，而是"这个地址是不是全网都在扫"——
// 一次噪声判定能把大量误报砍掉，所以它属于降噪主力。
type GreyNoise struct {
	doer *HTTPDoer
	base string
}

// NewGreyNoise 构造 GreyNoise 源。
func NewGreyNoise(doer *HTTPDoer, base string) *GreyNoise {
	if strings.TrimSpace(base) == "" {
		base = defaultGreyNoiseBase
	}
	return &GreyNoise{doer: doer, base: strings.TrimRight(strings.TrimSpace(base), "/")}
}

func (p *GreyNoise) Name() string { return "greynoise" }

func (p *GreyNoise) Category() string { return database.ThreatCategoryReputation }

// RequiresKey 为 false：community 接口匿名可用。若客户配了 key，会作为
// 请求头带上以提升配额，但这不是使用前提。
func (p *GreyNoise) RequiresKey() bool { return false }

func (p *GreyNoise) Supports(indicatorType string) bool {
	return strings.EqualFold(indicatorType, "ip")
}

// greyNoiseResponse 对应 v3/community/{ip}。实测两种形状：
//
//	200 {"ip":"71.6.135.131","noise":true,"riot":false,"classification":"benign",
//	     "name":"Shodan.io","link":"…","last_seen":"2026-11-22","message":"Success"}
//	404 {"ip":"1.1.1.1","noise":false,"riot":false,
//	     "message":"IP not observed scanning the internet."}
type greyNoiseResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	RIOT           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func (p *GreyNoise) Query(ctx context.Context, ind Indicator, key string) (*Result, error) {
	ip := strings.TrimSpace(ind.Normalized)
	if ip == "" {
		ip = strings.TrimSpace(ind.Value)
	}
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%w: greynoise 只接受 IP，收到 %q", ErrUnsupported, ind.Value)
	}

	headers := map[string]string{}
	if strings.TrimSpace(key) != "" {
		headers["key"] = strings.TrimSpace(key)
	}
	status, body, err := p.doer.getRaw(ctx, p.base+"/v3/community/"+ip, headers)
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

	var data greyNoiseResponse
	_ = json.Unmarshal(body, &data)

	switch status {
	case 200:
		res.Verdict, res.Summary = classifyGreyNoise(data)
		res.ExpiresAt = expiryIn(1 * time.Hour)
	case 404:
		// 404 是"没观测到扫描"，是有效结论而非错误，必须落负缓存。
		res.Verdict = database.ThreatVerdictClean
		res.Summary = "GreyNoise 未观测到该地址的全网扫描行为"
		res.ExpiresAt = expiryIn(6 * time.Hour)
	default:
		return nil, fmt.Errorf("greynoise 返回 HTTP %d", status)
	}
	return res, nil
}

// greyNoiseName 过滤掉 GreyNoise 用 "unknown" 表示"没有名字"的占位值，
// 否则摘要里会出现"（unknown）"这种没信息量还挺唬人的括号。
func greyNoiseName(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" || strings.EqualFold(name, "unknown") {
		return ""
	}
	return name
}

// classifyGreyNoise 把 GreyNoise 的分类翻译成我们的判定。
//
// 关键点：benign 的全网扫描器（如 Shodan）是 noise=true 但**非恶意**，
// 不能因为"它在扫"就判可疑；RIOT 则是已知良性服务，直接当干净。
func classifyGreyNoise(d greyNoiseResponse) (verdict, summary string) {
	if d.RIOT {
		name := greyNoiseName(d.Name)
		if name == "" {
			name = "已知良性服务"
		}
		return database.ThreatVerdictClean, "GreyNoise 识别为已知良性服务：" + name
	}
	if !d.Noise {
		return database.ThreatVerdictClean, "GreyNoise 未观测到该地址的全网扫描行为"
	}
	switch strings.ToLower(strings.TrimSpace(d.Classification)) {
	case "malicious":
		line := "GreyNoise 判定为恶意扫描源"
		if name := greyNoiseName(d.Name); name != "" {
			line += "（" + name + "）"
		}
		if d.LastSeen != "" {
			line += "，最近活动 " + d.LastSeen
		}
		return database.ThreatVerdictMalicious, line
	case "benign":
		line := "GreyNoise 观测到全网扫描，但归类为良性"
		if name := greyNoiseName(d.Name); name != "" {
			line += "（" + name + "）"
		}
		return database.ThreatVerdictClean, line
	case "":
		return database.ThreatVerdictSuspicious, "GreyNoise 观测到该地址在扫描，但未给出分类"
	default:
		return database.ThreatVerdictSuspicious, "GreyNoise 分类：" + d.Classification
	}
}
