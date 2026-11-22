package threatintel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"trail/internal/database"
)

// ThreatFox 是 IOC 共享库，订阅导出同样要 Auth-Key，且改版后走 zip：
//
//	https://threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/full.csv.zip
//
// 旧路径 /export/json/recent/ 已 410。
type ThreatFox struct {
	doer *HTTPDoer
	base string
}

// NewThreatFox 构造 ThreatFox 源。
func NewThreatFox(doer *HTTPDoer, endpoint string) *ThreatFox {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = "https://threatfox-api.abuse.ch"
	}
	return &ThreatFox{doer: doer, base: strings.TrimRight(strings.TrimSpace(endpoint), "/")}
}

func (p *ThreatFox) Name() string { return "threatfox" }

func (p *ThreatFox) RequiresKey() bool { return true }

func (p *ThreatFox) exportURL(key string) string {
	return p.base + "/v2/files/exports/" + key + "/full.csv.zip"
}

func (p *ThreatFox) Fetch(ctx context.Context, key string) ([]database.ThreatIntelFeedEntry, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, ErrMissingKey
	}
	status, body, err := p.doer.getRaw(ctx, p.exportURL(key), nil)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, fmt.Errorf("threatfox 拒绝了 Auth-Key（HTTP %d），请到 auth.abuse.ch 重新获取", status)
	}
	if status != 200 {
		return nil, fmt.Errorf("threatfox 返回 HTTP %d", status)
	}

	raw, err := unzipFirstCSV(body)
	if err != nil {
		return nil, fmt.Errorf("threatfox 导出解压失败: %w", err)
	}
	records, err := parseCSVRecords(raw)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("threatfox 导出为空")
	}

	idx := csvHeaderIndex(records[0])
	// 指标列名在不同版本里叫 ioc 或 indicator，两个都认。
	iocCol := -1
	for _, name := range []string{"ioc", "indicator", "ioc_value"} {
		if i, ok := idx[name]; ok {
			iocCol = i
			break
		}
	}
	if iocCol < 0 {
		return nil, fmt.Errorf("threatfox 导出缺少 ioc 列，表头为: %v", records[0])
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	entries := make([]database.ThreatIntelFeedEntry, 0, len(records))
	for _, rec := range records[1:] {
		if iocCol >= len(rec) {
			continue
		}
		ioc := strings.TrimSpace(rec[iocCol])
		if ioc == "" {
			continue
		}
		iocType := normalizeThreatFoxType(pick(rec, idx, "ioc_type", "type"))
		// ip:port 要先剥端口再归一，否则存进去的是 "1.2.3.4:443"，
		// 按 IP 反查永远打不中，这条 feed 等于白拉。
		if iocType == "ip" {
			if host, _, err := net.SplitHostPort(ioc); err == nil {
				ioc = host
			}
		}
		normalized := database.NormalizeIOCValue(iocType, ioc)
		if normalized == "" {
			continue
		}
		entries = append(entries, database.ThreatIntelFeedEntry{
			Source:        p.Name(),
			IndicatorType: iocType,
			Normalized:    normalized,
			Category:      pick(rec, idx, "threat_type"),
			Malware:       pick(rec, idx, "malware_printable", "malware"),
			Confidence:    confidenceFrom(pick(rec, idx, "confidence_level", "confidence"), 70),
			FirstSeen:     pick(rec, idx, "first_seen", "firstseen"),
			LastSeen:      pick(rec, idx, "last_seen", "lastseen"),
			Tags:          pick(rec, idx, "tags"),
			FetchedAt:     now,
		})
	}
	return entries, nil
}

// normalizeThreatFoxType 把 ThreatFox 的类型名收敛成本项目用的类型名。
//
// 哈希保留具体算法而不是统一成 "hash"：页面按类型筛选、IOC 库按 md5/sha1/sha256
// 分别存储，收敛成 hash 之后两边就对不上了。
func normalizeThreatFoxType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "ip", "ip:port", "ipv4":
		return "ip"
	case "domain", "hostname":
		return "domain"
	case "url":
		return "url"
	case "md5", "md5_hash":
		return "md5"
	case "sha1", "sha1_hash":
		return "sha1"
	case "sha256", "sha256_hash":
		return "sha256"
	}
	return strings.ToLower(strings.TrimSpace(t))
}
