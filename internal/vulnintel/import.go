package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trail/internal/database"
)

// 离线导入：内网环境拿不到外网时，用外部下载好的 JSON 包喂进来。
//
// 支持三种格式（format 留空时自动识别）：
//   - kev  ：CISA KEV 目录（known_exploited_vulnerabilities.json）
//   - epss ：EPSS 响应（api.first.org/data/v1/epss 的返回体）
//   - nvd  ：NVD 2.0 响应（rest/json/cves/2.0 的返回体）
const maxImportBytes = 512 << 20 // 512MB，防止误指到超大文件把内存打满

// ImportFile 从本地文件导入漏洞情报。
func ImportFile(ctx context.Context, db *database.DB, path, format string) (Summary, error) {
	sum := Summary{StartedAt: time.Now()}
	path = strings.TrimSpace(path)
	if path == "" {
		return sum, fmt.Errorf("文件路径不能为空")
	}
	info, err := os.Stat(path)
	if err != nil {
		return sum, fmt.Errorf("读取文件失败: %w", err)
	}
	if info.IsDir() {
		return sum, fmt.Errorf("%s 是目录，请指定具体的 JSON 文件", path)
	}
	if info.Size() > maxImportBytes {
		return sum, fmt.Errorf("文件过大（%d 字节），上限 %d", info.Size(), maxImportBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return sum, fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	kind := strings.ToLower(strings.TrimSpace(format))
	if kind == "" {
		kind = detectImportFormat(f)
		if _, err := f.Seek(0, 0); err != nil {
			return sum, fmt.Errorf("读取文件失败: %w", err)
		}
	}

	switch kind {
	case "kev":
		var cat kevCatalog
		if err := json.NewDecoder(f).Decode(&cat); err != nil {
			return sum, fmt.Errorf("解析 KEV 文件失败: %w", err)
		}
		if len(cat.Vulnerabilities) == 0 {
			return sum, fmt.Errorf("KEV 文件里没有 vulnerabilities 条目")
		}
		// 目录是全量语义：导入前清一次标记，避免旧条目残留
		if err := db.ClearKEV(); err != nil {
			return sum, err
		}
		for _, v := range cat.Vulnerabilities {
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			added, _ := time.Parse("2006-01-02", strings.TrimSpace(v.DateAdded))
			if err := db.UpsertKEVEntry(database.KEVEntry{
				CVEID: v.CVEID, DateAdded: added,
				Vendor: v.VendorProject, Product: v.Product,
				Name: v.VulnerabilityName, Description: v.ShortDescription,
				RequiredAction: v.RequiredAction, DueDate: v.DueDate,
				KnownRansomwareCampaignUse: strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known"),
			}); err != nil {
				continue
			}
			sum.KEV++
		}
		_ = db.SaveVulnIntelSync(database.VulnIntelSyncState{
			Source: "kev", LastSyncAt: time.Now().UTC().Format(time.RFC3339),
			TotalSynced: sum.KEV, Enabled: true,
		})

	case "epss":
		var resp epssResponse
		if err := json.NewDecoder(f).Decode(&resp); err != nil {
			return sum, fmt.Errorf("解析 EPSS 文件失败: %w", err)
		}
		if len(resp.Data) == 0 {
			return sum, fmt.Errorf("EPSS 文件里没有 data 条目")
		}
		for _, row := range resp.Data {
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			score, err1 := parseFloat(row.EPSS)
			pct, err2 := parseFloat(row.Percentile)
			if err1 != nil || err2 != nil {
				continue
			}
			at, _ := time.Parse("2006-01-02", strings.TrimSpace(row.Date))
			if err := db.UpdateEPSS(row.CVE, score, pct, at); err != nil {
				continue
			}
			sum.EPSS++
		}
		_ = db.SaveVulnIntelSync(database.VulnIntelSyncState{
			Source: "epss", LastSyncAt: time.Now().UTC().Format(time.RFC3339),
			TotalSynced: sum.EPSS, Enabled: true,
		})

	case "nvd":
		var resp nvdResponse
		if err := json.NewDecoder(f).Decode(&resp); err != nil {
			return sum, fmt.Errorf("解析 NVD 文件失败: %w", err)
		}
		if len(resp.Vulnerabilities) == 0 {
			return sum, fmt.Errorf("NVD 文件里没有 vulnerabilities 条目")
		}
		for _, v := range resp.Vulnerabilities {
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			intel, ranges := nvdToIntel(v.CVE)
			if intel.CVEID == "" {
				continue
			}
			if err := db.UpsertVulnIntel(intel, ranges); err != nil {
				continue
			}
			sum.NVD++
		}
		_ = db.SaveVulnIntelSync(database.VulnIntelSyncState{
			Source: "nvd", LastSyncAt: time.Now().UTC().Format(time.RFC3339),
			TotalSynced: sum.NVD, Enabled: true,
		})

	default:
		return sum, fmt.Errorf("无法识别的格式（支持 kev / epss / nvd），文件: %s", filepath.Base(path))
	}

	sum.FinishedAt = time.Now()
	return sum, nil
}

// detectImportFormat 读文件开头的一小段，按关键字段猜格式。
func detectImportFormat(f *os.File) string {
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	head := strings.ToLower(string(buf[:n]))
	switch {
	case strings.Contains(head, "\"knownransomwarecampaignuse\"") || strings.Contains(head, "\"catalogversion\""):
		return "kev"
	case strings.Contains(head, "\"epss\"") && strings.Contains(head, "\"percentile\""):
		return "epss"
	case strings.Contains(head, "\"lastmodified\"") || strings.Contains(head, "\"cvssmetricv31\""):
		return "nvd"
	}
	return ""
}
