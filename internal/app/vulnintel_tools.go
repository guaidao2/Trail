package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"trail/internal/config"
	"trail/internal/database"
	"trail/internal/hostclient"
	"trail/internal/mcp"
	"trail/internal/mcp/builtin"
	"trail/internal/security"
	"trail/internal/vulnintel"

	"go.uber.org/zap"
)

// registerVulnIntelTools 注册漏洞情报工具（外部公开知识库）。
//
// 设计要点：
//   - 情报本体是「外界已知什么」，与 IOC（攻击者实体）、vulnerabilities（自发现有）分开；
//   - 版本判定是三态：命中 / 未命中 / 无法判断，绝不把"无法判断"说成"安全"；
//   - 主机匹配只读，命中结果落 detect_findings（source=vuln_intel），复用主机发现与状态流转。
func registerVulnIntelTools(server *mcp.Server, db *database.DB, box *security.SecretBox, cfg *config.Config, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolVulnIntelSearch,
		ShortDescription: "检索公开漏洞情报",
		Description:      "按关键字或组件检索漏洞情报库（NVD + CISA KEV 在野利用 + EPSS + GHSA）。给 product + version 时返回版本判定三态：version_in_range=true 表示落在受影响区间；false 表示明确不在区间（不等于安全，区间可能缺失或填错）；字段缺失表示无结构化区间、需人工判断。排序为 KEV > EPSS > CVSS。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"keyword":  map[string]interface{}{"type": "string", "description": "CVE 编号 / 标题 / 描述关键字"},
				"product":  map[string]interface{}{"type": "string", "description": "组件名，如 httpd / openssh / log4j"},
				"vendor":   map[string]interface{}{"type": "string", "description": "厂商名，如 apache / openbsd"},
				"version":  map[string]interface{}{"type": "string", "description": "目标版本号，配合 product 做三态判定"},
				"severity": map[string]interface{}{"type": "string", "description": "CRITICAL / HIGH / MEDIUM / LOW"},
				"kev_only": map[string]interface{}{"type": "boolean", "description": "只看已在野利用（CISA KEV）"},
				"limit":    map[string]interface{}{"type": "integer", "description": "返回条数，默认 20，最大 100"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "intel:read"); !ok {
			return textResult("缺少 intel:read 权限", true), nil
		}
		hits, total, err := db.SearchVulnIntel(database.VulnIntelFilter{
			Keyword:  strArg(args, "keyword"),
			Vendor:   strArg(args, "vendor"),
			Product:  strArg(args, "product"),
			Version:  strArg(args, "version"),
			Severity: strArg(args, "severity"),
			KEVOnly:  boolArg(args, "kev_only"),
			Limit:    intArg(args, "limit", 20),
		})
		if err != nil {
			return textResult("检索漏洞情报失败: "+err.Error(), true), nil
		}
		payload := map[string]interface{}{
			"count":           len(hits),
			"total":           total,
			"vulnerabilities": hits,
		}
		if len(hits) == 0 {
			payload["note"] = "无命中：可能是组件名与 CPE 命名不符（试 httpd / openssh 这类产品名），或情报库尚未同步（可用 vuln_intel_sync）"
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolVulnIntelGet,
		ShortDescription: "取单条漏洞情报详情",
		Description:      "返回一条 CVE 的完整情报：描述、CVSS、是否在野利用（KEV）、EPSS 利用概率、结构化版本区间（含修复版本）、参考资料与公开 PoC 链接。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"cve_id": map[string]interface{}{"type": "string", "description": "CVE 编号，如 CVE-2021-44228"},
			},
			"required": []string{"cve_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "intel:read"); !ok {
			return textResult("缺少 intel:read 权限", true), nil
		}
		cveID := strings.TrimSpace(strArg(args, "cve_id"))
		if cveID == "" {
			return textResult("cve_id 不能为空", true), nil
		}
		rec, ranges, pocs, err := db.GetVulnIntel(cveID)
		if err != nil {
			return textResult("读取漏洞情报失败: "+err.Error(), true), nil
		}
		if rec == nil {
			return textResult("情报库没有这条记录（可能尚未同步，或用 vuln_intel_search 确认编号）", true), nil
		}
		b, _ := json.MarshalIndent(map[string]interface{}{
			"vulnerability": rec,
			"ranges":        ranges,
			"pocs":          pocs,
		}, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolVulnIntelMatchHost,
		ShortDescription: "比对主机软件清单与漏洞情报",
		Description:      "采集纳管主机的软件包清单（dpkg / rpm / pip / npm / gem / cargo / go / docker），与情报库做保守匹配。每条结果带四态 status：affected（版本明确落在受影响区间且无不确定因素）、needs_manual（版本落在区间，但存在不确定因素：包名与产品名不完全对应、版本带发行版修订、CVE 年代久远，或上游/修订两种比较器结论不一致）、unknown（无结构化区间）、not_affected（明确不在区间）。needs_patch_check=true 表示版本带发行版后缀，必须先核对发行版补丁再下结论。默认只把 affected 项写成该主机的检测发现。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"host_id":  map[string]interface{}{"type": "string", "description": "主机 ID"},
				"persist":  map[string]interface{}{"type": "boolean", "description": "是否把 affected 项写成检测发现，默认 true"},
				"limit":    map[string]interface{}{"type": "integer", "description": "返回条数上限，默认 50"},
				"include_unknown": map[string]interface{}{"type": "boolean", "description": "是否返回需要人工判断的 unknown 项，默认 true"},
			},
			"required": []string{"host_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "intel:read"); !ok {
			return textResult("缺少 intel:read 权限", true), nil
		}
		hostAccess, ok := hostToolAccess(ctx, "host:read")
		if !ok {
			return textResult("缺少 host:read 权限", true), nil
		}
		host, res := loadHostForTool(db, hostAccess, strArg(args, "host_id"))
		if res != nil {
			return res, nil
		}
		opts, err := hostOptionsFromRecord(box, host)
		if err != nil {
			return textResult("准备连接凭据失败: "+err.Error(), true), nil
		}
		execCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		out, err := hostclient.Exec(execCtx, opts, packageInventoryScript, 120*time.Second)
		if err != nil {
			return textResult("采集软件包清单失败: "+err.Error(), true), nil
		}
		pkgs := parsePackageInventory(out.Stdout)
		if len(pkgs) == 0 {
			return textResult("没能从主机采集到软件包清单（可能缺少 dpkg/rpm/pip/gem/cargo/go 等工具，或权限不足）", true), nil
		}
		matches, err := db.MatchPackages(pkgs)
		if err != nil {
			return textResult("匹配漏洞情报失败: "+err.Error(), true), nil
		}
		includeUnknown := boolArgDefault(args, "include_unknown", true)
		limit := intArg(args, "limit", 50)
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		affected, manual, unknown := 0, 0, 0
		shown := []database.PackageMatch{}
		for _, m := range matches {
			switch m.Status {
			case "affected":
				affected++
			case "needs_manual":
				manual++
			case "unknown":
				unknown++
			}
			if m.Status == "not_affected" {
				continue
			}
			if m.Status == "unknown" && !includeUnknown {
				continue
			}
			if len(shown) < limit {
				shown = append(shown, m)
			}
		}

		persisted := 0
		if boolArgDefault(args, "persist", true) {
			if _, ok := hostToolAccess(ctx, "host:write"); ok {
				for _, m := range shown {
					if m.Status != "affected" {
						continue
					}
					evidence := fmt.Sprintf("package=%s %s range=%s kev=%v epss=%s",
						m.Package.Name, m.Package.Version, m.Range, m.KEV, formatEPSS(m.EPSS))
					if m.PatchedVersion != "" {
						evidence += " fixed_in=" + m.PatchedVersion
					}
					if _, err := db.UpsertFinding(database.FindingUpsert{
						HostID: host.ID, Source: "vuln_intel", Kind: "system",
						RuleID: m.CVEID, Title: fmt.Sprintf("%s 影响 %s %s", m.CVEID, m.Package.Name, m.Package.Version),
						Category: "component_vuln", Severity: strings.ToLower(m.Severity),
						Subject: m.Package.Name, Evidence: evidence,
					}); err != nil {
						logger.Warn("写入漏洞情报发现失败", zap.String("cve", m.CVEID), zap.Error(err))
						continue
					}
					persisted++
				}
			}
		}

		patchCheckCount := 0
		for _, m := range matches {
			if m.NeedsPatchCheck {
				patchCheckCount++
			}
		}

		b, _ := json.MarshalIndent(map[string]interface{}{
			"host_id":           host.ID,
			"packages_scanned":  len(pkgs),
			"affected":          affected,
			"needs_manual":      manual,
			"unknown":           unknown,
			"needs_patch_check": patchCheckCount,
			"persisted":         persisted,
			"matched":           shown,
			"note":              "affected 表示版本落在区间且无不确定因素；needs_manual 需要人工核（包名模糊 / 留版修订 / 年代久远 / 两种比较器结论不一致）；needs_patch_check 的条目要核对发行版补丁（backport）后再定性",
		}, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolVulnIntelSync,
		ShortDescription: "触发漏洞情报同步",
		Description:      "从公开源同步漏洞情报：kev（CISA 在野利用，全量覆盖）、nvd（增量，首跑全量回填）、epss（利用概率）、ghsa（版本区间补充）、osv（按生态导入全量包，语言包精确匹配的数据来源）、poc（为 KEV 条目聚合公开 PoC）。单源失败不影响其它源，结果里会列出错误。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"source": map[string]interface{}{"type": "string", "description": "kev / nvd / epss / ghsa / osv / poc / all（默认 all）"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "intel:write"); !ok {
			return textResult("缺少 intel:write 权限", true), nil
		}
		ic := vulnIntelCfgSnapshot()
		syncCfg := vulnintel.Config{
			NVDAPIKey:    strings.TrimSpace(ic.NVDAPIKey),
			GitHubToken:  strings.TrimSpace(ic.GitHubToken),
			ProxyURL:     strings.TrimSpace(ic.Proxy),
			BackfillDays: ic.BackfillDays,
			MaxRuntime:   ic.VulnIntelMaxRuntime(),
			EPSSEnabled:  ic.VulnIntelEPSSOn(),
			GHSAEnabled:  ic.VulnIntelGHSAOn(),
			POCEnabled:   ic.VulnIntelPOCon(),
			OSVEnabled:   ic.VulnIntelOSVOn(),
			OSVBaseURL:   strings.TrimSpace(ic.OSVBaseURL),
		}
		source := strings.ToLower(strings.TrimSpace(strArg(args, "source")))
		switch source {
		case "", "all":
		case "nvd":
			syncCfg.EPSSEnabled, syncCfg.GHSAEnabled, syncCfg.POCEnabled = false, false, false
			syncCfg.OSVEnabled = false
			syncCfg.MaxRuntime = 5 * time.Minute
		case "kev", "epss", "ghsa", "poc":
			// 单独跑某一源时，只保留该源（NVD 必须关掉，否则会触发全量回填）
			only := source
			off := false
			syncCfg.NVDEnabled = &off
			syncCfg.EPSSEnabled = only == "epss"
			syncCfg.GHSAEnabled = only == "ghsa"
			syncCfg.POCEnabled = only == "poc"
			syncCfg.OSVEnabled = false
			syncCfg.MaxRuntime = 10 * time.Minute
		case "osv":
			only := false
			syncCfg.NVDEnabled = &only
			syncCfg.EPSSEnabled = false
			syncCfg.GHSAEnabled = false
			syncCfg.POCEnabled = false
			syncCfg.OSVEnabled = true
			syncCfg.MaxRuntime = 6 * time.Hour
		default:
			return textResult("source 仅支持 kev / nvd / epss / ghsa / poc / osv / all", true), nil
		}
		syncer := vulnintel.New(db, syncCfg, func(format string, a ...interface{}) {
			logger.Info(fmt.Sprintf(format, a...))
		})
		sum, err := syncer.Run(ctx)
		payload := map[string]interface{}{
			"summary": sum,
			"total_intel": func() int { t, _, _ := db.CountVulnIntel(); return t }(),
			"kev_intel": func() int { _, k, _ := db.CountVulnIntel(); return k }(),
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), err != nil), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolVulnIntelImport,
		ShortDescription: "从本地文件导入漏洞情报",
		Description:      "离线导入漏洞情报（内网拿不到外网时用）：支持 CISA KEV 目录、EPSS 响应、NVD 2.0 响应三种 JSON，format 留空时按内容自动识别。KEV 按全量语义导入（先清标记再写入，并带上厂商/产品/名称/修复动作/截止日期）；EPSS 只更新利用概率；NVD 会写入 CVE 主体与结构化版本区间。路径是 Trail 所在机器上的本地文件。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":   map[string]interface{}{"type": "string", "description": "本地 JSON 文件路径"},
				"format": map[string]interface{}{"type": "string", "description": "kev / epss / nvd；留空自动识别"},
			},
			"required": []string{"path"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "intel:write"); !ok {
			return textResult("缺少 intel:write 权限", true), nil
		}
		sum, err := vulnintel.ImportFile(ctx, db, strArg(args, "path"), strArg(args, "format"))
		payload := map[string]interface{}{"summary": sum}
		if err != nil {
			payload["error"] = err.Error()
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), err != nil), nil
	})
}

// packageInventoryScript 只读采集软件包清单；各段之间用标记分隔，缺失的工具静默跳过。
//
// 覆盖的生态对应情报库里的精确匹配键：dpkg/rpm（OS 包，走 CPE 匹配）、
// pip/npm/gem/go/cargo（语言包，只按 (生态, 精确包名) 匹配）。
const packageInventoryScript = `echo "=== dpkg ==="; dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | head -n 4000
echo "=== rpm ==="; rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | head -n 4000
echo "=== pip ==="; (pip3 list --format=freeze 2>/dev/null || pip list --format=freeze 2>/dev/null) | head -n 2000
echo "=== npm ==="; (npm ls -g --depth=0 --parseable 2>/dev/null | tail -n +2) | head -n 500
echo "=== gem ==="; gem list --local 2>/dev/null | head -n 2000
echo "=== cargo ==="; cargo install --list 2>/dev/null | head -n 500
echo "=== go ==="; (command -v go >/dev/null 2>&1 && find "$HOME/go/bin" /usr/local/bin -maxdepth 1 -type f 2>/dev/null | head -n 60 | while read -r b; do go version -m "$b" 2>/dev/null; done) | awk '$1 == "dep" {print $2 "\t" $3}' | sort -u | head -n 2000
echo "=== docker ==="; docker images --format '{{.Repository}}\t{{.Tag}}' 2>/dev/null | head -n 200
echo "=== end ==="`

// parsePackageInventory 解析清单输出，按段标记判定来源。
func parsePackageInventory(output string) []database.Package {
	pkgs := []database.Package{}
	source := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "=== ") && strings.HasSuffix(line, " ===") {
			source = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "=== "), " ==="))
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "=") {
			continue
		}
		name, version := "", ""
		switch source {
		case "dpkg", "rpm", "docker":
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			name, version = parts[0], parts[1]
			if source == "docker" && (version == "<none>" || version == "") {
				continue
			}
		case "pip":
			// name==version
			parts := strings.SplitN(line, "==", 2)
			if len(parts) != 2 {
				continue
			}
			name, version = parts[0], parts[1]
		case "npm":
			// 形如 /usr/lib/node_modules/@scope/pkg@1.2.3
			idx := strings.LastIndex(line, "@")
			if idx <= 0 {
				continue
			}
			name, version = line[:idx], line[idx+1:]
			name = strings.TrimPrefix(name, "/usr/lib/node_modules/")
			name = strings.TrimPrefix(name, "/usr/local/lib/node_modules/")
		case "gem":
			// 形如 rails (7.1.3) 或 nokogiri (1.16.0, 1.15.5, default: 1.14.0)
			// 同一 gem 可能装多个版本，取括号里的第一个（即最高版本）。
			open := strings.Index(line, " (")
			if open <= 0 {
				continue
			}
			name = line[:open]
			rest := strings.TrimSuffix(strings.TrimSpace(line[open+2:]), ")")
			if cut := strings.Index(rest, ","); cut >= 0 {
				rest = rest[:cut]
			}
			rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "default:"))
			version = rest
		case "cargo":
			// 形如 ripgrep v14.1.0:（后面可能跟缩进的 bin 行，不是版本行）
			if !strings.HasSuffix(line, ":") || strings.HasPrefix(line, " ") {
				continue
			}
			body := strings.TrimSuffix(line, ":")
			idx := strings.LastIndex(body, " v")
			if idx <= 0 {
				continue
			}
			name, version = body[:idx], strings.TrimPrefix(body[idx+1:], "v")
		case "go":
			// 来自 go version -m 的 dep 行：module<TAB>version
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			name, version = parts[0], parts[1]
			if version == "(devel)" || version == "" {
				continue
			}
		default:
			continue
		}
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, database.Package{Name: name, Version: version, Source: source})
	}
	return pkgs
}

func formatEPSS(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%.3f", *v)
}
