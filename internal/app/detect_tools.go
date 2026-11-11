package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"trail/internal/database"
	"trail/internal/detect/compliance"
	"trail/internal/detect/logscan"
	"trail/internal/hostclient"
	"trail/internal/mcp"
	"trail/internal/mcp/builtin"
	"trail/internal/security"

	"go.uber.org/zap"
)

// 检测引擎的规则集是编译期嵌入的（go:embed），只在进程内加载一次。
var (
	logRulesOnce sync.Once
	logRules     []logscan.Rule
	logRulesErr  error

	complianceOnce  sync.Once
	complianceSets  []compliance.Set
	complianceWarns []string
	complianceErr   error
)

func compiledLogRules() ([]logscan.Rule, error) {
	logRulesOnce.Do(func() {
		logRules = logscan.CompileRules(logscan.AllRules())
		if len(logRules) == 0 {
			logRulesErr = fmt.Errorf("日志检测规则集为空")
		}
	})
	return logRules, logRulesErr
}

func loadedComplianceSets() ([]compliance.Set, []string, error) {
	complianceOnce.Do(func() {
		complianceSets, complianceWarns, complianceErr = compliance.LoadSets()
	})
	return complianceSets, complianceWarns, complianceErr
}

// registerDetectTools 注册检测类 MCP 工具：日志攻击检测与基线合规核查。
//
// 两者都是**只读**能力：只执行读取类命令、不修改目标主机，所以统一按 host:read 校验。
// 判定逻辑与规则集来自 internal/detect（规则是 YAML + 自带正负样本，见各 rules/*.yaml）。
func registerDetectTools(server *mcp.Server, db *database.DB, box *security.SecretBox, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostLogScan,
		ShortDescription: "日志攻击检测",
		Description:      "在一台纳管主机上扫描日志里的攻击载荷与入侵痕迹：内置 SQL 注入、XSS、命令注入、路径穿越/包含、WebShell、SSTI、扫描器探测、协议异常、认证爆破与持久化等规则；带变形还原（URL/十六进制/CSS/Shell 引号/Base64/注释替换等），认证日志另做跨行关联（多次失败后成功、账号扫描、分布式爆破）。不指定 path 时自动探测常见日志。返回命中规则、严重度、来源 IP、证据行与关联结论。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":        map[string]interface{}{"type": "string", "description": "主机 ID"},
				"path":      map[string]interface{}{"type": "string", "description": "要扫描的日志绝对路径，如 /var/log/nginx/access.log；留空则自动探测常见日志（最多 3 个）"},
				"kind":      map[string]interface{}{"type": "string", "description": "日志类型：web / system（认证日志按 system 处理）/ all；留空按路径与内容自动判断"},
				"max_lines": map[string]interface{}{"type": "integer", "description": "每个日志扫描尾部行数，默认 2000，最大 20000"},
			},
			"required": []string{"id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:read")
		if !ok {
			return textResult("缺少 host:read 权限", true), nil
		}
		host, result := loadHostForTool(db, access, strArg(args, "id"))
		if result != nil {
			return result, nil
		}
		opts, err := hostOptionsFromRecord(box, host)
		if err != nil {
			return textResult("准备连接参数失败: "+err.Error(), true), nil
		}
		rules, err := compiledLogRules()
		if err != nil {
			return textResult("日志规则加载失败: "+err.Error(), true), nil
		}

		maxLines := intArg(args, "max_lines", 2000)
		if maxLines <= 0 || maxLines > 20000 {
			maxLines = 2000
		}

		scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		paths := []string{}
		if p := strings.TrimSpace(strArg(args, "path")); p != "" {
			if !allowedLogPath(p) {
				return textResult("只允许读取 /var/log/ 下的日志文件；读取其它任意文件请用 host_download（需要 host:exec 权限）", true), nil
			}
			// 字符串前缀挡不住符号链接：/var/log/x -> /root/.ssh/id_rsa 仍然"看起来在白名单里"。
			// 在目标机上取真实路径后再判一次。
			rpRes, rpErr := hostclient.Exec(scanCtx, opts, "command -v realpath >/dev/null 2>&1 && realpath -e -- "+shellQuote(p)+" 2>/dev/null || readlink -f -- "+shellQuote(p)+" 2>/dev/null || true", 10*time.Second)
			if rpErr != nil || rpRes == nil {
				return textResult("校验日志路径失败: "+errText(rpErr), true), nil
			}
			resolved := strings.TrimSpace(rpRes.Stdout)
			if resolved == "" || !allowedLogPath(resolved) {
				return textResult("日志路径校验失败：无法解析到 /var/log 或 /var/adm 下（文件不存在、符号链接指向白名单之外，或目标机缺少 realpath/readlink）: "+p, true), nil
			}
			paths = append(paths, resolved)
		} else {
			out, probeErr := hostclient.Exec(scanCtx, opts, logProbeScript(), 30*time.Second)
			if probeErr != nil || out == nil {
				return textResult("探测日志文件失败: "+errText(probeErr), true), nil
			}
			for _, line := range strings.Split(out.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				paths = append(paths, line)
				if len(paths) >= 3 {
					break
				}
			}
			if len(paths) == 0 {
				return textResult("未在常见路径发现可读日志，请用 path 参数指定日志文件绝对路径", false), nil
			}
		}

		type fileScan struct {
			Path         string                 `json:"path"`
			Kind         string                 `json:"kind"`
			Result       logscan.Result         `json:"result"`
			Correlations []logscan.Correlation  `json:"correlations,omitempty"`
		}
		scans := make([]fileScan, 0, len(paths))
		for _, p := range paths {
			cmd := fmt.Sprintf("tail -n %d -- %s 2>/dev/null", maxLines, shellQuote(p))
			res, execErr := hostclient.Exec(scanCtx, opts, cmd, 60*time.Second)
			if res == nil || strings.TrimSpace(res.Stdout) == "" {
				logger.Warn("日志读取失败或为空", zap.String("host", host.ID), zap.String("path", p), zap.String("err", errText(execErr)))
				continue
			}
			text := res.Stdout
			rawKind := strings.TrimSpace(strArg(args, "kind"))
			if rawKind == "" {
				rawKind = logscan.GuessLogKind(p, text)
			}
			kind := normalizeLogKind(rawKind)
			fileRules := logscan.RulesForKind(rules, kind)
			scanned := logscan.ScanWithLimits(text, p, fileRules, kind, logscan.ScanLimits{
				MaxDuration: 30 * time.Second,
				Ctx:         scanCtx,
				MaxHits:     500,
			})
			fs := fileScan{Path: p, Kind: kind, Result: scanned}
			if kind == "auth" || kind == "system" {
				fs.Correlations = logscan.AnalyzeAuth(strings.Split(text, "\n"), logscan.DefaultThresholds())
			}
			scans = append(scans, fs)
		}

		if len(scans) == 0 {
			return textResult("读取到的日志内容为空，未执行检测", false), nil
		}

		// 落库：命中的日志行写成"检测发现"，来源 IP 同时变成 observed 状态的 IOC 候选。
		// 观察态而不是确认态——日志里出现一个 IP 不等于它恶意，确认要人来做。
		persisted, iocCandidates := 0, 0
		for _, fs := range scans {
			for _, hit := range fs.Result.Hits {
				if _, err := db.UpsertFinding(database.FindingUpsert{
					HostID:   host.ID,
					Source:   "log_scan",
					Kind:     "log",
					RuleID:   hit.RuleID,
					Title:    hit.RuleName,
					Category: hit.Category,
					Severity: hit.Severity,
					Subject:  hit.SourceIP,
					Evidence: hit.Line,
				}); err != nil {
					logger.Warn("写入检测发现失败", zap.String("host", host.ID), zap.String("rule", hit.RuleID), zap.Error(err))
				} else {
					persisted++
				}
				ip := strings.TrimSpace(hit.SourceIP)
				if ip == "" {
					continue
				}
				rec, _, iocErr := db.UpsertIOC(database.IOCUpsert{
					Type:     "ip",
					Value:    ip,
					Status:   database.IOCStatusObserved,
					Severity: hit.Severity,
					Source:   "log_scan",
					Note:     "日志检测命中：" + hit.RuleName,
				})
				if iocErr != nil || rec == nil {
					continue
				}
				if hitErr := db.RecordIOCHit(rec.ID, host.ID, "log_scan", hit.RuleID, hit.Line); hitErr != nil {
					logger.Warn("记录 IOC 命中失败", zap.String("ioc", rec.ID), zap.Error(hitErr))
				} else {
					iocCandidates++
				}
			}
		}

		payload := map[string]interface{}{
			"host":               map[string]interface{}{"id": host.ID, "name": host.Name, "address": host.Address},
			"files":              scans,
			"persisted_findings": persisted,
			"ioc_candidates":     iocCandidates,
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostBaselineAudit,
		ShortDescription: "基线合规核查",
		Description:      "在一台纳管主机上执行只读的基线合规核查：身份鉴别、访问控制、SUID 提权面、安全审计、入侵防范、系统加固、常见提权路径，依据 GB/T 22239-2019（等保 2.0）三级与 CIS 加固要求。每项给出结论（符合 / 不符合 / 需要 root / 需人工）、判定说明、实际执行的命令与整改建议；读不到结果的项标为「需要 root」而不是「符合」。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":       map[string]interface{}{"type": "string", "description": "主机 ID"},
				"category": map[string]interface{}{"type": "string", "description": "只跑某一类检查，如 身份鉴别 / 访问控制 / 安全审计；留空跑全部"},
				"ids": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "只跑指定检查项 ID，如 CHK-ID-001；留空跑全部",
				},
			},
			"required": []string{"id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:read")
		if !ok {
			return textResult("缺少 host:read 权限", true), nil
		}
		host, result := loadHostForTool(db, access, strArg(args, "id"))
		if result != nil {
			return result, nil
		}
		opts, err := hostOptionsFromRecord(box, host)
		if err != nil {
			return textResult("准备连接参数失败: "+err.Error(), true), nil
		}
		sets, warns, err := loadedComplianceSets()
		if err != nil {
			return textResult("基线检查集加载失败: "+err.Error(), true), nil
		}
		checks := compliance.AllChecks(sets)
		if cat := strings.TrimSpace(strArg(args, "category")); cat != "" {
			filtered := checks[:0:0]
			for _, c := range checks {
				if c.Category == cat || strings.Contains(c.Category, cat) {
					filtered = append(filtered, c)
				}
			}
			checks = filtered
		}
		onlyIDs := hostStringSliceArg(args, "ids")
		if len(checks) == 0 {
			return textResult("没有匹配的检查项（category / ids 过滤过严）", false), nil
		}

		auditCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()

		exec := func(command string, timeoutSec int) (string, error) {
			d := time.Duration(timeoutSec) * time.Second
			if d <= 0 {
				d = 10 * time.Second
			}
			r, execErr := hostclient.Exec(auditCtx, opts, command, d)
			if r == nil {
				return "", execErr
			}
			out := r.Stdout
			if strings.TrimSpace(r.Stderr) != "" {
				out = strings.TrimSpace(out + "\n" + r.Stderr)
			}
			if r.ExitCode != 0 {
				return out, fmt.Errorf("exit status %d", r.ExitCode)
			}
			return out, nil
		}

		results, missing := compliance.RunWithContext(auditCtx, checks, exec, onlyIDs, nil)

		// 只把"不符合"落成发现；"需要 root / 需人工"是未知，不是问题，
		// 记成发现会把"没查到"伪装成"有问题"。
		persisted := 0
		for _, r := range results {
			if r.Status != compliance.StatusFail {
				continue
			}
			if _, err := db.UpsertFinding(database.FindingUpsert{
				HostID:   host.ID,
				Source:   "baseline_audit",
				Kind:     "baseline",
				RuleID:   r.ID,
				Title:    r.Title,
				Category: r.Category,
				Severity: r.Severity,
				Evidence: r.Detail,
			}); err != nil {
				logger.Warn("写入基线发现失败", zap.String("host", host.ID), zap.String("check", r.ID), zap.Error(err))
			} else {
				persisted++
			}
		}

		payload := map[string]interface{}{
			"persisted_findings": persisted,
			"host":     map[string]interface{}{"id": host.ID, "name": host.Name, "address": host.Address},
			"summary":  compliance.Summarize(results),
			"results":  results,
			"warnings": warns,
		}
		if len(missing) > 0 {
			payload["missing_ids"] = missing
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})
}

// logProbeScript 列出常见的、可读的日志文件（每行一个路径）。
//
// 与 awdshell 的候选表保持一致，另外补了 journald 环境常见的落盘位置。
func logProbeScript() string {
	return `for f in /var/log/nginx/access.log /var/log/nginx/error.log /var/log/apache2/access.log ` +
		`/var/log/apache2/error.log /var/log/httpd/access_log /var/log/httpd/error_log ` +
		`/var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog; do ` +
		`[ -r "$f" ] && echo "$f"; done`
}

// normalizeLogKind 把工具层的日志类型映射到规则引擎认的词表。
//
// 规则引擎只区分 web / system（空串表示不过滤），认证日志按 system 规则集处理；
// 传 "auth" / "other" 时要先归一，否则 RulesForKind 会把两类规则全过滤掉，
// 满页失败登录的 auth.log 会静默扫出 0 条命中。
func normalizeLogKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "web":
		return logscan.KindWeb
	case "auth", "system":
		return logscan.KindSystem
	default:
		return ""
	}
}

// allowedLogPath 只放行日志目录，避免只读权限被用来读任意文件。
func allowedLogPath(p string) bool {
	clean := strings.TrimSpace(p)
	if clean == "" || strings.Contains(clean, "..") {
		return false
	}
	return strings.HasPrefix(clean, "/var/log/") || strings.HasPrefix(clean, "/var/adm/")
}

// shellQuote 用单引号包裹参数，避免路径里的空格/特殊字符被 shell 解释。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
