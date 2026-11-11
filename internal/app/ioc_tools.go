package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"trail/internal/database"
	"trail/internal/hostclient"
	"trail/internal/mcp"
	"trail/internal/mcp/builtin"
	"trail/internal/security"

	"go.uber.org/zap"
)

// registerIOCTools 注册 IOC 情报库相关工具。
//
// 权限划分：查询类要 ioc:read；写入/改状态要 ioc:write；
// 封禁/解封会真的在目标主机上改防火墙，所以同时要求 host:exec 与 ioc:write。
//
// 封禁默认 dry_run=true：Agent 只能"给出建议"，真正执行必须显式传 dry_run=false，
// 也就是人明确说了"封"才封。这与"封禁不需要额外审批"的约定一致——人已经说了，
// 不需要再拦一道 HITL，但工具默认不会替人做决定。
func registerIOCTools(server *mcp.Server, db *database.DB, box *security.SecretBox, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolIOCLookup,
		ShortDescription: "查询 IOC 情报",
		Description:      "按指标值查询情报库：这个 IP / 域名 / URL / 哈希 / 邮箱 / 文件名是否在档、当前状态（观察/确认/已封禁/误报）、置信度、首次与最近出现时间、命中次数，以及它命中过哪些主机（含每台主机的证据与是否已封禁）。研判时先查这里。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"value": map[string]interface{}{"type": "string", "description": "指标值，如 1.2.3.4 / evil.example.com / <sha256>"},
				"type":  map[string]interface{}{"type": "string", "description": "指标类型：ip / domain / url / md5 / sha1 / sha256 / email / filename；留空默认 ip"},
			},
			"required": []string{"value"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "ioc:read"); !ok {
			return textResult("缺少 ioc:read 权限", true), nil
		}
		iocType := strings.ToLower(strings.TrimSpace(strArg(args, "type")))
		if iocType == "" {
			iocType = "ip"
		}
		value := strings.TrimSpace(strArg(args, "value"))
		if value == "" {
			return textResult("value 不能为空", true), nil
		}
		normalized := database.NormalizeIOCValue(iocType, value)
		hit, err := db.GetIOCByValue(iocType, value)
		if err != nil {
			return textResult("查询 IOC 失败: "+err.Error(), true), nil
		}
		if hit == nil {
			payload := map[string]interface{}{
				"found":      false,
				"type":       iocType,
				"value":      value,
				"normalized": normalized,
				"hint":       "情报库中没有这条记录；若日志/主机证据充分，可用 ioc_upsert 以 observed 状态入库",
			}
			b, _ := json.MarshalIndent(payload, "", "  ")
			return textResult(string(b), false), nil
		}
		hosts, err := db.ListIOCHits(hit.ID, 100)
		if err != nil {
			return textResult("查询关联主机失败: "+err.Error(), true), nil
		}
		payload := map[string]interface{}{"found": true, "ioc": hit, "hosts": hosts}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolIOCUpsert,
		ShortDescription: "写入 IOC 情报",
		Description:      "把一条指标写入情报库（按类型+归一值去重，重复写入只更新最后出现时间与字段）。默认状态 observed（观察）——日志里出现过不等于有罪；只有确认过的才应改成 confirmed。可设置置信度、严重度、过期时间、标签与备注。状态只升不降（observed → confirmed → blocked），误报为终态。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"value":      map[string]interface{}{"type": "string", "description": "指标值"},
				"type":       map[string]interface{}{"type": "string", "description": "ip / domain / url / md5 / sha1 / sha256 / email / filename；默认 ip"},
				"status":     map[string]interface{}{"type": "string", "description": "observed（默认）/ confirmed / blocked / false_positive"},
				"confidence": map[string]interface{}{"type": "integer", "description": "置信度 0-100，默认 50"},
				"severity":   map[string]interface{}{"type": "string", "description": "critical / high / medium（默认）/ low / info"},
				"source":     map[string]interface{}{"type": "string", "description": "来源：manual / log_scan / baseline_audit / external"},
				"tags":       map[string]interface{}{"type": "string", "description": "逗号分隔标签，如 scanner,brute-force"},
				"note":       map[string]interface{}{"type": "string", "description": "备注：这条情报的来源与判断依据"},
				"expires_at": map[string]interface{}{"type": "string", "description": "过期时间（RFC3339 或 YYYY-MM-DD）；留空表示不过期"},
			},
			"required": []string{"value"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "ioc:write")
		if !ok {
			return textResult("缺少 ioc:write 权限", true), nil
		}
		iocType := strings.ToLower(strings.TrimSpace(strArg(args, "type")))
		if iocType == "" {
			iocType = "ip"
		}
		rec, created, err := db.UpsertIOC(database.IOCUpsert{
			Type:       iocType,
			Value:      strArg(args, "value"),
			Status:     strArg(args, "status"),
			Confidence: intArg(args, "confidence", 50),
			Severity:   strArg(args, "severity"),
			Source:     strArg(args, "source"),
			Tags:       strArg(args, "tags"),
			Note:       strArg(args, "note"),
			ExpiresAt:  strArg(args, "expires_at"),
			OwnerID:    strings.TrimSpace(access.UserID),
		})
		if err != nil {
			return textResult("写入 IOC 失败: "+err.Error(), true), nil
		}
		payload := map[string]interface{}{"created": created, "ioc": rec}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolIOCList,
		ShortDescription: "列出 IOC 情报",
		Description:      "分页列出情报库条目，可按关键字、类型、状态过滤，也可只看命中过某台主机的条目；同时返回各状态的数量概览。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"keyword": map[string]interface{}{"type": "string", "description": "按值/备注/标签模糊匹配"},
				"type":    map[string]interface{}{"type": "string", "description": "按类型过滤"},
				"status":  map[string]interface{}{"type": "string", "description": "observed / confirmed / blocked / false_positive"},
				"host_id": map[string]interface{}{"type": "string", "description": "只看命中过这台主机的 IOC"},
				"limit":   map[string]interface{}{"type": "integer", "description": "返回条数，默认 50，最大 200"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "ioc:read"); !ok {
			return textResult("缺少 ioc:read 权限", true), nil
		}
		list, total, err := db.ListIOCs(database.IOCFilter{
			Keyword: strArg(args, "keyword"),
			Type:    strArg(args, "type"),
			Status:  strArg(args, "status"),
			HostID:  strArg(args, "host_id"),
		}, intArg(args, "limit", 50), 0)
		if err != nil {
			return textResult("列出 IOC 失败: "+err.Error(), true), nil
		}
		counts, _ := db.CountIOCByStatus()
		payload := map[string]interface{}{"total": total, "items": list, "by_status": counts}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolIOCRecordHit,
		ShortDescription: "记录 IOC 命中主机",
		Description:      "记录「某条 IOC 命中过某台主机」的证据（来源、规则 ID、证据片段）。同一对 IOC 与主机只累加次数，不重复建行；这是攻击者档案与主机关联的写入口。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ioc_id":   map[string]interface{}{"type": "string", "description": "IOC 记录 ID"},
				"host_id":  map[string]interface{}{"type": "string", "description": "主机 ID"},
				"source":   map[string]interface{}{"type": "string", "description": "来源：log_scan / baseline_audit / manual"},
				"rule_id":  map[string]interface{}{"type": "string", "description": "命中的规则 ID（如 SQLI-4001）"},
				"evidence": map[string]interface{}{"type": "string", "description": "证据片段：日志行或检查输出"},
			},
			"required": []string{"ioc_id", "host_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if _, ok := hostToolAccess(ctx, "ioc:write"); !ok {
			return textResult("缺少 ioc:write 权限", true), nil
		}
		iocID := strings.TrimSpace(strArg(args, "ioc_id"))
		hostID := strings.TrimSpace(strArg(args, "host_id"))
		if err := db.RecordIOCHit(iocID, hostID, strArg(args, "source"), strArg(args, "rule_id"), strArg(args, "evidence")); err != nil {
			return textResult("记录命中失败: "+err.Error(), true), nil
		}
		hits, err := db.ListIOCHits(iocID, 50)
		if err != nil {
			return textResult("记录成功但读取关联失败: "+err.Error(), false), nil
		}
		b, _ := json.MarshalIndent(map[string]interface{}{"ioc_id": iocID, "hosts": hits}, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolIOCBlock,
		ShortDescription: "按 IOC 封禁主机",
		Description:      "在指定主机上用 iptables 封禁一个 IOC（仅支持类型 ip）。默认 dry_run=true，只返回将要执行的命令；只有人明确要求封禁时才传 dry_run=false。封禁记录（命令原文与撤销命令）会写进 IOC 的主机关联里，可用 ioc_unblock 撤销。私有网段、回环与已纳管主机地址会被拒绝。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ioc_id":   map[string]interface{}{"type": "string", "description": "要封禁的 IOC ID"},
				"host_ids": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "在哪几台主机上执行封禁"},
				"dry_run":  map[string]interface{}{"type": "boolean", "description": "true（默认）只返回命令不执行；false 才真正下发"},
				"chain":    map[string]interface{}{"type": "string", "description": "iptables 链，默认 INPUT"},
			},
			"required": []string{"ioc_id", "host_ids"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:exec")
		if !ok {
			return textResult("缺少 host:exec 权限", true), nil
		}
		if _, ok := hostToolAccess(ctx, "ioc:write"); !ok {
			return textResult("缺少 ioc:write 权限", true), nil
		}
		rec, err := db.GetIOC(strings.TrimSpace(strArg(args, "ioc_id")))
		if err != nil {
			return textResult("读取 IOC 失败: "+err.Error(), true), nil
		}
		if rec == nil {
			return textResult("IOC 不存在", true), nil
		}
		if rec.Type != "ip" {
			return textResult(fmt.Sprintf("当前只支持封禁 ip 类型，这条是 %s；域名/URL 请在边界设备或 DNS 层处理", rec.Type), true), nil
		}
		if rec.Status == database.IOCStatusFalsePositive {
			return textResult("这条 IOC 已标记为误报，拒绝封禁", true), nil
		}
		if rec.Status == database.IOCStatusObserved {
			return textResult("这条 IOC 还是观察态（observed），不允许封禁；请先确认情报（ioc_upsert status=confirmed）再下发", true), nil
		}
		ip := net.ParseIP(rec.Normalized)
		if ip == nil {
			return textResult("IOC 值不是合法 IP: "+rec.Value, true), nil
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			return textResult("拒绝封禁私有/回环/链路本地地址（会误伤内网或本机）: "+ip.String(), true), nil
		}
		chain := strings.TrimSpace(strArg(args, "chain"))
		if chain == "" {
			chain = "INPUT"
		}
		if !validIPTablesChain(chain) {
			return textResult("chain 只允许字母、数字、下划线与短横线（如 INPUT / DOCKER-USER）", true), nil
		}
		dryRun := boolArgDefault(args, "dry_run", true)
		hostIDs := hostStringSliceArg(args, "host_ids")
		if len(hostIDs) == 0 {
			return textResult("host_ids 不能为空", true), nil
		}

		type hostOutcome struct {
			HostID         string `json:"host_id"`
			OK             bool   `json:"ok"`
			Output         string `json:"output,omitempty"`
			Error          string `json:"error,omitempty"`
			BlockCommand   string `json:"block_command"`
			UnblockCommand string `json:"unblock_command"`
		}
		outcomes := make([]hostOutcome, 0, len(hostIDs))
		for _, hid := range hostIDs {
			out := hostOutcome{
				HostID:         hid,
				BlockCommand:   fmt.Sprintf("iptables -C %s -s %s -j DROP 2>/dev/null || iptables -I %s -s %s -j DROP", chain, ip, chain, ip),
				UnblockCommand: fmt.Sprintf("iptables -D %s -s %s -j DROP", chain, ip),
			}
			if dryRun {
				out.OK = true
				outcomes = append(outcomes, out)
				continue
			}
			host, res := loadHostForTool(db, access, hid)
			if res != nil {
				out.Error = "主机不可访问或不存在"
				outcomes = append(outcomes, out)
				continue
			}
			opts, err := hostOptionsFromRecord(box, host)
			if err != nil {
				out.Error = "准备连接参数失败: " + err.Error()
				outcomes = append(outcomes, out)
				continue
			}
			execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			r, execErr := hostclient.Exec(execCtx, opts, out.BlockCommand, 30*time.Second)
			cancel()
			if r == nil {
				out.Error = errText(execErr)
				outcomes = append(outcomes, out)
				continue
			}
			out.Output = strings.TrimSpace(r.Stdout + r.Stderr)
			if r.ExitCode != 0 {
				out.Error = fmt.Sprintf("exit status %d", r.ExitCode)
			} else {
				out.OK = true
				if markErr := db.MarkIOCHostBlocked(rec.ID, hid, out.BlockCommand, out.UnblockCommand); markErr != nil {
					out.Error = "已下发但记录失败: " + markErr.Error()
				}
			}
			outcomes = append(outcomes, out)
		}
		if !dryRun {
			allOK := true
			for _, o := range outcomes {
				if !o.OK {
					allOK = false
				}
			}
			if allOK {
				if err := db.SetIOCStatus(rec.ID, database.IOCStatusBlocked); err != nil {
					logger.Warn("IOC 封禁成功但状态更新失败", zap.String("ioc", rec.ID), zap.Error(err))
				}
			}
		}
		payload := map[string]interface{}{
			"ioc":      map[string]interface{}{"id": rec.ID, "value": rec.Normalized, "type": rec.Type},
			"dry_run":  dryRun,
			"chain":    chain,
			"outcomes": outcomes,
			"hint":     "dry_run=true 只给命令；确认要封时用 dry_run=false 重跑。撤销用 ioc_unblock。",
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		return textResult(string(b), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolIOCUnblock,
		ShortDescription: "撤销 IOC 封禁",
		Description:      "撤销某条 IOC 在指定主机上的封禁（按记录里的撤销命令执行），并清除封禁留痕。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ioc_id":   map[string]interface{}{"type": "string", "description": "IOC ID"},
				"host_ids": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "要解封的主机"},
			},
			"required": []string{"ioc_id", "host_ids"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:exec")
		if !ok {
			return textResult("缺少 host:exec 权限", true), nil
		}
		if _, ok := hostToolAccess(ctx, "ioc:write"); !ok {
			return textResult("缺少 ioc:write 权限", true), nil
		}
		iocID := strings.TrimSpace(strArg(args, "ioc_id"))
		hostIDs := hostStringSliceArg(args, "host_ids")
		hits, err := db.ListIOCHits(iocID, 500)
		if err != nil {
			return textResult("读取封禁记录失败: "+err.Error(), true), nil
		}
		byHost := map[string]*database.IOCHit{}
		for _, h := range hits {
			byHost[h.HostID] = h
		}
		type outcome struct {
			HostID  string `json:"host_id"`
			OK      bool   `json:"ok"`
			Command string `json:"command,omitempty"`
			Error   string `json:"error,omitempty"`
		}
		outcomes := make([]outcome, 0, len(hostIDs))
		for _, hid := range hostIDs {
			o := outcome{HostID: hid}
			hit := byHost[hid]
			if hit == nil || strings.TrimSpace(hit.UnblockCommand) == "" {
				o.Error = "没有这条 IOC 在该主机上的封禁记录"
				outcomes = append(outcomes, o)
				continue
			}
			o.Command = hit.UnblockCommand
			host, res := loadHostForTool(db, access, hid)
			if res != nil {
				o.Error = "主机不可访问或不存在"
				outcomes = append(outcomes, o)
				continue
			}
			opts, err := hostOptionsFromRecord(box, host)
			if err != nil {
				o.Error = "准备连接参数失败: " + err.Error()
				outcomes = append(outcomes, o)
				continue
			}
			execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			r, execErr := hostclient.Exec(execCtx, opts, hit.UnblockCommand, 30*time.Second)
			cancel()
			if r == nil {
				o.Error = errText(execErr)
				outcomes = append(outcomes, o)
				continue
			}
			if r.ExitCode != 0 {
				o.Error = fmt.Sprintf("exit status %d: %s", r.ExitCode, strings.TrimSpace(r.Stdout+r.Stderr))
			} else {
				o.OK = true
				if markErr := db.MarkIOCHostUnblocked(iocID, hid); markErr != nil {
					o.Error = "已撤销但记录失败: " + markErr.Error()
				}
			}
			outcomes = append(outcomes, o)
		}
		if n, err := db.CountIOCHostBlocked(iocID); err == nil && n == 0 {
			if rec, _ := db.GetIOC(iocID); rec != nil && rec.Status == database.IOCStatusBlocked {
				if err := db.SetIOCStatus(iocID, database.IOCStatusConfirmed); err != nil {
					logger.Warn("IOC 已全部解封但状态回退失败", zap.String("ioc", iocID), zap.Error(err))
				}
			}
		}
		b, _ := json.MarshalIndent(map[string]interface{}{"ioc_id": iocID, "outcomes": outcomes}, "", "  ")
		return textResult(string(b), false), nil
	})
}

// boolArg 读取布尔参数，缺省时用 def。
func boolArgDefault(args map[string]interface{}, key string, def bool) bool {
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "true" || s == "1" || s == "yes" {
			return true
		}
		if s == "false" || s == "0" || s == "no" {
			return false
		}
	}
	return def
}

// validIPTablesChain 校验链名，避免把用户输入拼进远端命令时被注入。
func validIPTablesChain(chain string) bool {
	if chain == "" || len(chain) > 32 {
		return false
	}
	for _, r := range chain {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
