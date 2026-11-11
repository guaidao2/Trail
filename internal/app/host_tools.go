package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"trail/internal/authctx"
	"trail/internal/database"
	"trail/internal/hostclient"
	"trail/internal/mcp"
	"trail/internal/mcp/builtin"
	"trail/internal/security"

	"go.uber.org/zap"
)

// registerHostTools 注册主机纳管相关 MCP 工具。
//
// 命令执行与文件传输类工具（host_exec / host_upload / host_download）与其它内置工具
// 一样走 Agent 的工具审批链路：开启审批模式后由 HITL 决定是否放行，关闭时也仍受
// host:exec 权限与工具执行拦截规则约束；只读工具（host_list/get/probe/inspect）按 host:read 校验。
func registerHostTools(server *mcp.Server, db *database.DB, box *security.SecretBox, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostList,
		ShortDescription: "列出纳管主机",
		Description:      "列出当前用户可见的纳管主机（SSH / Telnet），可按关键字、分组、环境、状态、协议过滤。返回主机 ID、名称、地址、协议、端口、状态与最近探测时间。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"keyword":     map[string]interface{}{"type": "string", "description": "按名称/地址/备注/标签模糊匹配"},
				"group":       map[string]interface{}{"type": "string", "description": "按分组精确过滤"},
				"environment": map[string]interface{}{"type": "string", "description": "按环境精确过滤（如 prod/test）"},
				"status":      map[string]interface{}{"type": "string", "description": "unknown / online / offline"},
				"protocol":    map[string]interface{}{"type": "string", "description": "ssh / telnet"},
				"page_size":   map[string]interface{}{"type": "integer", "description": "返回条数，默认 20，最大 100"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:read")
		if !ok {
			return textResult("缺少认证身份", true), nil
		}
		limit := intArg(args, "page_size", 20)
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		list, total, err := db.ListHosts(limit, 0, database.HostFilter{
			Keyword:     strArg(args, "keyword"),
			Group:       strArg(args, "group"),
			Environment: strArg(args, "environment"),
			Status:      strArg(args, "status"),
			Protocol:    strArg(args, "protocol"),
		}, access)
		if err != nil {
			return textResult("读取主机列表失败: "+err.Error(), true), nil
		}
		if len(list) == 0 {
			return textResult("当前范围下没有纳管主机", false), nil
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "共 %d 台主机（本页 %d 台）：\n\n", total, len(list))
		for _, h := range list {
			fmt.Fprintf(&sb, "- %s | ID=%s | %s:%d | %s | 用户=%s | 认证=%s | 状态=%s",
				h.Name, h.ID, h.Address, h.Port, h.Protocol, h.Username, h.AuthType, h.Status)
			if h.LastCheck != "" {
				fmt.Fprintf(&sb, " | 最近探测=%s", h.LastCheck)
			}
			if h.GroupName != "" {
				fmt.Fprintf(&sb, " | 分组=%s", h.GroupName)
			}
			if h.Env != "" {
				fmt.Fprintf(&sb, " | 环境=%s", h.Env)
			}
			sb.WriteString("\n")
		}
		return textResult(sb.String(), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostGet,
		ShortDescription: "查看主机详情",
		Description:      "按主机 ID 查看纳管主机的详情（不含任何凭据明文）。",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"id": map[string]interface{}{"type": "string", "description": "主机 ID"}},
			"required":   []string{"id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:read")
		if !ok {
			return textResult("缺少认证身份", true), nil
		}
		host, result := loadHostForTool(db, access, strArg(args, "id"))
		if result != nil {
			return result, nil
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "主机 %s（%s）\n", host.Name, host.ID)
		fmt.Fprintf(&sb, "- 地址: %s:%d (%s)\n", host.Address, host.Port, host.Protocol)
		fmt.Fprintf(&sb, "- 登录用户: %s（认证方式 %s）\n", host.Username, host.AuthType)
		fmt.Fprintf(&sb, "- 已保存凭据: %v\n", host.HasSecret)
		fmt.Fprintf(&sb, "- 状态: %s", host.Status)
		if host.LastError != "" {
			fmt.Fprintf(&sb, "（最近错误: %s）", host.LastError)
		}
		sb.WriteString("\n")
		if host.OSInfo != "" {
			fmt.Fprintf(&sb, "- 系统信息: %s\n", host.OSInfo)
		}
		if host.GroupName != "" || host.Env != "" {
			fmt.Fprintf(&sb, "- 分组/环境: %s / %s\n", host.GroupName, host.Env)
		}
		if host.Remark != "" {
			fmt.Fprintf(&sb, "- 备注: %s\n", host.Remark)
		}
		return textResult(sb.String(), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostProbe,
		ShortDescription: "探测主机连通性",
		Description:      "连接目标主机并取回内核/发行版、当前用户与主机名，同时把状态写回主机记录（online / offline）。",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"id": map[string]interface{}{"type": "string", "description": "主机 ID"}},
			"required":   []string{"id"},
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
		probeCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		probe, probeErr := hostclient.Probe(probeCtx, opts)
		status := "online"
		errMsg := ""
		if probeErr != nil || !probe.Online {
			status = "offline"
			if probeErr != nil {
				errMsg = probeErr.Error()
			} else {
				errMsg = probe.Error
			}
		}
		if err := db.UpdateHostProbe(host.ID, status, errMsg, probe.OSInfo); err != nil {
			logger.Warn("回写主机探测状态失败", zap.String("host", host.ID), zap.Error(err))
		}
		if status == "online" && strings.TrimSpace(host.HostKey) == "" && strings.TrimSpace(probe.HostKey) != "" {
			// 首次信任（TOFU）：记录指纹，后续连接按它校验。
			if err := db.SetHostKey(host.ID, probe.HostKey); err != nil {
				logger.Warn("记录主机密钥指纹失败", zap.String("host", host.ID), zap.Error(err))
			}
		}
		if status != "online" {
			return textResult(fmt.Sprintf("主机 %s 探测失败: %s", host.Name, errMsg), true), nil
		}
		return textResult(fmt.Sprintf("主机 %s 在线\n- 系统: %s\n- 用户: %s\n- 主机名: %s\n- 主机密钥: %s\n- 耗时: %dms",
			host.Name, probe.OSInfo, probe.RemoteUser, probe.RemoteHostname, probe.HostKey, probe.Duration.Milliseconds()), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostExec,
		ShortDescription: "在纳管主机上执行命令",
		Description:      "在指定纳管主机上执行一条命令并返回 stdout/stderr 与退出码。属于高风险写操作，受 host:exec 权限、调用拦截规则与 HITL 审批约束；请优先使用只读命令排查。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":              map[string]interface{}{"type": "string", "description": "主机 ID"},
				"command":         map[string]interface{}{"type": "string", "description": "要执行的命令"},
				"timeout_seconds": map[string]interface{}{"type": "integer", "description": "超时秒数，默认 60，最大 600"},
			},
			"required": []string{"id", "command"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:exec")
		if !ok {
			return textResult("缺少 host:exec 权限", true), nil
		}
		host, result := loadHostForTool(db, access, strArg(args, "id"))
		if result != nil {
			return result, nil
		}
		command := strings.TrimSpace(strArg(args, "command"))
		if command == "" {
			return textResult("command 不能为空", true), nil
		}
		timeout := time.Duration(intArg(args, "timeout_seconds", 60)) * time.Second
		if timeout <= 0 || timeout > 10*time.Minute {
			timeout = 60 * time.Second
		}
		opts, err := hostOptionsFromRecord(box, host)
		if err != nil {
			return textResult("准备连接参数失败: "+err.Error(), true), nil
		}
		execCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
		defer cancel()
		res, execErr := hostclient.Exec(execCtx, opts, command, timeout)
		if res == nil {
			return textResult("执行失败: "+execErr.Error(), true), nil
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "主机: %s (%s:%d)\n命令: %s\n退出码: %d\n耗时: %dms\n",
			host.Name, host.Address, host.Port, command, res.ExitCode, res.Duration.Milliseconds())
		if strings.TrimSpace(res.Stdout) != "" {
			fmt.Fprintf(&sb, "\n--- stdout ---\n%s", strings.TrimRight(res.Stdout, "\n"))
		}
		if strings.TrimSpace(res.Stderr) != "" {
			fmt.Fprintf(&sb, "\n--- stderr ---\n%s", strings.TrimRight(res.Stderr, "\n"))
		}
		if execErr != nil {
			fmt.Fprintf(&sb, "\n--- error ---\n%s", execErr.Error())
		}
		return textResult(sb.String(), execErr != nil), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostUpload,
		ShortDescription: "上传文件到纳管主机",
		Description:      "把 base64 内容写到纳管主机的指定路径（自动创建父目录并设置权限，默认 600）。属于高风险写操作，受 host:exec 权限与 HITL 审批约束。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":             map[string]interface{}{"type": "string", "description": "主机 ID"},
				"path":           map[string]interface{}{"type": "string", "description": "目标绝对路径"},
				"content_base64": map[string]interface{}{"type": "string", "description": "文件内容的 base64 编码"},
				"mode":           map[string]interface{}{"type": "string", "description": "文件权限，默认 600"},
			},
			"required": []string{"id", "path", "content_base64"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:exec")
		if !ok {
			return textResult("缺少 host:exec 权限", true), nil
		}
		host, result := loadHostForTool(db, access, strArg(args, "id"))
		if result != nil {
			return result, nil
		}
		content, err := base64.StdEncoding.DecodeString(strArg(args, "content_base64"))
		if err != nil {
			return textResult("content_base64 不是合法 base64", true), nil
		}
		opts, err := hostOptionsFromRecord(box, host)
		if err != nil {
			return textResult("准备连接参数失败: "+err.Error(), true), nil
		}
		uploadCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		if err := hostclient.UploadFile(uploadCtx, opts, strArg(args, "path"), content, strArg(args, "mode")); err != nil {
			return textResult("上传失败: "+err.Error(), true), nil
		}
		return textResult(fmt.Sprintf("已上传 %d 字节到 %s:%s", len(content), host.Name, strArg(args, "path")), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostDownload,
		ShortDescription: "从纳管主机读取文件",
		Description:      "读取纳管主机上指定路径的文件内容并以 base64 返回（单次 8MiB 上限）。需要 host:exec 权限。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":   map[string]interface{}{"type": "string", "description": "主机 ID"},
				"path": map[string]interface{}{"type": "string", "description": "文件绝对路径"},
			},
			"required": []string{"id", "path"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		access, ok := hostToolAccess(ctx, "host:exec")
		if !ok {
			return textResult("缺少认证身份", true), nil
		}
		host, result := loadHostForTool(db, access, strArg(args, "id"))
		if result != nil {
			return result, nil
		}
		opts, err := hostOptionsFromRecord(box, host)
		if err != nil {
			return textResult("准备连接参数失败: "+err.Error(), true), nil
		}
		downloadCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		content, err := hostclient.DownloadFile(downloadCtx, opts, strArg(args, "path"))
		if err != nil {
			return textResult("下载失败: "+err.Error(), true), nil
		}
		return textResult(fmt.Sprintf("path=%s bytes=%d\ncontent_base64=%s", strArg(args, "path"), len(content), base64.StdEncoding.EncodeToString(content)), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolHostInspect,
		ShortDescription: "主机基础巡检",
		Description:      "在一台纳管主机上执行一组只读巡检命令（系统与内核、负载与磁盘、登录用户、监听端口、失败登录、计划任务、SUID 文件计数、最近登录），返回原始结果便于研判与留证。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string", "description": "主机 ID"},
				"checks": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "要执行的检查项子集：system/load/disk/users/ports/logins/cron/suid/last。默认全部",
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
		checks := hostStringSliceArg(args, "checks")
		script := buildInspectScript(checks)
		inspectCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		res, execErr := hostclient.Exec(inspectCtx, opts, script, 2*time.Minute)
		if res == nil {
			return textResult("巡检执行失败: "+execErr.Error(), true), nil
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "主机 %s (%s:%d) 巡检结果\n", host.Name, host.Address, host.Port)
		fmt.Fprintf(&sb, "退出码: %d，耗时: %dms\n\n%s\n", res.ExitCode, res.Duration.Milliseconds(), strings.TrimSpace(res.Stdout))
		if strings.TrimSpace(res.Stderr) != "" {
			fmt.Fprintf(&sb, "\n--- stderr ---\n%s", strings.TrimSpace(res.Stderr))
		}
		if execErr != nil {
			fmt.Fprintf(&sb, "\n--- error ---\n%s", execErr.Error())
		}
		return textResult(sb.String(), execErr != nil), nil
	})

	logger.Debug("主机纳管工具注册成功")
}

// inspectCommands 是巡检脚本的组成，按检查项分组，便于 Agent 只跑关心的部分。
var inspectCommands = []struct {
	key   string
	title string
	cmd   string
}{
	{"system", "系统与内核", `echo "[system]"; uname -a; cat /etc/os-release 2>/dev/null | head -3; uptime`},
	{"load", "负载与内存", `echo "[load]"; (top -bn1 2>/dev/null | head -5) || true; free -m 2>/dev/null || true`},
	{"disk", "磁盘使用", `echo "[disk]"; df -h 2>/dev/null | head -15`},
	{"users", "登录用户", `echo "[users]"; who 2>/dev/null; echo; id 2>/dev/null`},
	{"ports", "监听端口", `echo "[ports]"; (ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null) | head -40`},
	{"logins", "失败登录", `echo "[logins]"; (grep -i "failed password" /var/log/auth.log 2>/dev/null || grep -i "failed password" /var/log/secure 2>/dev/null || echo "no auth log readable") | tail -20`},
	{"cron", "计划任务", `echo "[cron]"; (crontab -l 2>/dev/null || echo "no user crontab"); ls -la /etc/cron.d 2>/dev/null | head -20`},
	{"suid", "SUID 文件", `echo "[suid]"; find / -xdev -perm -4000 -type f 2>/dev/null | head -40`},
	{"last", "最近登录", `echo "[last]"; last -n 10 2>/dev/null || echo "last unavailable"`},
}

func buildInspectScript(checks []string) string {
	wanted := make(map[string]bool, len(checks))
	for _, c := range checks {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			wanted[c] = true
		}
	}
	parts := make([]string, 0, len(inspectCommands))
	for _, item := range inspectCommands {
		if len(wanted) > 0 && !wanted[item.key] {
			continue
		}
		parts = append(parts, item.cmd)
	}
	return strings.Join(parts, "; echo; ")
}

// hostToolAccess 从工具上下文取当前身份与权限作用域。
func hostToolAccess(ctx context.Context, permission string) (database.RBACListAccess, bool) {
	principal, ok := authctx.PrincipalFromContext(ctx)
	if !ok {
		return database.RBACListAccess{}, false
	}
	if !principal.HasPermission(permission) {
		return database.RBACListAccess{}, false
	}
	return database.RBACListAccess{UserID: principal.UserID, Scope: principal.ScopeFor(permission)}, true
}

// loadHostForTool 读取主机并做资源级访问校验；失败时返回可直接回给模型的错误结果。
func loadHostForTool(db *database.DB, access database.RBACListAccess, id string) (*database.Host, *mcp.ToolResult) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, textResult("id 不能为空", true)
	}
	host, err := db.GetHost(id)
	if err != nil {
		return nil, textResult("读取主机失败: "+err.Error(), true)
	}
	if host == nil {
		return nil, textResult("主机不存在: "+id, true)
	}
	if access.UserID != "" && access.Scope != database.RBACScopeAll {
		if !db.UserCanAccessResource(access.UserID, access.Scope, "host", host.ID) {
			return nil, textResult("无权访问该主机", true)
		}
	}
	return host, nil
}

// hostOptionsFromRecord 解密凭据并组装连接参数，明文只在内存中使用。
func hostOptionsFromRecord(box *security.SecretBox, host *database.Host) (hostclient.Options, error) {
	if box == nil {
		return hostclient.Options{}, fmt.Errorf("凭据加密未初始化")
	}
	secret, err := box.Decrypt(host.SecretCipher)
	if err != nil {
		return hostclient.Options{}, err
	}
	passphrase, err := box.Decrypt(host.PassphraseCipher)
	if err != nil {
		return hostclient.Options{}, err
	}
	opts := hostclient.Options{
		Protocol:   host.Protocol,
		Address:    host.Address,
		Port:       host.Port,
		Username:   host.Username,
		HostKeyPin: host.HostKey,
	}
	if strings.EqualFold(host.AuthType, "key") {
		opts.PrivateKey = secret
		opts.Passphrase = passphrase
	} else {
		opts.Password = secret
	}
	return opts, nil
}

func hostStringSliceArg(args map[string]interface{}, key string) []string {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	out := make([]string, 0, 4)
	switch v := raw.(type) {
	case []string:
		out = append(out, v...)
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		for _, part := range strings.Split(v, ",") {
			out = append(out, part)
		}
	}
	return out
}
