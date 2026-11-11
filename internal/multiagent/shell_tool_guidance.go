package multiagent

import "strings"

func shellToolsPresent(toolNames []string) bool {
	for _, n := range toolNames {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "exec", "execute":
			return true
		}
	}
	return false
}

// injectShellToolGuidance 在系统提示末尾追加 exec/execute 分工（仅当工具列表含 exec 或 execute）。
func injectShellToolGuidance(instruction string, toolNames []string) string {
	if !shellToolsPresent(toolNames) {
		return instruction
	}
	block := strings.TrimSpace(shellExecExecuteGuidance)
	if block == "" {
		return instruction
	}
	s := strings.TrimSpace(instruction)
	if s == "" {
		return block
	}
	return s + "\n\n" + block
}

// shellExecExecuteGuidance 说明本机 shell 工具与远程主机工具的分工。
const shellExecExecuteGuidance = `命令执行分工：
- exec/execute 只作用于本平台所在主机，用于本地排查与辅助脚本。
- 远端主机一律使用 host_* 工具（host_list / host_probe / host_inspect / host_exec / host_download），不要用 exec 拼 ssh 连接串。
- 命令执行类动作受 host:exec 权限、调用拦截规则与人机协同审批约束；执行前说明影响面与回滚方式。`
