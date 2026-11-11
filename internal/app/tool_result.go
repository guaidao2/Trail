package app

import "trail/internal/mcp"

// textResult 构造一个纯文本工具结果（原先定义在已删除的 project_fact_tools.go 里，
// 资产/主机等工具仍在使用，这里保留共享实现）。
func textResult(msg string, isErr bool) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.Content{{Type: "text", Text: msg}},
		IsError: isErr,
	}
}

// strArg 读取字符串参数（缺失或类型不符时返回空串）。
func strArg(args map[string]interface{}, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// boolArg 读取布尔参数（缺失或类型不符时返回 false）。
func boolArg(args map[string]interface{}, key string) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

// intArg 读取整数参数（兼容 JSON 的 float64），缺失时返回默认值。
func intArg(args map[string]interface{}, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return def
	}
}
