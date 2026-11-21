package app

import (
	"sync"

	"trail/internal/config"
)

// vulnIntelSyncMu 串行化三个同步入口（自动 ticker / REST 手动同步 / MCP 工具），
// 避免并发推进同一游标导致某个窗口被跳过。
var vulnIntelSyncMu sync.Mutex

// vulnIntelCfgSnapshot 读取漏洞情报配置的并发安全副本。
// 启动时由 configHandler 注入；未注入时返回零值（等价于未配置）。
var vulnIntelCfgSnapshot = func() config.VulnIntelConfig {
	return config.VulnIntelConfig{}
}
