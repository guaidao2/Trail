package app

import (
	"trail/internal/config"
)

// threatIntelCfgSnapshot 读取威胁情报配置的并发安全副本。
// 启动时由 configHandler 注入；未注入时返回零值（等价于只跑免 key 的源）。
var threatIntelCfgSnapshot = func() config.ThreatIntelConfig {
	return config.ThreatIntelConfig{}
}
