package threatintel

import (
	"os"
	"strings"
	"testing"
)

// liveEnabled 是真实网络测试的统一开关。默认跳过：CI 与离线环境不该依赖外网，
// 但接口契约又要能对着线上真实响应验一次，所以留这个显式入口。
func liveEnabled(t *testing.T) {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TRAIL_LIVE_THREATINTEL")) != "1" {
		t.Skip("跳过真实网络测试（设 TRAIL_LIVE_THREATINTEL=1 开启）")
	}
}
