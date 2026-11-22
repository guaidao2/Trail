//go:build cgo

package threatintel

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"trail/internal/database"
)

// 这组测试会真的出网打 Shodan InternetDB，因此默认跳过。
// 跑法：TRAIL_LIVE_THREATINTEL=1 go test ./internal/threatintel/ -run Live -v
//
// 为什么值得留：接口字段是外部契约，写死一个假响应只能证明解析器对，
// 证明不了对方还在按这个形状回话。这条测试是"接口没悄悄变"的哨兵。
func newLiveService(t *testing.T) (*Service, *database.DB) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "live.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	svc := NewService(db, Config{Timeout: 20 * time.Second}, zap.NewNop())
	if err := svc.EnsureSources(context.Background()); err != nil {
		t.Fatalf("注册源失败: %v", err)
	}
	return svc, db
}

func TestLiveInternetDBRealQuery(t *testing.T) {
	liveEnabled(t)
	svc, _ := newLiveService(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 60.205.92.121 是官方文档示例里那种"有真实暴露面"的地址：
	// 有端口、有 CPE、有已知漏洞，能同时验证三条解析路径。
	res, err := svc.Query(ctx, "ip", "60.205.92.121")
	if err != nil {
		t.Fatalf("真实查询失败: %v", err)
	}
	if len(res.Results) == 0 {
		t.Fatalf("应有 internetdb 结果，skipped=%v", res.Skipped)
	}
	var found *Result
	for _, r := range res.Results {
		if r.Source == "internetdb" {
			found = r
		}
	}
	if found == nil {
		t.Fatalf("结果里没有 internetdb：%+v", res.Skipped)
	}
	if found.Verdict != VerdictExposure {
		t.Errorf("verdict 应为 exposure，实际 %q", found.Verdict)
	}
	if !strings.Contains(found.Summary, "开放端口") {
		t.Errorf("摘要应包含端口信息，实际: %s", found.Summary)
	}
	if strings.TrimSpace(found.Payload) == "" {
		t.Error("原始响应应被保留，便于溯源")
	}
	t.Logf("摘要: %s", found.Summary)

	// 第二次查询应命中缓存，不再打网络。
	cached, err := svc.Query(ctx, "ip", "60.205.92.121")
	if err != nil {
		t.Fatalf("二次查询失败: %v", err)
	}
	if len(cached.Results) == 0 || !cached.Results[0].Cached {
		t.Errorf("二次查询应来自缓存，实际: %+v", cached.Results)
	}
}

func TestLivePrivateIPShortCircuit(t *testing.T) {
	liveEnabled(t)
	svc, _ := newLiveService(t)
	res, err := svc.Query(context.Background(), "ip", "192.168.1.10")
	if err != nil {
		t.Fatalf("私网查询不应报错: %v", err)
	}
	if len(res.Results) != 0 {
		t.Errorf("私网地址不应发起外部查询，实际有 %d 条结果", len(res.Results))
	}
	if !strings.Contains(res.Note, "内网") {
		t.Errorf("应说明是内网地址，实际 note=%q", res.Note)
	}
}

// OTX 的 URL 类型要把整条 URL 塞进 path，不转义会被 ? 和 / 破坏。
// 这条真实请求用来确认转义后的形式 OTX 是认的，而不是只能靠读代码判断。
func TestLiveOTXURLQuery(t *testing.T) {
	liveEnabled(t)
	doer := NewHTTPDoer("", 25*time.Second)
	p := NewOTX(doer, "")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	target := "http://www.example.com/evil/path?id=1&x=2"
	res, err := p.Query(ctx, Indicator{Type: "url", Value: target, Normalized: target}, "")
	if err != nil {
		t.Fatalf("OTX URL 查询不应报错（转义没被接受？）: %v", err)
	}
	if res.HTTPStatus != 200 && res.HTTPStatus != 404 {
		t.Errorf("应有 200 或 404，实际 %d", res.HTTPStatus)
	}
	if strings.TrimSpace(res.Normalized) == "" {
		t.Error("应回填指标值")
	}
	t.Logf("OTX URL 查询 HTTP=%d verdict=%s summary=%s", res.HTTPStatus, res.Verdict, res.Summary)
}
