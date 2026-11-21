// Package vulnintel 从公开源同步漏洞情报：CISA KEV、NVD 2.0、EPSS、GHSA 与 GitHub PoC。
//
// 设计要点：每个源独立状态（游标 / 最近成功 / 累计条数 / 最后错误），
// 单源失败不影响其它源；限速按是否配置 key 自适应；一次运行的耗时上限由 MaxRuntime 控制，
// 没跑完的窗口留给下一轮，而不是从头再来。
package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config 是一次同步的配置。
type Config struct {
	NVDAPIKey    string        // 可选；匿名 5 req/30s，有 key 50 req/30s
	GitHubToken  string        // 可选；GHSA 与 PoC 搜索用
	ProxyURL     string        // 全局出口代理（内网部署常用）
	BackfillDays int           // 首跑回看天数；0 表示从 1988 年起全量回填
	PageDelay    time.Duration // 请求间隔；0 时按是否有 key 推导
	MaxRuntime   time.Duration // 单次运行上限，默认 30 分钟
	POCEnabled   bool          // 是否为 KEV / 近期高危聚合 GitHub PoC
	EPSSEnabled  bool          // 是否同步 EPSS
	GHSAEnabled  bool          // 是否同步 GHSA（需 GitHub 出网；token 可选）
	OSVEnabled   bool          // 是否导入 OSV 生态全量包（语言包精确匹配的数据来源）
	OSVForce     bool          // 手动触发时忽略游标，全量重导一遍

	// NVDEnabled 为 nil 时默认开启；单源同步（只拉 KEV/EPSS）必须关掉，
	// 否则会顺带跑一次 NVD 全量回填。
	NVDEnabled *bool

	// 以下地址可选覆盖：内网镜像或测试用；留空走默认公开源。
	KEVURL       string
	NVDBaseURL   string
	EPSSBaseURL  string
	GitHubAPIURL string
	OSVBaseURL   string
}

func (c Config) nvdOn() bool {
	if c.NVDEnabled == nil {
		return true
	}
	return *c.NVDEnabled
}

func (c Config) kevURL() string {
	if v := strings.TrimSpace(c.KEVURL); v != "" {
		return v
	}
	return kevFeedURL
}

func (c Config) nvdBase() string {
	if v := strings.TrimSpace(c.NVDBaseURL); v != "" {
		return v
	}
	return nvdAPIBase
}

func (c Config) epssBase() string {
	if v := strings.TrimSpace(c.EPSSBaseURL); v != "" {
		return v
	}
	return epssAPIBase
}

func (c Config) githubBase() string {
	if v := strings.TrimSpace(c.GitHubAPIURL); v != "" {
		return v
	}
	return githubAPIURL
}

// PageDelayFor 按是否配置 NVD key 推导请求间隔。
//
// 匿名 5 次/30s ≈ 6.5s；有 key 50 次/30s ≈ 0.7s。
// 主同步与任何"快通道"必须共用这一份数字，否则快的那条会把慢的挤成 429。
func PageDelayFor(apiKey string) time.Duration {
	if strings.TrimSpace(apiKey) != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

// client 是带限速与代理的 HTTP 客户端。
type client struct {
	http      *http.Client
	delay     time.Duration
	mu        sync.Mutex
	next      time.Time
	userAgent string
}

func newClient(cfg Config) *client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	if proxy := strings.TrimSpace(cfg.ProxyURL); proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	delay := cfg.PageDelay
	if delay <= 0 {
		delay = PageDelayFor(cfg.NVDAPIKey)
	}
	return &client{
		http:      &http.Client{Transport: transport, Timeout: 90 * time.Second},
		delay:     delay,
		userAgent: "Trail-VulnIntel/1.0 (+https://github.com/guaidao2/Trail)",
	}
}

// wait 在发送下一个请求前按固定间隔放行。
func (c *client) wait(ctx context.Context) error {
	c.mu.Lock()
	now := time.Now()
	if c.next.After(now) {
		d := c.next.Sub(now)
		c.next = c.next.Add(c.delay)
		c.mu.Unlock()
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.next = now.Add(c.delay)
	c.mu.Unlock()
	return nil
}

// getJSON 拉取并解码 JSON；429/5xx 做有限次退避重试。
func (c *client) getJSON(ctx context.Context, rawURL string, headers map[string]string, out interface{}) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := c.wait(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			if !sleepCtx(ctx, backoff(attempt)) {
				return ctx.Err()
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("%s 返回 %d", rawURL, resp.StatusCode)
			if !sleepCtx(ctx, backoff(attempt)*2) {
				return ctx.Err()
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s 返回 %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(truncate(string(body), 200)))
		}
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("解析 %s 失败: %w", rawURL, err)
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s 请求失败", rawURL)
	}
	return lastErr
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt)) * time.Second
	if d > 20*time.Second {
		d = 20 * time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
