package threatintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// userAgent 让对端能识别流量来源。abuse.ch 与 Shodan 都对无 UA 的脚本不太友好。
const userAgent = "Trail-ThreatIntel/1.0 (+https://github.com/guaidao2/Trail)"

// HTTPDoer 是所有情报源共用的 HTTP 层，集中处理代理、超时、UA 与响应体读取。
//
// 没有做重试：查询式源的退避由 service 层的令牌桶统一负责，
// feed 式源失败就该整轮失败并在下一轮重来，悄悄重试反而会掩盖问题。
type HTTPDoer struct {
	client *http.Client
}

// NewHTTPDoer 构造客户端。proxy 为空时跟随环境变量，内网部署常用显式代理。
func NewHTTPDoer(proxy string, timeout time.Duration) *HTTPDoer {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
	}
	if p := strings.TrimSpace(proxy); p != "" {
		if u, err := url.Parse(p); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPDoer{client: &http.Client{Transport: transport, Timeout: timeout}}
}

// getRaw 发 GET 并原样返回状态码与响应体。非 2xx 不当作 error——很多源用
// 404 表示"没有这条情报"，那是有效结果，需要调用方自己按协议解释。
func (d *HTTPDoer) getRaw(ctx context.Context, rawURL string, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		// 注意：这里和下面的 Do 失败是两条独立的泄漏路径。
		// NewRequest 内部走 url.Parse，失败时返回的 *url.Error 同样带着完整 URL；
		// endpoint 写错或 Key 里混进非法字符，照样能把密钥写进 last_error。
		return 0, nil, fmt.Errorf("构造对 %s 的请求失败: %w", sanitizeURLForError(rawURL), unwrapHTTPError(err))
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	for k, v := range headers {
		if strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := d.client.Do(req)
	if err != nil {
		// 不能把原始错误直接往上抛：net/http 的 *url.Error 会带上完整 URL，
		// 而 abuse.ch 的 Auth-Key 就在 URL path 里。一次 DNS 或代理失败
		// 就足以把 Key 写进 last_error 字段、日志、REST 响应和 MCP 输出。
		return 0, nil, fmt.Errorf("请求 %s 失败: %w", sanitizeURLForError(rawURL), unwrapHTTPError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("读取响应失败: %w", err)
	}
	return resp.StatusCode, body, nil
}

// sanitizeURLForError 只保留协议与主机，丢掉路径与查询串。
// 情报源的密钥常被放在路径或查询串里，报错信息里带着它等于到处泄密。
func sanitizeURLForError(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "情报源"
	}
	return u.Scheme + "://" + u.Host
}

// unwrapHTTPError 从 *url.Error 里取出底层原因，避免连带原始 URL。
func unwrapHTTPError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}
