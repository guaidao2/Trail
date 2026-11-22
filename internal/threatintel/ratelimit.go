package threatintel

import (
	"context"
	"sync"
	"time"
)

// rateLimiter 是按源共享的请求节流器，用"最小间隔"实现，
// 不引入额外依赖：perMinute 次/分等价于每 (60/perMinute) 秒放行一个。
//
// 为什么要它：一些源的免费额度是硬限速（VirusTotal 4 次/分钟），
// 并行或连续查询会直接吃 429；被限速后重试反而更糟。
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	interval := time.Minute / time.Duration(perMinute)
	if interval <= 0 {
		interval = time.Millisecond
	}
	return &rateLimiter{interval: interval}
}

// wait 阻塞到下一个放行时刻。ctx 取消时立刻返回。
func (l *rateLimiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.IsZero() || !l.next.After(now) {
		l.next = now.Add(l.interval)
		l.mu.Unlock()
		return nil
	}
	delay := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// limiterFor 取（或按当前配额重建）某个源的节流器。
// 配置热更新把 rps 调大调小时，旧节流器会被替换掉。
func (s *Service) limiterFor(source string, perMinute int) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	s.limMu.Lock()
	defer s.limMu.Unlock()
	if s.limiters == nil {
		s.limiters = map[string]*rateLimiter{}
	}
	if existing, ok := s.limiters[source]; ok {
		if existing != nil && existing.interval == time.Minute/time.Duration(perMinute) {
			return existing
		}
	}
	lim := newRateLimiter(perMinute)
	s.limiters[source] = lim
	return lim
}
