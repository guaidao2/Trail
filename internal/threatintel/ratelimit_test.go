package threatintel

import (
	"context"
	"testing"
	"time"
)

// 节流器是「免费额度不被一次批量任务打光」的最后一道闸。
// 这里只测快速可判定的性质，不真等满一分钟。

func TestRateLimiterIntervalFromPerMinute(t *testing.T) {
	cases := map[int]time.Duration{
		4:  15 * time.Second, // VirusTotal 免费档
		60: time.Second,
		1:  time.Minute,
	}
	for perMinute, want := range cases {
		lim := newRateLimiter(perMinute)
		if lim == nil {
			t.Fatalf("perMinute=%d 不应返回 nil", perMinute)
		}
		if lim.interval != want {
			t.Errorf("perMinute=%d 的间隔应为 %v，实际 %v", perMinute, want, lim.interval)
		}
	}
}

func TestRateLimiterDisabledWhenZero(t *testing.T) {
	// 0 表示不限速：返回 nil，调用方据此完全跳过排队。
	if lim := newRateLimiter(0); lim != nil {
		t.Error("perMinute=0 应返回 nil 表示不限速")
	}
	if err := newRateLimiter(0).wait(context.Background()); err != nil {
		t.Errorf("nil 节流器的 wait 应直接返回: %v", err)
	}
}

func TestRateLimiterFirstCallDoesNotWait(t *testing.T) {
	lim := newRateLimiter(1) // 间隔一分钟
	start := time.Now()
	if err := lim.wait(context.Background()); err != nil {
		t.Fatalf("首次调用不应报错: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("首次调用应立即放行，实际等了 %v", elapsed)
	}
}

func TestRateLimiterHonorsContextCancel(t *testing.T) {
	lim := newRateLimiter(1) // 间隔一分钟
	if err := lim.wait(context.Background()); err != nil {
		t.Fatalf("预热失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := lim.wait(ctx)
	if err == nil {
		t.Fatal("ctx 到期时应返回错误而不是继续等")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("应在 ctx 到期后立即返回，实际等了 %v", elapsed)
	}
}
