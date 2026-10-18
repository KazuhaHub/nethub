package auth

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginLimitsBothBudgetsAndRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	ip := netip.MustParseAddr("192.0.2.1")
	limiter := newLoginLimiter(100)
	for i := 0; i < 5; i++ {
		if err := limiter.Allow(ip, "one@example.com", now); err != nil {
			t.Fatal(err)
		}
	}
	var limited *RateLimitError
	if err := limiter.Allow(netip.MustParseAddr("192.0.2.2"), "one@example.com", now.Add(time.Second)); !errors.As(err, &limited) || limited.RetryAfter != 59*time.Second {
		t.Fatalf("account budget: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := limiter.Allow(ip, fmt.Sprintf("other-%d@example.com", i), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := limiter.Allow(ip, "fresh@example.com", now); !errors.As(err, &limited) {
		t.Fatal("IP budget bypassed through different accounts")
	}
	if err := limiter.Allow(ip, "one@example.com", now.Add(time.Minute)); err != nil {
		t.Fatal("account remained locked after window")
	}
}

func TestLoginLimiterCapacityAndConcurrentAdmission(t *testing.T) {
	now := time.Unix(1000, 0)
	ip := netip.MustParseAddr("192.0.2.1")
	limiter := newLoginLimiter(1)
	if err := limiter.Allow(ip, "one", now); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Allow(ip, "new", now); err == nil {
		t.Fatal("live capacity record was evicted")
	}
	if len(limiter.accounts) != 1 || len(limiter.ips) != 1 {
		t.Fatal("capacity exceeded")
	}
	if err := limiter.Allow(ip, "new", now.Add(time.Minute)); err != nil {
		t.Fatal("expired capacity not reclaimed")
	}
	limiter = newLoginLimiter(10)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			if limiter.Allow(ip, "same", now) == nil {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 5 {
		t.Fatalf("concurrent admissions=%d", accepted.Load())
	}
}
