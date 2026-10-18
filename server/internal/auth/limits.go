package auth

import (
	"crypto/sha256"
	"net/netip"
	"sync"
	"time"
)

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "login rate limited" }

type attemptWindow struct {
	start time.Time
	count int
}

// Limits are process-local attempt budgets, not persistent account lockouts.
// Live entries are never evicted to admit attacker-chosen account/IP keys.
type loginLimiter struct {
	mu       sync.Mutex
	ips      map[netip.Addr]attemptWindow
	accounts map[[32]byte]attemptWindow
	capacity int
}

func newLoginLimiter(capacity int) *loginLimiter {
	return &loginLimiter{ips: make(map[netip.Addr]attemptWindow), accounts: make(map[[32]byte]attemptWindow), capacity: capacity}
}

func (l *loginLimiter) allow(ip netip.Addr, account string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := sha256.Sum256([]byte(account))
	ip = ip.Unmap()
	if len(l.ips) >= l.capacity || len(l.accounts) >= l.capacity {
		for k, v := range l.ips {
			if !now.Before(v.start.Add(time.Minute)) {
				delete(l.ips, k)
			}
		}
		for k, v := range l.accounts {
			if !now.Before(v.start.Add(time.Minute)) {
				delete(l.accounts, k)
			}
		}
	}
	ipWindow, ipKnown := l.ips[ip]
	accountWindow, accountKnown := l.accounts[key]
	if !ipKnown && len(l.ips) >= l.capacity || !accountKnown && len(l.accounts) >= l.capacity {
		return &RateLimitError{time.Minute}
	}
	if !now.Before(ipWindow.start.Add(time.Minute)) {
		ipWindow = attemptWindow{start: now}
	}
	if !now.Before(accountWindow.start.Add(time.Minute)) {
		accountWindow = attemptWindow{start: now}
	}
	var retry time.Duration
	if ipWindow.count >= 10 {
		retry = ipWindow.start.Add(time.Minute).Sub(now)
	}
	if accountWindow.count >= 5 {
		retry = max(retry, accountWindow.start.Add(time.Minute).Sub(now))
	}
	if retry > 0 {
		return &RateLimitError{retry}
	}
	ipWindow.count++
	accountWindow.count++
	l.ips[ip] = ipWindow
	l.accounts[key] = accountWindow
	return nil
}
