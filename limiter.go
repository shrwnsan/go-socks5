package socks5

import (
	"sync"
	"time"
)

type limiterEntry struct {
	count     int
	windowEnd time.Time
}

// FixedWindowLimiter limits auth attempts per user/userAddr within a time window.
// Use nil limiter to disable limiting entirely.
type FixedWindowLimiter struct {
	maxAttempts int
	window      time.Duration
	now         func() time.Time

	mu      sync.Mutex
	entries map[string]*limiterEntry
}

// NewFixedWindowLimiter creates a limiter with maxAttempts per window duration.
// If maxAttempts <= 0 or window <= 0, the limiter allows all attempts.
func NewFixedWindowLimiter(maxAttempts int, window time.Duration) *FixedWindowLimiter {
	return &FixedWindowLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		now:         time.Now,
		entries:     make(map[string]*limiterEntry),
	}
}

func (l *FixedWindowLimiter) Allow(user, userAddr string) bool {
	if l == nil || l.maxAttempts <= 0 || l.window <= 0 {
		return true
	}
	key := limiterKey(user, userAddr)
	if key == "" {
		return true
	}

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok || now.After(entry.windowEnd) {
		l.entries[key] = &limiterEntry{count: 0, windowEnd: now.Add(l.window)}
		return true
	}

	return entry.count < l.maxAttempts
}

func (l *FixedWindowLimiter) Failed(user, userAddr string) {
	if l == nil || l.maxAttempts <= 0 || l.window <= 0 {
		return
	}
	key := limiterKey(user, userAddr)
	if key == "" {
		return
	}

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok || now.After(entry.windowEnd) {
		l.entries[key] = &limiterEntry{count: 1, windowEnd: now.Add(l.window)}
		return
	}
	entry.count++
}

func (l *FixedWindowLimiter) Succeeded(user, userAddr string) {
	if l == nil || l.maxAttempts <= 0 || l.window <= 0 {
		return
	}
	key := limiterKey(user, userAddr)
	if key == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func limiterKey(user, userAddr string) string {
	if userAddr == "" {
		return user
	}
	if user == "" {
		return userAddr
	}
	return userAddr + "|" + user
}
