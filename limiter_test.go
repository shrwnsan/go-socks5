package socks5

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFixedWindowLimiter_AllowsThenBlocks(t *testing.T) {
	now := time.Now()
	limiter := NewFixedWindowLimiter(2, time.Minute)
	limiter.now = func() time.Time { return now }

	require.True(t, limiter.Allow("user", "1.2.3.4"))
	limiter.Failed("user", "1.2.3.4")
	require.True(t, limiter.Allow("user", "1.2.3.4"))
	limiter.Failed("user", "1.2.3.4")
	require.False(t, limiter.Allow("user", "1.2.3.4"))
}

func TestFixedWindowLimiter_ResetsOnSuccess(t *testing.T) {
	now := time.Now()
	limiter := NewFixedWindowLimiter(1, time.Minute)
	limiter.now = func() time.Time { return now }

	limiter.Failed("user", "1.2.3.4")
	require.False(t, limiter.Allow("user", "1.2.3.4"))
	limiter.Succeeded("user", "1.2.3.4")
	require.True(t, limiter.Allow("user", "1.2.3.4"))
}

func TestFixedWindowLimiter_ResetsAfterWindow(t *testing.T) {
	now := time.Now()
	limiter := NewFixedWindowLimiter(1, time.Minute)
	limiter.now = func() time.Time { return now }

	limiter.Failed("user", "1.2.3.4")
	require.False(t, limiter.Allow("user", "1.2.3.4"))

	now = now.Add(2 * time.Minute)
	require.True(t, limiter.Allow("user", "1.2.3.4"))
}
