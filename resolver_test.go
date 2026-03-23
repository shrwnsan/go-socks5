package socks5

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSResolver(t *testing.T) {
	d := DNSResolver{}
	ctx := context.Background()

	_, addr, err := d.Resolve(ctx, "localhost")
	require.NoError(t, err)
	assert.True(t, addr.IsLoopback())
}

func TestDNSResolver_ContextCancelled(t *testing.T) {
	d := DNSResolver{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := d.Resolve(ctx, "localhost")
	require.Error(t, err)
}
