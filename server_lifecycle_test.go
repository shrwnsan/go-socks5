package socks5

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServer_ShutdownWaitsForConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)

	srv := NewServer(
		WithAllowNoAuth(true),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.ServeContext(ctx, ln)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String()) // nolint: noctx
	require.NoError(t, err)
	defer conn.Close() // nolint: errcheck

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
		conn.Close() // nolint: errcheck
	}()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	require.NoError(t, srv.Shutdown(shutdownCtx))
}

func TestServer_MaxConns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // nolint: noctx
	require.NoError(t, err)
	defer ln.Close() // nolint: errcheck

	srv := NewServer(
		WithAllowNoAuth(true),
		WithMaxConns(1),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.ServeContext(ctx, ln)
	}()

	conn1, err := net.Dial("tcp", ln.Addr().String()) // nolint: noctx
	require.NoError(t, err)
	defer conn1.Close() // nolint: errcheck

	conn2, err := net.Dial("tcp", ln.Addr().String()) // nolint: noctx
	require.NoError(t, err)
	defer conn2.Close() // nolint: errcheck

	_ = conn2.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn2.Read(buf)
	require.Error(t, err)
}
