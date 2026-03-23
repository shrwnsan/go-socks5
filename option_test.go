package socks5

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMiddlewareChain_Execute_EmptyCallsLast(t *testing.T) {
	called := false
	chain := MiddlewareChain{}

	err := chain.Execute(context.Background(), io.Discard, &Request{}, func(ctx context.Context, writer io.Writer, request *Request) error {
		called = true
		return nil
	})

	require.NoError(t, err)
	require.True(t, called)
}
