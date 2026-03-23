package socks5

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shrwnsan/go-socks5/statute"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	rsp := new(bytes.Buffer)
	cator := NoAuthAuthenticator{}

	ctx, err := cator.Authenticate(req, rsp, "")
	require.NoError(t, err)
	assert.Equal(t, statute.MethodNoAuth, ctx.Method)
	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodNoAuth}, rsp.Bytes())
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	rsp := new(bytes.Buffer)
	cator := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"foo": "bar",
		},
	}

	ctx, err := cator.Authenticate(req, rsp, "")
	require.NoError(t, err)
	assert.Equal(t, statute.MethodUserPassAuth, ctx.Method)

	val, ok := ctx.Payload["username"]
	require.True(t, ok)
	require.Equal(t, "foo", val)
	require.NotContains(t, ctx.Payload, "password")

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthSuccess}, rsp.Bytes())
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	rsp := new(bytes.Buffer)
	cator := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"foo": "bar",
		},
	}

	ctx, err := cator.Authenticate(req, rsp, "")
	require.True(t, errors.Is(err, statute.ErrUserAuthFailed))
	require.Nil(t, ctx)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthFailure}, rsp.Bytes())
}

type limiterStub struct {
	allowed bool
	failed  int
	success int
}

func (l *limiterStub) Allow(_, _ string) bool {
	return l.allowed
}

func (l *limiterStub) Failed(_, _ string) {
	l.failed++
}

func (l *limiterStub) Succeeded(_, _ string) {
	l.success++
}

func TestPasswordAuth_LimiterBlocks(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	rsp := new(bytes.Buffer)
	limiter := &limiterStub{allowed: false}
	cator := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"foo": "bar",
		},
		Limiter: limiter,
	}

	ctx, err := cator.Authenticate(req, rsp, "1.2.3.4")
	require.True(t, errors.Is(err, statute.ErrUserAuthFailed))
	require.Nil(t, ctx)
	require.Equal(t, 0, limiter.failed)
	require.Equal(t, 0, limiter.success)
	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthFailure}, rsp.Bytes())
}

func TestPasswordAuth_LimiterFailed(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	rsp := new(bytes.Buffer)
	limiter := &limiterStub{allowed: true}
	cator := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"foo": "bar",
		},
		Limiter: limiter,
	}

	ctx, err := cator.Authenticate(req, rsp, "1.2.3.4")
	require.True(t, errors.Is(err, statute.ErrUserAuthFailed))
	require.Nil(t, ctx)
	require.Equal(t, 1, limiter.failed)
	require.Equal(t, 0, limiter.success)
}

func TestPasswordAuth_LimiterSucceeded(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	rsp := new(bytes.Buffer)
	limiter := &limiterStub{allowed: true}
	cator := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"foo": "bar",
		},
		Limiter: limiter,
	}

	ctx, err := cator.Authenticate(req, rsp, "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, ctx)
	require.Equal(t, 0, limiter.failed)
	require.Equal(t, 1, limiter.success)
}
