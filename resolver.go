package socks5

import (
	"context"
	"net"
)

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

// Resolve implement interface NameResolver
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, name)
	if err != nil || len(ips) == 0 {
		return ctx, nil, err
	}
	return ctx, ips[0].IP, nil
}
