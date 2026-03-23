package socks5

// Metrics provides hooks for observability into the SOCKS5 server.
// Implement this interface to collect connection stats, auth events,
// and command execution metrics.
type Metrics interface {
	// ConnectionOpened is called when a new connection is accepted.
	ConnectionOpened()
	// ConnectionClosed is called when a connection is closed.
	ConnectionClosed()
	// AuthSuccess is called on successful authentication.
	AuthSuccess(method uint8, user string)
	// AuthFailure is called on failed authentication.
	AuthFailure(method uint8, user string)
	// CommandExecuted is called when a SOCKS5 command is processed.
	// cmd is one of statute.CommandConnect, CommandBind, CommandAssociate.
	CommandExecuted(cmd uint8)
	// BytesTransferred records bytes proxied.
	// direction is "client_to_target" or "target_to_client".
	BytesTransferred(direction string, n int64)
}

// NoOpMetrics is a no-op implementation of Metrics.
type NoOpMetrics struct{}

func (NoOpMetrics) ConnectionOpened()                       {}
func (NoOpMetrics) ConnectionClosed()                       {}
func (NoOpMetrics) AuthSuccess(_ uint8, _ string)           {}
func (NoOpMetrics) AuthFailure(_ uint8, _ string)           {}
func (NoOpMetrics) CommandExecuted(_ uint8)                 {}
func (NoOpMetrics) BytesTransferred(_ string, _ int64)      {}
