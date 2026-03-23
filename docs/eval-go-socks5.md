# 🔐 Security Code Review: go-socks5

**Repository:** github.com/shrwnsan/go-socks5 (forked from github.com/things-go/go-socks5)  
**Version:** Latest (as of review)  
**Reviewer:** Security Audit  
**Date:** 2026-03-23
**Document Version:** v1.2

---

## Executive Summary

This is a SOCKS5 proxy server implementation in Go. Overall, the codebase is reasonably well-structured, but contains several **medium to high severity security issues** that should be addressed before production deployment.

| Severity | Count |
|----------|-------|
| 🔴 High | 3 |
| 🟠 Medium | 5 |
| 🟡 Low | 4 |
| 🔵 Info | 3 |

---

## 🔴 HIGH SEVERITY FINDINGS

### 1. Plaintext Credential Storage in Memory

**Location:** `auth.go:67-72`, `credentials.go:19-24`

```go
// auth.go
return &AuthContext{
    statute.MethodUserPassAuth,
    map[string]string{
        "username": string(nup.User),
        "password": string(nup.Pass),  // ⚠️ Password stored in plaintext in context
    },
}, nil
```

**Risk:** Passwords are stored in plaintext in the `AuthContext.Payload` map, which persists in memory for the connection duration. If memory is dumped (crash dump, memory forensics, etc.), credentials are exposed.

**Recommendation:**
- Zero the password bytes after validation
- Do not store the password in `AuthContext` - only store username
- Use `memzero`-style clearing for sensitive buffers

---

### 2. No Rate Limiting / Brute Force Protection

**Location:** `server.go:162-175`, `auth.go:44-72`

```go
func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*AuthContext, error) {
    // ... no rate limiting ...
    if !a.Credentials.Valid(string(nup.User), string(nup.Pass), userAddr) {
        // Just returns failure - attacker can retry infinitely
        return nil, statute.ErrUserAuthFailed
    }
}
```

**Risk:** An attacker can perform unlimited authentication attempts without any throttling, enabling brute-force or credential stuffing attacks.

**Recommendation:**
- Implement exponential backoff per IP/user
- Add configurable rate limiting
- Consider account lockout after N failed attempts
- Log failed authentication attempts with source IP

---

### 3. Open Proxy by Default (No Authentication Required)

**Location:** `server.go:70-77`

```go
// Ensure we have at least one authentication method enabled
if (len(srv.authMethods) == 0) && srv.credentials != nil {
    srv.authMethods = []Authenticator{&UserPassAuthenticator{srv.credentials}}
}
if len(srv.authMethods) == 0 {
    srv.authMethods = []Authenticator{&NoAuthAuthenticator{}}  // ⚠️ Defaults to no auth!
}
```

**Risk:** The default configuration creates an **open proxy** accessible without authentication. This can be abused for:
- Hiding attacker's origin
- Bypassing IP-based restrictions
- Launching attacks through the proxy
- Bandwidth abuse

**Recommendation:**
- Require explicit opt-in for `NoAuthAuthenticator`
- Log a prominent warning when running without authentication
- Document the risks of open proxies clearly

---

## 🟠 MEDIUM SEVERITY FINDINGS

### 4. Potential DNS Rebinding / SSRF via Domain Resolution

**Location:** `resolver.go:16-22`, `handle.go:46-54`

```go
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
    addr, err := net.ResolveIPAddr("ip", name)  // ⚠️ Arbitrary DNS resolution
    return ctx, addr.IP, err
}
```

**Risk:** The proxy will resolve any domain name provided by the client, enabling:
- DNS rebinding attacks
- SSRF to internal services (e.g., `internal.corp:22`)
- Scanning internal networks via timing analysis

**Recommendation:**
- Add domain allowlist/blocklist capability
- Block resolution of private IP ranges (RFC 1918) from external clients
- Consider DNS pinning

---

### 5. Missing Input Validation on Domain Name Length

**Location:** `statute/message.go:54-60`

```go
case ATYPDomain:
    if _, err = io.ReadFull(r, tmp[:1]); err != nil {
        return req, fmt.Errorf("failed to get request, %v", err)
    }
    domainLen := int(tmp[0])  // ⚠️ Length from untrusted input, but max is 255 (OK)
    addr := make([]byte, domainLen+2)
```

**Status:** Actually **not exploitable** - the domain length is a single byte (max 255), which is safe.

**However**, in `statute/datagram.go:33-36`:

```go
func NewDatagram(destAddr string, data []byte) (p Datagram, err error) {
    if p.DstAddr.AddrType == ATYPDomain && len(p.DstAddr.FQDN) > math.MaxUint8 {
        err = errors.New("destination host name too long")
        return
    }
```

The check exists but is only in `NewDatagram`, not in `ParseDatagram`. This is inconsistent.

---

### 6. Information Disclosure via Error Messages

**Location:** `handle.go:92-100`

```go
if err != nil {
    msg := err.Error()
    resp := statute.RepHostUnreachable
    if strings.Contains(msg, "refused") {
        resp = statute.RepConnectionRefused
    } else if strings.Contains(msg, "network is unreachable") {
        resp = statute.RepNetworkUnreachable
    }
    // ...
    return fmt.Errorf("connect to %v failed, %v", request.RawDestAddr, err)  // ⚠️ Full error logged
}
```

**Risk:** Internal error details are logged and could leak infrastructure information.

**Recommendation:**
- Sanitize error messages before logging
- Use generic error responses to clients

---

### 7. UDP Associate Source Validation Bypass

**Location:** `handle.go:195-199`

```go
// check src addr whether equal requst.DestAddr
srcEqual := ((request.DestAddr.IP.IsUnspecified()) || request.DestAddr.IP.Equal(srcAddr.IP)) && 
            (request.DestAddr.Port == 0 || request.DestAddr.Port == srcAddr.Port)
if !srcEqual {
    continue
}
```

**Risk:** If `request.DestAddr.IP` is unspecified (`0.0.0.0` or `::`), any source IP is accepted. This may be intentional but could allow UDP spoofing.

---

### 8. No Connection Timeout Enforcement

**Location:** `server.go:101-130`

```go
func (sf *Server) ServeConn(conn net.Conn) error {
    // No deadline set on the connection
    bufConn := bufio.NewReader(conn)
    mr, err := statute.ParseMethodRequest(bufConn)  // ⚠️ Can block forever
```

**Risk:** Attackers can open connections and leave them idle, consuming server resources (slowloris-style attack).

**Recommendation:**
- Set reasonable deadlines for handshake phases
- Implement connection idle timeouts
- Add configurable timeout options

---

## 🟡 LOW SEVERITY FINDINGS

### 9. Type Assertion Without Check (Potential Panic)

**Location:** `handle.go:162`

```go
udpAddr = &net.UDPAddr{IP: request.LocalAddr.(*net.TCPAddr).IP, Port: 0}  // ⚠️ Direct type assertion
```

**Risk:** If `LocalAddr` is not a `*net.TCPAddr`, this will panic and crash the server.

**Recommendation:**
```go
tcpAddr, ok := request.LocalAddr.(*net.TCPAddr)
if !ok {
    return fmt.Errorf("local address is not TCP")
}
udpAddr = &net.UDPAddr{IP: tcpAddr.IP, Port: 0}
```

---

### 10. Goroutine Leak Potential

**Location:** `handle.go:113-118`

```go
sf.goFunc(func() { errCh <- sf.Proxy(target, request.Reader) })
sf.goFunc(func() { errCh <- sf.Proxy(writer, target) })
// Wait
for i := 0; i < 2; i++ {
    e := <-errCh
    if e != nil {
        return e  // ⚠️ Returns early, but other goroutine may still run
    }
}
```

**Risk:** When an error occurs, the function returns but the other goroutine continues until it hits an error. This is mostly handled by connection closure, but could be cleaner.

---

### 11. Buffer Pool Size Panic

**Location:** `bufferpool/pool.go:33-37`

```go
func (sf *pool) Put(b []byte) {
    if cap(b) != sf.size {
        panic("invalid buffer size that's put into leaky buffer")  // ⚠️ Panic on invalid usage
    }
    sf.pool.Put(b[:0])
}
```

**Risk:** Incorrect buffer pool usage causes a panic rather than an error.

---

### 12. Logger Interface Only Supports Error Level

**Location:** `logger.go:5-13`

```go
type Logger interface {
    Errorf(format string, arg ...interface{})
}
```

**Risk:** No support for info/debug/warn levels, limiting security audit capabilities.

---

## 🔵 INFORMATIONAL FINDINGS

### 13. No TLS Certificate Validation Options

**Location:** `server.go:89-94`

```go
func (sf *Server) ListenAndServeTLS(network, addr string, c *tls.Config) error {
    l, err := tls.Listen(network, addr, c)
    // ...
}
```

The TLS configuration is passed in but there's no guidance on proper certificate validation.

---

### 14. Missing SOCKS5 Fragmentation Handling

**Location:** `statute/datagram.go:28`

```go
type Datagram struct {
    RSV     uint16
    Frag    byte  // ⚠️ Fragment field is parsed but never used
```

The `Frag` field is parsed but fragmentation is not implemented. Per RFC 1928, fragments with `FRAG != 0` should probably be rejected.

---

### 15. No GSSAPI Authentication Support

**Location:** `statute/statute.go:23`

```go
MethodGSSAPI = byte(0x01) // TODO: not support now
```

Documented but not implemented - this is fine, just informational.

---

## 🛡️ SECURITY RECOMMENDATIONS SUMMARY

### Critical Actions
1. **Never store passwords in AuthContext** - validate and discard
2. **Add rate limiting** to authentication attempts
3. **Change default behavior** to require explicit opt-in for no-auth mode

### Important Actions
4. Add domain/IP allowlisting for destination addresses
5. Implement connection timeouts
6. Add type assertion safety checks
7. Sanitize error messages

### Best Practices
8. Add audit logging for authentication events
9. Support structured logging with levels
10. Consider adding metrics/monitoring hooks
11. Reject UDP datagrams with `FRAG != 0`
12. Document security considerations in README

---

## 📋 POSITIVE SECURITY OBSERVATIONS

1. ✅ Uses `io.ReadFull` for exact byte reads (prevents partial read issues)
2. ✅ Proper connection cleanup with `defer`
3. ✅ Buffer pool prevents unbounded memory allocation
4. ✅ Context support for cancellation
5. ✅ RuleSet interface allows flexible access control
6. ✅ TLS support included
7. ✅ Tests use actual network operations (not just mocks)

---

## Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `server.go` | 186 | Main server implementation |
| `handle.go` | 261 | Request handling and proxying |
| `auth.go` | 73 | Authentication mechanisms |
| `option.go` | 184 | Configuration options |
| `credentials.go` | 19 | Credential storage interface |
| `ruleset.go` | 54 | Access control rules |
| `resolver.go` | 21 | DNS resolution |
| `logger.go` | 25 | Logging interface |
| `bufferpool/pool.go` | 39 | Buffer pooling |
| `statute/statute.go` | 56 | Protocol constants |
| `statute/message.go` | 184 | Request/reply parsing |
| `statute/addr.go` | 55 | Address specification |
| `statute/auth.go` | 91 | Auth packet handling |
| `statute/datagram.go` | 108 | UDP datagram handling |
| `statute/method.go` | 65 | Method negotiation |

---

## Conclusion

The `go-socks5` library is a functional SOCKS5 implementation but has several security concerns that should be addressed before production use. The most critical issues are around **credential handling**, **lack of rate limiting**, and **insecure defaults**. With the recommended fixes, this would be a reasonably secure proxy library.

**Recommended Risk Level:** Medium-High for production use without modifications.

---

## References

- [RFC 1928 - SOCKS Protocol Version 5](https://tools.ietf.org/html/rfc1928)
- [RFC 1929 - Username/Password Authentication for SOCKS V5](https://tools.ietf.org/html/rfc1929)
- [OWASP - SOCKS Proxy Security](https://owasp.org/www-community/vulnerabilities/SOCKS_proxy_misconfiguration)

---

# 🔧 General Code Quality Review

*Non-security related improvements: bugs, maintainability, robustness, and feature gaps*

---

## 🐛 BUGS

### 1. Middleware Chain Skips Handler When Empty

**Location:** `option.go:141-149`

```go
func (m MiddlewareChain) Execute(ctx context.Context, writer io.Writer, request *Request, last Handler) error {
    if len(m) == 0 {
        return nil  // ⚠️ BUG: Returns nil without calling `last` handler
    }
    for i := 0; i < len(m); i++ {
        if err := m[i](ctx, writer, request); err != nil {
            return err
        }
    }
    return last(ctx, writer, request)
}
```

**Problem:** When middleware chain is empty, the final handler (`last`) is never executed. The caller expects the handler to run regardless of middleware presence.

**Fix:**
```go
func (m MiddlewareChain) Execute(ctx context.Context, writer io.Writer, request *Request, last Handler) error {
    for _, middleware := range m {
        if err := middleware(ctx, writer, request); err != nil {
            return err
        }
    }
    return last(ctx, writer, request)
}
```

---

### 2. Comment Typos and Copy-Paste Errors

**Location:** `handle.go:106, 111`

```go
// handleBind is used to handle a connect command  // ⚠️ Wrong: it's bind, not connect
func (sf *Server) handleBind(...)

// handleAssociate is used to handle a connect command  // ⚠️ Wrong: it's associate
func (sf *Server) handleAssociate(...)
```

Also in `handle.go:261`:
```go
// Proxy is used to suffle data from src to destination  // ⚠️ Typo: "suffle" → "shuffle"
```

---

## 🧹 CODE QUALITY

### 3. Inconsistent Receiver Naming

**Location:** Throughout codebase

```go
func (sf *Server) Serve(...)         // "sf" - unclear meaning
func (a NoAuthAuthenticator) ...     // "a"
func (p *PermitCommand) Allow(...)   // "p"
func (sf *pool) Get()                // "sf" again for different type!
```

**Recommendation:** Use consistent, type-based receiver names:
```go
func (s *Server) Serve(...)
func (a *NoAuthAuthenticator) Authenticate(...)
func (p *pool) Get()
```

---

### 4. Magic Numbers Without Constants

**Location:** `server.go:59`

```go
srv := &Server{
    bufferPool: bufferpool.NewPool(32 * 1024),  // ⚠️ What is 32*1024?
    // ...
}
```

**Fix:**
```go
const defaultBufferSize = 32 * 1024 // 32KB - matches typical TCP buffer

srv := &Server{
    bufferPool: bufferpool.NewPool(defaultBufferSize),
    // ...
}
```

---

### 5. Duplicate Command Handling Pattern

**Location:** `handle.go:63-94`

```go
switch req.Command {
case statute.CommandConnect:
    last = sf.handleConnect
    if sf.userConnectHandle != nil {
        last = sf.userConnectHandle
    }
    if len(sf.userConnectMiddlewares) != 0 {
        return sf.userConnectMiddlewares.Execute(ctx, write, req, last)
    }
case statute.CommandBind:
    last = sf.handleBind
    if sf.userBindHandle != nil {
        last = sf.userBindHandle
    }
    if len(sf.userBindMiddlewares) != 0 {
        return sf.userBindMiddlewares.Execute(ctx, write, req, last)
    }
// ... same pattern for Associate
}
```

**Problem:** Repetitive pattern for each command type violates DRY principle.

**Fix:** Extract to helper struct/method:
```go
type commandHandler struct {
    default    Handler
    custom     Handler
    middleware MiddlewareChain
}

func (h *commandHandler) resolve() Handler {
    if h.custom != nil {
        return h.custom
    }
    return h.default
}
```

---

### 6. UDP Associate Function Too Long

**Location:** `handle.go:133-259`

The `handleAssociate` function is ~126 lines with deeply nested goroutines and callbacks, making it hard to read and test.

**Recommendation:** Extract into smaller functions:
```go
func (sf *Server) handleAssociate(ctx context.Context, writer io.Writer, request *Request) error {
    // Setup logic...
    sf.goFunc(func() {
        sf.relayUDPPackets(bindLn, request, dial)
    })
    // Wait for TCP connection close...
}

func (sf *Server) relayUDPPackets(bindLn *net.UDPConn, request *Request, dial DialFunc) {
    // Extracted UDP relay logic
}
```

---

## 🏗️ MISSING FEATURES

### 7. No Graceful Shutdown Support

**Location:** `server.go:95-107`

```go
func (sf *Server) Serve(l net.Listener) error {
    defer l.Close()
    for {
        conn, err := l.Accept()
        if err != nil {
            return err  // ⚠️ No way to trigger graceful shutdown
        }
        sf.goFunc(func() { sf.ServeConn(conn) })
    }
}
```

**Problem:** No mechanism to gracefully stop accepting connections and drain existing ones.

**Fix:**
```go
func (sf *Server) Serve(ctx context.Context, l net.Listener) error {
    defer l.Close()
    
    go func() {
        <-ctx.Done()
        l.Close()
    }()
    
    for {
        conn, err := l.Accept()
        if err != nil {
            if ctx.Err() != nil {
                return nil // Graceful shutdown
            }
            return err
        }
        // ...
    }
}
```

---

### 8. No Connection Tracking for Graceful Drain

**Location:** `server.go`

```go
sf.goFunc(func() {
    sf.ServeConn(conn)  // ⚠️ Connection not tracked
})
```

**Problem:** Can't wait for all connections to finish on shutdown.

**Fix:**
```go
type Server struct {
    // ...
    wg sync.WaitGroup
}

func (sf *Server) Serve(l net.Listener) error {
    // ...
    sf.wg.Add(1)
    go func() {
        defer sf.wg.Done()
        sf.ServeConn(conn)
    }()
}

func (sf *Server) Shutdown(ctx context.Context) error {
    // Close listener, wait for connections
    sf.wg.Wait()
    return nil
}
```

---

### 9. No Maximum Connection Limit

**Location:** `server.go:95-107`

```go
for {
    conn, err := l.Accept()
    // ⚠️ No limit - accepts unlimited connections
    sf.goFunc(func() { sf.ServeConn(conn) })
}
```

**Problem:** Unlimited connections can exhaust file descriptors and memory (DoS vector).

**Fix:**
```go
type Server struct {
    maxConns int32
    curConns int32
}

func (sf *Server) canAccept() bool {
    if sf.maxConns <= 0 {
        return true
    }
    return atomic.LoadInt32(&sf.curConns) < sf.maxConns
}

// In Serve loop:
if !sf.canAccept() {
    conn.Close()
    continue
}
atomic.AddInt32(&sf.curConns, 1)
```

---

### 10. No Metrics/Observability Interface

**Location:** `server.go`

**Problem:** No visibility into server health - active connections, bytes transferred, error rates.

**Recommendation:** Add metrics interface:
```go
type Metrics interface {
    ConnectionOpened()
    ConnectionClosed()
    BytesTransferred(direction string, n int64)
    AuthAttempt(success bool)
    CommandExecuted(cmd byte)
}

// Usage:
server := socks5.NewServer(
    socks5.WithMetrics(prometheusMetrics),
)
```

---

## 🛠️ ROBUSTNESS

### 11. Ignored Close() Errors

**Location:** Multiple files

```go
defer target.Close() // nolint: errcheck
defer conn.Close()   // nolint: errcheck
defer bindLn.Close() // nolint: errcheck
```

**Problem:** Errors from `Close()` are silently ignored. For network connections, this can hide data corruption (incomplete writes, buffered data not flushed).

**Fix:**
```go
defer func() {
    if cerr := target.Close(); cerr != nil && err == nil {
        err = cerr // Propagate close error if no other error
    }
}()
```

---

### 12. Hardcoded Error Detection via String Matching

**Location:** `handle.go:92-98`

```go
msg := err.Error()
resp := statute.RepHostUnreachable
if strings.Contains(msg, "refused") {
    resp = statute.RepConnectionRefused
} else if strings.Contains(msg, "network is unreachable") {
    resp = statute.RepNetworkUnreachable
}
```

**Problem:** Fragile - relies on error message text which varies by platform and Go version.

**Fix:** Use proper error inspection:
```go
import "syscall"

var (
    netErr net.Error
    opErr  *net.OpError
)

if errors.As(err, &netErr) && netErr.Timeout() {
    resp = statute.RepTTLExpired
} else if errors.As(err, &opErr) {
    if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
        resp = statute.RepConnectionRefused
    } else if errors.Is(opErr.Err, syscall.ENETUNREACH) {
        resp = statute.RepNetworkUnreachable
    }
}
```

---

### 13. Context Not Propagated Through Request Handling

**Location:** `handle.go:32`

```go
func (sf *Server) handleRequest(write io.Writer, req *Request) error {
    ctx := context.Background()  // ⚠️ Fresh context, loses cancellation/tracing
```

**Problem:** No way to cancel operations or propagate trace IDs through the request lifecycle.

**Fix:** Accept context from caller:
```go
func (sf *Server) handleRequest(ctx context.Context, write io.Writer, req *Request) error {
    // Use ctx for all operations
}
```

---

### 14. bufio.Reader May Lose Buffered Data

**Location:** `server.go:118-130`

```go
bufConn := bufio.NewReader(conn)
mr, err := statute.ParseMethodRequest(bufConn)
// ... later ...
authContext, err = sf.authenticate(conn, bufConn, userAddr, mr.Methods)
// ... later ...
request, err := ParseRequest(bufConn)
```

**Problem:** If `bufConn` buffers more data than consumed, that data is not available on the underlying `conn`. This could cause issues if the client sends data eagerly.

**Recommendation:** Either ensure all buffered data is consumed, or document that clients must wait for server responses before sending more data.

---

### 15. Missing AddrSpec Validation

**Location:** `statute/addr.go`

```go
func (sf *AddrSpec) String() string {
    if len(sf.IP) != 0 {
        return net.JoinHostPort(sf.IP.String(), strconv.Itoa(sf.Port))
    }
    return net.JoinHostPort(sf.FQDN, strconv.Itoa(sf.Port))
}
```

**Problem:** No validation that:
- `Port` is in valid range (0-65535)
- FQDN is not empty when IP is nil
- IP is valid length (4 or 16 bytes)

**Fix:**
```go
func (sf *AddrSpec) Validate() error {
    if sf.Port < 0 || sf.Port > 65535 {
        return fmt.Errorf("invalid port: %d", sf.Port)
    }
    if len(sf.IP) == 0 && sf.FQDN == "" {
        return errors.New("neither IP nor FQDN specified")
    }
    if len(sf.IP) != 0 && len(sf.IP) != net.IPv4len && len(sf.IP) != net.IPv6len {
        return fmt.Errorf("invalid IP length: %d", len(sf.IP))
    }
    return nil
}
```

---

## 📊 QUALITY IMPROVEMENTS SUMMARY

| # | Priority | Category | Issue |
|---|----------|----------|-------|
| 1 | 🔴 High | Bug | Middleware skips handler when empty |
| 2 | 🟡 Low | Docs | Comment typos and copy-paste errors |
| 3 | 🟡 Low | Style | Inconsistent receiver naming |
| 4 | 🟡 Low | Style | Magic numbers without constants |
| 5 | 🟠 Medium | DRY | Duplicate command handling pattern |
| 6 | 🟠 Medium | Maintainability | UDP handler too long/nested |
| 7 | 🔴 High | Feature | No graceful shutdown support |
| 8 | 🟠 Medium | Feature | No connection tracking for drain |
| 9 | 🔴 High | Robustness | No maximum connection limit |
| 10 | 🟡 Low | Feature | No metrics/observability interface |
| 11 | 🟠 Medium | Robustness | Ignored Close() errors |
| 12 | 🟠 Medium | Robustness | String-based error matching |
| 13 | 🟠 Medium | Feature | Context not propagated |
| 14 | 🟠 Medium | Correctness | bufio.Reader buffering issue |
| 15 | 🟡 Low | Robustness | Missing AddrSpec validation |

---

## 🎯 RECOMMENDED PRIORITY

**Fix Immediately:**
1. Middleware chain bug (#1) - breaks functionality
2. Graceful shutdown (#7) - production requirement
3. Max connection limit (#9) - DoS protection

**Fix Soon:**
4. Connection tracking (#8)
5. Close() error handling (#11)
6. Context propagation (#13)

**Nice to Have:**
7. Code style improvements (#3, #4, #5, #6)
8. Metrics interface (#10)
9. Validation improvements (#14, #15)

---

## 🔍 ADDITIONAL FINDINGS (Independent Review - 2026-03-23)

*Findings discovered during secondary review by Claude Code (GLM 5)*

---

### 🟠 MEDIUM SEVERITY

### 16. Timing Attack in Password Comparison

**Location:** `credentials.go:13-15`

```go
func (s StaticCredentials) Valid(user, password, _ string) bool {
    pass, ok := s[user]
    return ok && password == pass  // ⚠️ String comparison - not constant-time
}
```

**Risk:** Uses `==` for password comparison, which is vulnerable to timing attacks. An attacker can measure response times to iteratively guess the correct password byte-by-byte.

**Fix:**
```go
import "crypto/subtle"

func (s StaticCredentials) Valid(user, password, _ string) bool {
    pass, ok := s[user]
    if !ok {
        return false
    }
    return subtle.ConstantTimeCompare([]byte(password), []byte(pass)) == 1
}
```

---

### 17. Race Condition in UDP Associate Connection Map

**Location:** `handle.go:255-263`

```go
if target, ok := conns.Load(connKey); !ok {
    targetNew, err := dial(ctx, "udp", pk.DstAddr.String())
    if err != nil {
        sf.logger.Errorf("connect to %v failed, %v", pk.DstAddr, err)
        continue
    }
    conns.Store(connKey, targetNew)
    // ...
}
```

**Risk:** Check-then-act pattern with `sync.Map` - two goroutines processing packets for the same destination could race to create duplicate connections. One connection would be leaked.

**Fix:** Use atomic `LoadOrStore`:
```go
targetNew, err := dial(ctx, "udp", pk.DstAddr.String())
if err != nil {
    sf.logger.Errorf("connect to %v failed, %v", pk.DstAddr, err)
    continue
}
actual, loaded := conns.LoadOrStore(connKey, targetNew)
if loaded {
    targetNew.Close() // Close the duplicate
    target = actual.(net.Conn)
} else {
    target = targetNew
    // Start relay goroutine...
}
```

---

### 18. Context Ignored in DNS Resolution

**Location:** `resolver.go:17-22`

```go
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
    addr, err := net.ResolveIPAddr("ip", name)  // ⚠️ ctx not used!
    return ctx, addr.IP, err
}
```

**Risk:** Context is accepted but completely ignored. DNS resolution cannot be cancelled, which can cause hangs during shutdown or timeout scenarios.

**Fix:** Use `net.Resolver` with context:
```go
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
    resolver := &net.Resolver{}
    ips, err := resolver.LookupIPAddr(ctx, name)
    if err != nil || len(ips) == 0 {
        return ctx, nil, err
    }
    return ctx, ips[0].IP, nil
}
```

---

### 🟡 LOW SEVERITY

### 19. Missing Port Range Validation

**Location:** `statute/addr.go:47-49`

```go
as.Port, err = strconv.Atoi(port)
if err != nil {
    return
}
// ⚠️ No check for valid port range (0-65535)
```

**Risk:** Malformed input could produce negative or overflow ports without error, leading to unexpected behavior.

**Fix:**
```go
as.Port, err = strconv.Atoi(port)
if err != nil {
    return
}
if as.Port < 0 || as.Port > 65535 {
    err = fmt.Errorf("invalid port number: %d", as.Port)
    return
}
```

---

### 20. Unhandled Write Error in authenticate

**Location:** `server.go:194`

```go
conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable}) //nolint: errcheck
```

**Risk:** Error ignored when sending "no acceptable method" response. Client may hang indefinitely waiting for a response that was never sent.

**Fix:**
```go
if _, err := conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable}); err != nil {
    return nil, fmt.Errorf("failed to send method rejection: %w", err)
}
return nil, statute.ErrNoSupportedAuth
```

---

### 21. Nil IP Check Missing in UDP Source Validation

**Location:** `handle.go:248`

```go
srcEqual := ((request.DestAddr.IP.IsUnspecified()) || request.DestAddr.IP.Equal(srcAddr.IP)) &&
            (request.DestAddr.Port == 0 || request.DestAddr.Port == srcAddr.Port)
```

**Risk:** If `request.DestAddr.IP` is nil (not just unspecified), calling `IsUnspecified()` may panic or behave unexpectedly.

**Fix:**
```go
srcEqual := (len(request.DestAddr.IP) == 0 || request.DestAddr.IP.IsUnspecified() || request.DestAddr.IP.Equal(srcAddr.IP)) &&
            (request.DestAddr.Port == 0 || request.DestAddr.Port == srcAddr.Port)
```

---

## 📊 UPDATED QUALITY IMPROVEMENTS SUMMARY

| # | Priority | Category | Issue |
|---|----------|----------|-------|
| 1 | 🔴 High | Bug | Middleware skips handler when empty |
| 2 | 🟡 Low | Docs | Comment typos and copy-paste errors |
| 3 | 🟡 Low | Style | Inconsistent receiver naming |
| 4 | 🟡 Low | Style | Magic numbers without constants |
| 5 | 🟠 Medium | DRY | Duplicate command handling pattern |
| 6 | 🟠 Medium | Maintainability | UDP handler too long/nested |
| 7 | 🔴 High | Feature | No graceful shutdown support |
| 8 | 🟠 Medium | Feature | No connection tracking for drain |
| 9 | 🔴 High | Robustness | No maximum connection limit |
| 10 | 🟡 Low | Feature | No metrics/observability interface |
| 11 | 🟠 Medium | Robustness | Ignored Close() errors |
| 12 | 🟠 Medium | Robustness | String-based error matching |
| 13 | 🟠 Medium | Feature | Context not propagated |
| 14 | 🟠 Medium | Correctness | bufio.Reader buffering issue |
| 15 | 🟡 Low | Robustness | Missing AddrSpec validation |
| 16 | 🟠 Medium | Security | Timing attack in password comparison |
| 17 | 🟠 Medium | Concurrency | Race condition in UDP connection map |
| 18 | 🟠 Medium | Feature | Context ignored in DNS resolution |
| 19 | 🟡 Low | Validation | Missing port range validation |
| 20 | 🟡 Low | Robustness | Unhandled Write error in authenticate |
| 21 | 🟡 Low | Robustness | Nil IP check missing in UDP validation |

---

## 🎯 UPDATED RECOMMENDED PRIORITY

**Fix Immediately (Security/Correctness):**
1. Middleware chain bug (#1) - breaks functionality
2. Graceful shutdown (#7) - production requirement
3. Max connection limit (#9) - DoS protection
4. **Timing attack in password comparison (#16)** - security vulnerability
5. **Race condition in UDP map (#17)** - resource leak

If the proxy is exposed publicly, prioritize **timing-attack fixes (#16)** alongside the open-proxy default and auth hardening.

**Fix Soon (Production Readiness):**
6. Connection tracking (#8)
7. Close() error handling (#11)
8. Context propagation (#13)
9. **Context in DNS resolution (#18)**
10. **Use errors.Is/As instead of string matching (#12)**

**Nice to Have:**
11. Code style improvements (#3, #4, #5, #6)
12. Metrics interface (#10)
13. Validation improvements (#14, #15, #19, #20, #21)

---

## 📈 REVIEW COMPARISON

| Metric | Original Review | Independent Review |
|--------|-----------------|-------------------|
| High Severity | 3 | 3 (confirmed) |
| Medium Severity | 8 | 11 (+3 new) |
| Low Severity | 4 | 6 (+2 new) |
| **Total Issues** | **15** | **21** |

### Key Differences

| Finding | Original | Independent |
|---------|----------|-------------|
| Timing attack | Not mentioned | 🟠 Medium |
| UDP race condition | Not mentioned | 🟠 Medium |
| Context in DNS | Not mentioned | 🟠 Medium |
| Port validation | Mentioned in Validate() | Found in ParseAddrSpec |
| bufio.Reader | 🟠 Medium | Considered low risk (protocol is request-response) |
| UDP source validation | Listed as potential bypass | Considered intentional per RFC 1928 |

---

## 🧾 CHANGELOG

### v1.3 — 2026-03-24
- Fixed comment typos: `handleBind`, `handleAssociate`, and `Proxy` function documentation.
- Added exported constants: `DefaultBufferSize` (32KB), `DefaultHandshakeTimeout` (10s).
- Added `Metrics` interface for observability with `NoOpMetrics` default and `WithMetrics()` option.
- Metrics hooks: `ConnectionOpened`, `ConnectionClosed`, `CommandExecuted`, `AuthSuccess`, `AuthFailure`, `BytesTransferred`.
- Updated module path from `github.com/things-go/go-socks5` to `github.com/shrwnsan/go-socks5` for fork testing.

### v1.2 — 2026-03-23
- Implemented critical fixes: secure default auth opt-in, constant-time password comparison, auth rate limiting interface + helper, handshake deadline, UDP associate race fix, nil IP handling, context propagation + DNS resolution context, error classification, close error handling, AddrSpec validation + port range check, UDP FRAG rejection, bind addr type assertion safety, graceful shutdown + connection tracking + max conns.
- Added tests for middleware chain, limiter helper, lifecycle, resolver context, and validation paths.
- Added open-proxy warning and limiter usage note.

### v1.1 — 2026-03-23
- Added independent review deltas: timing attack in password comparison, UDP associate race condition, DNS resolution context usage, port range validation, unhandled write error in auth, and nil IP handling in UDP validation.
- Expanded review comparison metrics and recommendations.

### v1.0 — 2026-03-23
- Initial security and code quality evaluation.

---

## 🔧 IMPLEMENTATION CHECKLIST

When ready to apply fixes, tackle in this order:

### Phase 1: Critical Bug Fixes
- [x] Fix middleware chain (`option.go:138-148`)
- [x] Add constant-time password comparison (`credentials.go`)
- [x] Add type assertion safety check (`handle.go:202`)

### Phase 2: Concurrency & Resource Management
- [x] Use `LoadOrStore` in UDP associate (`handle.go:255-263`)
- [x] Add graceful shutdown with `Shutdown(ctx)` method
- [x] Add max connection limit with atomic counter
- [x] Add `sync.WaitGroup` for connection tracking

### Phase 3: Context & Error Handling
- [x] Propagate context through request handling
- [x] Honor context in DNS resolution
- [x] Use `errors.Is/As` for error classification
- [x] Handle Close() errors properly

### Phase 4: Code Quality
- [x] Fix comment typos
- [x] Add port range validation
- [x] Add nil IP check in UDP validation
- [x] Add metrics interface

### Phase 5: Remaining (Style/Optional)
- [ ] Consistent receiver naming (`sf` vs `s` vs `a` etc.) — deferred, pervasive change
