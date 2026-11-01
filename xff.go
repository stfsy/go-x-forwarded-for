package xff

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
)

const defaultMaxHops = 30

var (
	// ErrMaxHopsExceeded is returned when the proxy chain exceeds MaxHops.
	ErrMaxHopsExceeded = errors.New("xff: maximum proxy hops exceeded")

	// ErrInvalidHeader is returned when an untrusted or malformed IP is found in X-Forwarded-For.
	ErrInvalidHeader = errors.New("xff: invalid IP in X-Forwarded-For header")
)

type contextKey struct{}

var clientAddrContextKey = contextKey{}

// ipv6BogonPrefixes contains special-purpose, reserved, and test IPv6 networks
// per RFC 4291, RFC 6666, RFC 2928, RFC 3849.
var ipv6BogonPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("::/96"),         // RFC 4291 Deprecated IPv4-Compatible IPv6
	netip.MustParsePrefix("100::/64"),      // RFC 6666 Discard Prefix
	netip.MustParsePrefix("2001::/23"),     // RFC 2928 IETF Protocol Assignments
	netip.MustParsePrefix("2001:db8::/32"), // RFC 3849 Documentation
}

var (
	defaultXFFOnce     sync.Once
	defaultXFFInstance *XFF
)

// ContextWithClientAddr returns a copy of parent context with the resolved client IP address stored.
func ContextWithClientAddr(ctx context.Context, addr netip.Addr) context.Context {
	return context.WithValue(ctx, clientAddrContextKey, addr)
}

// ClientAddrFromContext extracts the resolved client netip.Addr from the request context if set.
func ClientAddrFromContext(ctx context.Context) (netip.Addr, bool) {
	if ctx == nil {
		return netip.Addr{}, false
	}
	addr, ok := ctx.Value(clientAddrContextKey).(netip.Addr)
	return addr, ok
}

// isIPv4Bogon performs zero-memory-dereference register checks for IPv4 bogon ranges
// per RFC 791, RFC 6598, RFC 6890, RFC 5737, RFC 7526, RFC 2544, RFC 1112, RFC 919.
func isIPv4Bogon(addr netip.Addr) bool {
	b := addr.As4()
	b0 := b[0]
	if b0 == 0 || b0 >= 240 { // 0.0.0.0/8 (RFC 791), 240.0.0.0/4 (RFC 1112 & RFC 919)
		return true
	}
	if b0 == 100 { // 100.64.0.0/10 CGNAT (RFC 6598)
		return b[1]&0xc0 == 64
	}
	if b0 == 192 {
		return (b[1] == 0 && (b[2] == 0 || b[2] == 2)) || (b[1] == 88 && b[2] == 99)
	}
	if b0 == 198 {
		return (b[1]&0xfe == 18) || (b[1] == 51 && b[2] == 100)
	}
	return b0 == 203 && b[1] == 0 && b[2] == 113
}

// IsPublicAddr returns true if the address is a valid, globally routable public address
// on the Internet (not private, loopback, link-local, multicast, unspecified, or reserved bogon).
func IsPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	// Normalize IPv4-mapped IPv6 (e.g. ::ffff:192.0.2.1 -> 192.0.2.1)
	addr = addr.Unmap()

	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return false
	}

	if addr.Is4() {
		return !isIPv4Bogon(addr)
	}

	for i := range ipv6BogonPrefixes {
		if ipv6BogonPrefixes[i].Contains(addr) {
			return false
		}
	}

	return true
}

// IsPublicIP reports whether the given IP is a globally routable public IP address.
func IsPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return IsPublicAddr(addr)
}

// trimToken strips spaces, tabs, and enclosing double or single quotes without allocations.
func trimToken(token string) string {
	for len(token) > 0 {
		c := token[0]
		if c == ' ' || c == '\t' || c == '"' || c == '\'' {
			token = token[1:]
			continue
		}
		break
	}
	for len(token) > 0 {
		c := token[len(token)-1]
		if c == ' ' || c == '\t' || c == '"' || c == '\'' {
			token = token[:len(token)-1]
			continue
		}
		break
	}
	return token
}

// formatAddrPort formats an IP address and optional port into a single heap string
// using a stack-allocated byte buffer without intermediate allocations.
func formatAddrPort(addr netip.Addr, port string) string {
	if port == "" {
		return addr.String()
	}
	var buf [64]byte
	b := buf[:0]
	if addr.Is6() {
		b = append(b, '[')
		b = addr.AppendTo(b)
		b = append(b, ']')
	} else {
		b = addr.AppendTo(b)
	}
	b = append(b, ':')
	b = append(b, port...)
	return string(b)
}

// parseIPToken extracts a netip.Addr from an X-Forwarded-For token which may be:
// - IPv4 ("1.2.3.4")
// - IPv4 with port ("1.2.3.4:1234")
// - IPv6 ("2001:db8::1")
// - IPv6 in brackets ("[2001:db8::1]")
// - IPv6 in brackets with port ("[2001:db8::1]:1234")
// parseIPToken extracts a netip.Addr from an X-Forwarded-For token which may be:
// - IPv4 ("1.2.3.4")
// - IPv4 with port ("1.2.3.4:1234")
// - IPv6 ("2001:db8::1")
// - IPv6 in brackets ("[2001:db8::1]")
// - IPv6 in brackets with port ("[2001:db8::1]:1234")
func parseIPToken(token string) (netip.Addr, bool) {
	token = trimToken(token)
	if token == "" {
		return netip.Addr{}, false
	}

	// If enclosed in brackets: e.g. [2001:db8::1] or [2001:db8::1]:8080
	if token[0] == '[' {
		closeBracket := strings.IndexByte(token, ']')
		if closeBracket != -1 {
			if closeBracket == len(token)-1 {
				inside := token[1:closeBracket]
				if addr, err := netip.ParseAddr(inside); err == nil {
					return addr.WithZone(""), true
				}
				return netip.Addr{}, false
			}
			if token[closeBracket+1] == ':' {
				if ap, err := netip.ParseAddrPort(token); err == nil {
					return ap.Addr().WithZone(""), true
				}
			}
		}
		return netip.Addr{}, false
	}

	hasColon := strings.IndexByte(token, ':') != -1
	hasDot := strings.IndexByte(token, '.') != -1

	// Fast path: IPv4 with port ("1.2.3.4:1234")
	if hasColon && hasDot {
		if addrPort, err := netip.ParseAddrPort(token); err == nil {
			return addrPort.Addr().WithZone(""), true
		}
		return netip.Addr{}, false
	}

	// Standard IPv4 ("1.2.3.4") or unbracketed IPv6 ("2001:db8::1")
	if addr, err := netip.ParseAddr(token); err == nil {
		return addr.WithZone(""), true
	}

	// Fallback for non-standard port formats
	if addrPort, err := netip.ParseAddrPort(token); err == nil {
		return addrPort.Addr().WithZone(""), true
	}

	return netip.Addr{}, false
}

// Parse parses the value of the X-Forwarded-For header and returns the rightmost
// public IP address. Evaluating from right to left protects against client IP spoofing
// by prioritizing values appended by downstream proxies.
func Parse(ipList string) string {
	addr, ok := ParseAddr(ipList)
	if !ok {
		return ""
	}
	return addr.String()
}

// ParseAddr parses the value of the X-Forwarded-For header and returns the rightmost
// valid public IP address as a netip.Addr without heap allocations.
func ParseAddr(ipList string) (netip.Addr, bool) {
	end := len(ipList)
	hops := 0
	for end > 0 && hops < defaultMaxHops {
		hops++
		start := strings.LastIndexByte(ipList[:end], ',')
		var token string
		if start == -1 {
			token = ipList[:end]
			end = 0
		} else {
			token = ipList[start+1 : end]
			end = start
		}

		addr, ok := parseIPToken(token)
		if ok && IsPublicAddr(addr) {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// Options is a configuration container to set up the XFF middleware.
type Options struct {
	// AllowedSubnets is a list of trusted proxy CIDRs (e.g. "10.0.0.0/8", "127.0.0.1/32").
	// A valid CIDR string with subnet mask is always required.
	AllowedSubnets []string

	// AllowedFunc allows custom verification of whether a proxy IP is trusted.
	AllowedFunc func(sip string) bool

	// AllowedAddrFunc allows custom verification of whether a proxy IP is trusted
	// directly as a netip.Addr without heap string allocations.
	AllowedAddrFunc func(addr netip.Addr) bool

	// TrustLoopback automatically trusts loopback addresses (127.0.0.0/8, ::1/128)
	// as trusted proxies. Default is true in Default().
	TrustLoopback bool

	// InsecureTrustAll disables all proxy verification and blindly trusts all incoming headers.
	// CAUTION: Enables arbitrary IP spoofing if exposed directly to untrusted clients.
	InsecureTrustAll bool

	// MaxHops limits the number of proxy hops evaluated from right to left (default 30).
	MaxHops int

	// ErrorHandler is called when proxy resolution encounters an error (e.g. ErrMaxHopsExceeded).
	// If nil, Handler replies with http.StatusBadRequest and the error message.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	// Debug adds diagnostic logging to Logger.
	Debug bool

	// Logger defines a custom logger. If nil and Debug is true, logs to os.Stdout.
	Logger *log.Logger
}

// XFF http handler
type XFF struct {
	log             *log.Logger
	allowedFunc     func(sip string) bool
	allowedAddrFunc func(addr netip.Addr) bool
	errorHandler    func(w http.ResponseWriter, r *http.Request, err error)
	trustedV4       []netip.Prefix
	trustedV6       []netip.Prefix
	maxHops         int
	trustAll        bool
	trustLoopback   bool
}

// New creates a new XFF handler with the provided options.
// AllowedSubnets requires valid CIDR notation strings (e.g. "10.0.0.0/8", "192.168.1.1/32").
func New(options Options) (*XFF, error) {
	var (
		v4Prefixes []netip.Prefix
		v6Prefixes []netip.Prefix
	)
	for _, cidr := range options.AllowedSubnets {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		if prefix.Addr().Is4() {
			v4Prefixes = append(v4Prefixes, prefix)
		} else {
			v6Prefixes = append(v6Prefixes, prefix)
		}
	}

	maxHops := options.MaxHops
	if maxHops <= 0 {
		maxHops = defaultMaxHops
	}

	xff := &XFF{
		log:             options.Logger,
		allowedFunc:     options.AllowedFunc,
		allowedAddrFunc: options.AllowedAddrFunc,
		errorHandler:    options.ErrorHandler,
		trustedV4:       v4Prefixes,
		trustedV6:       v6Prefixes,
		maxHops:         maxHops,
		trustAll:        options.InsecureTrustAll,
		trustLoopback:   options.TrustLoopback,
	}

	if options.Debug && xff.log == nil {
		xff.log = log.New(os.Stdout, "[xff] ", log.LstdFlags)
	}

	return xff, nil
}

// Default creates a new XFF handler with safe defaults:
// - Trusts loopback proxies (127.0.0.0/8, ::1/128).
// - Rejects forwarded headers from untrusted networks.
func Default() (*XFF, error) {
	return New(Options{
		TrustLoopback: true,
	})
}

// isAllowed checks if a given netip.Addr is an authorized proxy.
func (xff *XFF) isAllowed(addr netip.Addr) bool {
	if xff.trustAll {
		return true
	}

	addr = addr.Unmap()

	if xff.trustLoopback && addr.IsLoopback() {
		return true
	}

	if xff.allowedAddrFunc != nil && xff.allowedAddrFunc(addr) {
		return true
	}

	if xff.allowedFunc != nil && xff.allowedFunc(addr.String()) {
		return true
	}

	if addr.Is4() {
		for i := range xff.trustedV4 {
			if xff.trustedV4[i].Contains(addr) {
				return true
			}
		}
	} else {
		for i := range xff.trustedV6 {
			if xff.trustedV6[i].Contains(addr) {
				return true
			}
		}
	}

	return false
}

// ResolveClientAddr resolves the real client address from the request by traversing
// the proxy chain backwards (right to left) through trusted proxies.
// If MaxHops is exceeded while still traversing trusted proxies, ErrMaxHopsExceeded is returned.
// If an invalid IP token is encountered from a trusted proxy, ErrInvalidHeader is returned.
func (xff *XFF) ResolveClientAddr(r *http.Request) (netip.Addr, string, error) {
	var (
		remoteAddr netip.Addr
		remotePort string
	)

	// Fast path: standard host:port (e.g. "1.2.3.4:1234" or "[::1]:1234")
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		remoteAddr = ap.Addr()
		colon := strings.LastIndexByte(r.RemoteAddr, ':')
		remotePort = r.RemoteAddr[colon+1:]
	} else {
		// Fallback for host without port or non-standard address formats
		remoteHost, p, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
			p = ""
		}
		remotePort = p

		remoteAddr, err = netip.ParseAddr(strings.Trim(remoteHost, "[]"))
		if err != nil {
			if xff.log != nil {
				xff.log.Printf("invalid remote addr: %s", r.RemoteAddr)
			}
			return netip.Addr{}, remotePort, nil
		}
	}
	remoteAddr = remoteAddr.Unmap()

	// If connecting peer is not a trusted proxy, do not trust any forwarded headers.
	if !xff.isAllowed(remoteAddr) {
		if xff.log != nil {
			xff.log.Printf("peer %s is not an authorized proxy; ignoring headers", remoteAddr)
		}
		return netip.Addr{}, remotePort, nil
	}

	// Supported header: X-Forwarded-For
	var headers []string
	if r.Header != nil {
		headers = r.Header["X-Forwarded-For"]
		if len(headers) == 0 {
			headers = r.Header.Values("X-Forwarded-For")
		}
	}
	if len(headers) == 0 {
		return netip.Addr{}, remotePort, nil
	}

	var candidate netip.Addr
	found := false
	hops := 0

outer:
	for h := len(headers) - 1; h >= 0; h-- {
		s := headers[h]
		end := len(s)
		for end > 0 {
			if hops >= xff.maxHops {
				if xff.log != nil {
					xff.log.Printf("max hops %d exceeded for remote peer %s", xff.maxHops, remoteAddr)
				}
				return netip.Addr{}, remotePort, ErrMaxHopsExceeded
			}
			hops++
			start := strings.LastIndexByte(s[:end], ',')
			var token string
			if start == -1 {
				token = s[:end]
				end = 0
			} else {
				token = s[start+1 : end]
				end = start
			}

			addr, ok := parseIPToken(token)
			if !ok {
				if xff.log != nil {
					xff.log.Printf("invalid IP token %q from trusted proxy %s", token, remoteAddr)
				}
				return netip.Addr{}, remotePort, ErrInvalidHeader
			}
			addr = addr.Unmap()
			candidate = addr
			found = true

			// If this intermediate IP is NOT an allowed proxy, it is the originating client!
			// Stop traversing left to prevent client-injected spoofed headers from taking effect.
			if !xff.isAllowed(addr) {
				break outer
			}
		}
	}

	if !found {
		return netip.Addr{}, remotePort, nil
	}

	if xff.log != nil {
		xff.log.Printf("resolved client %s via proxy %s", candidate, remoteAddr)
	}

	return candidate, remotePort, nil
}

// ResolveRemoteAddr returns the resolved remote address formatted as host:port (or host).
// If resolution encounters an error (e.g. ErrMaxHopsExceeded or ErrInvalidHeader), the error is returned.
// If no proxy headers were resolved or peer is untrusted, it returns r.RemoteAddr and nil.
func (xff *XFF) ResolveRemoteAddr(r *http.Request) (string, error) {
	clientAddr, port, err := xff.ResolveClientAddr(r)
	if err != nil {
		return r.RemoteAddr, err
	}
	if !clientAddr.IsValid() {
		return r.RemoteAddr, nil
	}

	return formatAddrPort(clientAddr, port), nil
}

// GetRemoteAddr parses the given request and returns the resolved remote address
// using safe default options (trusting loopback proxies).
func GetRemoteAddr(r *http.Request) (string, error) {
	defaultXFFOnce.Do(func() {
		defaultXFFInstance, _ = Default()
	})
	return defaultXFFInstance.ResolveRemoteAddr(r)
}

// GetRemoteAddrIfAllowed parses the given request, resolves the proxy header
// and returns the resolved remote address if the connecting IP satisfies the allowed predicate.
func GetRemoteAddrIfAllowed(r *http.Request, allowed func(sip string) bool) (string, error) {
	xffmw := XFF{
		allowedFunc: allowed,
		maxHops:     defaultMaxHops,
	}
	return xffmw.ResolveRemoteAddr(r)
}

// Handler updates r.RemoteAddr and injects the resolved netip.Addr into the request context.
// If an error occurs (such as ErrMaxHopsExceeded), ErrorHandler is invoked, or http.StatusBadRequest is returned.
func (xff *XFF) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientAddr, port, err := xff.ResolveClientAddr(r)
		if err != nil {
			if xff.errorHandler != nil {
				xff.errorHandler(w, r, err)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if clientAddr.IsValid() {
			r.RemoteAddr = formatAddrPort(clientAddr, port)
			r = r.WithContext(ContextWithClientAddr(r.Context(), clientAddr))
		}
		h.ServeHTTP(w, r)
	})
}

// ServeHTTP provides Negroni-compatible middleware interface.
func (xff *XFF) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	clientAddr, port, err := xff.ResolveClientAddr(r)
	if err != nil {
		if xff.errorHandler != nil {
			xff.errorHandler(w, r, err)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if clientAddr.IsValid() {
		r.RemoteAddr = formatAddrPort(clientAddr, port)
		r = r.WithContext(ContextWithClientAddr(r.Context(), clientAddr))
	}
	next(w, r)
}

// HandlerFunc provides Martini-compatible handler.
func (xff *XFF) HandlerFunc(w http.ResponseWriter, r *http.Request) {
	addr, err := xff.ResolveRemoteAddr(r)
	if err == nil {
		r.RemoteAddr = addr
	}
}
