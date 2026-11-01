package xff

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_none(t *testing.T) {
	res := Parse("")
	assert.Equal(t, "", res)
}

func TestParse_localhost(t *testing.T) {
	res := Parse("127.0.0.1")
	assert.Equal(t, "", res)
}

func TestParse_invalid(t *testing.T) {
	res := Parse("invalid")
	assert.Equal(t, "", res)
}

func TestParse_invalid_sioux(t *testing.T) {
	res := Parse("123#1#2#3")
	assert.Equal(t, "", res)
}

func TestParse_invalid_private_lookalike(t *testing.T) {
	res := Parse("102.3.2.1")
	assert.Equal(t, "102.3.2.1", res)
}

func TestParse_valid(t *testing.T) {
	res := Parse("68.45.152.220")
	assert.Equal(t, "68.45.152.220", res)
}

func TestParse_multi_rightmost(t *testing.T) {
	// Secure right-to-left parsing picks the rightmost public IP
	res := Parse("12.13.14.15, 68.45.152.220")
	assert.Equal(t, "68.45.152.220", res)
}

func TestParse_multi_last(t *testing.T) {
	res := Parse("192.168.110.162, 190.57.149.90")
	assert.Equal(t, "190.57.149.90", res)
}

func TestParse_multi_with_invalid(t *testing.T) {
	res := Parse("192.168.110.162, invalid, 190.57.149.90")
	assert.Equal(t, "190.57.149.90", res)
}

func TestParse_multi_with_invalid2(t *testing.T) {
	res := Parse("192.168.110.162, 190.57.149.90, invalid")
	assert.Equal(t, "190.57.149.90", res)
}

func TestParse_multi_with_invalid_sioux(t *testing.T) {
	res := Parse("192.168.110.162, 190.57.149.90, 123#1#2#3")
	assert.Equal(t, "190.57.149.90", res)
}

func TestParse_ipv6(t *testing.T) {
	res := Parse("2604:2000:71a9:bf00:f178:a500:9a2d:670d")
	assert.Equal(t, "2604:2000:71a9:bf00:f178:a500:9a2d:670d", res)
}

func TestParse_ipv6_with_port(t *testing.T) {
	res := Parse("[2604:2000:71a9:bf00:f178:a500:9a2d:670d]:8080")
	assert.Equal(t, "2604:2000:71a9:bf00:f178:a500:9a2d:670d", res)
}

func TestIsPublicIP(t *testing.T) {
	// Standard private IPv4
	assert.False(t, IsPublicIP(net.ParseIP("127.0.0.1")))
	assert.False(t, IsPublicIP(net.ParseIP("10.0.0.1")))
	assert.False(t, IsPublicIP(net.ParseIP("172.16.0.1")))
	assert.False(t, IsPublicIP(net.ParseIP("192.168.1.1")))
	assert.False(t, IsPublicIP(net.ParseIP("169.254.169.254")))

	// Bogons and special ranges
	assert.False(t, IsPublicIP(net.ParseIP("100.64.0.1")))       // CGNAT (RFC 6598)
	assert.False(t, IsPublicIP(net.ParseIP("198.18.0.1")))       // Benchmarking (RFC 2544)
	assert.False(t, IsPublicIP(net.ParseIP("192.0.2.1")))        // TEST-NET-1 (RFC 5737)
	assert.False(t, IsPublicIP(net.ParseIP("198.51.100.1")))     // TEST-NET-2 (RFC 5737)
	assert.False(t, IsPublicIP(net.ParseIP("203.0.113.1")))      // TEST-NET-3 (RFC 5737)
	assert.False(t, IsPublicIP(net.ParseIP("240.0.0.1")))        // Class E (RFC 1112)
	assert.False(t, IsPublicIP(net.ParseIP("0.0.0.1")))          // RFC 791
	assert.False(t, IsPublicIP(net.ParseIP("255.255.255.255")))  // Broadcast

	// IPv6 private & bogon
	assert.False(t, IsPublicIP(net.ParseIP("::1")))
	assert.False(t, IsPublicIP(net.ParseIP("fc00::1")))
	assert.False(t, IsPublicIP(net.ParseIP("fe80::1")))
	assert.False(t, IsPublicIP(net.ParseIP("2001:db8::1")))
	assert.False(t, IsPublicIP(net.ParseIP("100::1")))

	// Deprecated IPv4-compatible IPv6 (RFC 4291)
	assert.False(t, IsPublicIP(net.ParseIP("::192.0.2.1")))
	assert.False(t, IsPublicIP(net.ParseIP("::8.8.8.8")))

	// IPv4-mapped IPv6
	assert.False(t, IsPublicIP(net.ParseIP("::ffff:127.0.0.1")))
	assert.False(t, IsPublicIP(net.ParseIP("::ffff:10.0.0.1")))
	assert.False(t, IsPublicIP(net.ParseIP("::ffff:169.254.1.1")))

	// Valid public IPs
	assert.True(t, IsPublicIP(net.ParseIP("8.8.8.8")))
	assert.True(t, IsPublicIP(net.ParseIP("::ffff:8.8.8.8")))
	assert.True(t, IsPublicIP(net.ParseIP("2604:2000:71a9:bf00:f178:a500:9a2d:670d")))
}

func TestIsPublicAddr(t *testing.T) {
	assert.False(t, IsPublicAddr(netip.Addr{}))
	assert.False(t, IsPublicAddr(netip.MustParseAddr("100.64.0.1")))
	assert.False(t, IsPublicAddr(netip.MustParseAddr("240.0.0.1")))
	assert.True(t, IsPublicAddr(netip.MustParseAddr("8.8.8.8")))
}

func TestGetRemoteAddr_ipv4(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4:1234", ra)
}

func TestGetRemoteAddr_ipv6(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "[2001:db8:0:1:1:1:1:1]:1234",
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "[2001:db8:0:1:1:1:1:1]:1234", ra)
}

func TestGetRemoteAddr_untrusted_direct_peer(t *testing.T) {
	// Default() only trusts loopback; untrusted direct peer cannot spoof XFF
	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
		Header: http.Header{
			"X-Forwarded-For": []string{"100.0.0.1"},
		},
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4:1234", ra)
}

func TestGetRemoteAddr_untrusted_non_standard_addr(t *testing.T) {
	// Preserves non-standard address format (e.g. unix domain socket) directly
	r := &http.Request{
		RemoteAddr: "@custom-socket",
		Header: http.Header{
			"X-Forwarded-For": []string{"8.8.8.8"},
		},
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "@custom-socket", ra)
}

func TestGetRemoteAddr_trusted_loopback_proxy(t *testing.T) {
	// Loopback proxy is trusted by Default()
	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header: http.Header{
			"X-Forwarded-For": []string{"8.8.8.8"},
		},
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:1234", ra)
}

func TestGetRemoteAddr_ipv6_with_xff(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header: http.Header{
			"X-Forwarded-For": []string{"2604:2000:71a9:bf00:f178:a500:9a2d:670d"},
		},
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "[2604:2000:71a9:bf00:f178:a500:9a2d:670d]:1234", ra)
}

func TestGetRemoteAddr_invalid_remote_addr(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "invalid-remote-addr",
		Header: http.Header{
			"X-Forwarded-For": []string{"8.8.8.8"},
		},
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "invalid-remote-addr", ra)
}

func TestGetRemoteAddr_empty_xff(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header: http.Header{
			"X-Forwarded-For": []string{""},
		},
	}
	ra, err := GetRemoteAddr(r)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:1234", ra)
}

func TestGetRemoteAddr_not_allowed(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
		Header: http.Header{
			"X-Forwarded-For": []string{"8.8.8.8"},
		},
	}
	ra, err := GetRemoteAddrIfAllowed(r, func(sip string) bool { return false })
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4:1234", ra)
}

func TestGetRemoteAddr_allowed(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
		Header: http.Header{
			"X-Forwarded-For": []string{"8.8.8.8"},
		},
	}
	ra, err := GetRemoteAddrIfAllowed(r, func(sip string) bool { return sip == "1.2.3.4" })
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:1234", ra)
}

func TestAllowedAddrFunc(t *testing.T) {
	xffmw, err := New(Options{
		AllowedAddrFunc: func(addr netip.Addr) bool {
			return addr == netip.MustParseAddr("1.2.3.4")
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	ra, err := xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:1234", ra)

	// Untrusted peer rejected
	req.RemoteAddr = "1.2.3.5:1234"
	ra, err = xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.5:1234", ra)
}

func TestAllowedFunc_Options(t *testing.T) {
	xffmw, err := New(Options{
		AllowedFunc: func(sip string) bool {
			return sip == "10.1.2.3"
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	ra, err := xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:1234", ra)

	reqUntrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	reqUntrusted.RemoteAddr = "10.1.2.4:1234"
	reqUntrusted.Header.Set("X-Forwarded-For", "8.8.8.8")
	ra, err = xffmw.ResolveRemoteAddr(reqUntrusted)
	require.NoError(t, err)
	assert.Equal(t, "10.1.2.4:1234", ra)
}

func TestIPv4MappedIPv6Peer(t *testing.T) {
	// Dual-stack listeners in Go receive IPv4 connections as IPv4-mapped IPv6 (::ffff:x.x.x.x)
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
		TrustLoopback:  true,
	})
	require.NoError(t, err)

	// 1. IPv4-mapped loopback proxy
	reqLoopback := httptest.NewRequest(http.MethodGet, "/", nil)
	reqLoopback.RemoteAddr = "[::ffff:127.0.0.1]:1234"
	reqLoopback.Header.Set("X-Forwarded-For", "8.8.8.8")

	ra, err := xffmw.ResolveRemoteAddr(reqLoopback)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:1234", ra)

	// 2. IPv4-mapped private proxy in AllowedSubnets
	reqProxy := httptest.NewRequest(http.MethodGet, "/", nil)
	reqProxy.RemoteAddr = "[::ffff:10.0.0.1]:5432"
	reqProxy.Header.Set("X-Forwarded-For", "9.9.9.9")

	ra, err = xffmw.ResolveRemoteAddr(reqProxy)
	require.NoError(t, err)
	assert.Equal(t, "9.9.9.9:5432", ra)

	// 3. IPv4-mapped untrusted peer
	reqUntrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	reqUntrusted.RemoteAddr = "[::ffff:1.2.3.4]:1234"
	reqUntrusted.Header.Set("X-Forwarded-For", "9.9.9.9")

	ra, err = xffmw.ResolveRemoteAddr(reqUntrusted)
	require.NoError(t, err)
	assert.Equal(t, "[::ffff:1.2.3.4]:1234", ra)
}

func TestNew_strict_cidr_validation(t *testing.T) {
	// Rejects invalid string
	m, err := New(Options{
		AllowedSubnets: []string{"invalid"},
	})
	assert.Nil(t, m)
	assert.NotNil(t, err)

	// Rejects single IP without CIDR notation
	m2, err2 := New(Options{
		AllowedSubnets: []string{"10.0.0.1"},
	})
	assert.Nil(t, m2)
	assert.NotNil(t, err2)

	// Accepts valid CIDR notation
	m3, err3 := New(Options{
		AllowedSubnets: []string{"10.0.0.1/32", "192.168.0.0/16", "::1/128"},
	})
	assert.NotNil(t, m3)
	assert.NoError(t, err3)
}

func TestNew_debug(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "[test] ", 0)
	m, err := New(Options{
		Debug:         true,
		Logger:        logger,
		TrustLoopback: true,
	})
	require.NoError(t, err)
	require.NotNil(t, m)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	_, err = m.ResolveRemoteAddr(req)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "resolved client 8.8.8.8 via proxy 127.0.0.1")

	// Test untrusted peer logging
	buf.Reset()
	reqUntrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	reqUntrusted.RemoteAddr = "1.2.3.4:1234"
	reqUntrusted.Header.Set("X-Forwarded-For", "8.8.8.8")
	_, _ = m.ResolveRemoteAddr(reqUntrusted)

	assert.Contains(t, buf.String(), "peer 1.2.3.4 is not an authorized proxy; ignoring headers")
}

func TestProxyChain_SpoofingPrevention(t *testing.T) {
	// Attacker sends forged '1.1.1.1'.
	// Proxy ALB (10.0.0.1) appends attacker's real IP '198.51.100.25'.
	// Middleware must resolve '198.51.100.25' and NOT the forged '1.1.1.1'.
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5432"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.25")

	resolved, err := xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.25:5432", resolved)
}

func TestProxyChain_MultiHopTrusted(t *testing.T) {
	// Client (203.0.113.195) -> Proxy1 (172.16.0.5) -> Proxy2 (10.0.0.2) -> Go Server
	// Both proxies are in AllowedSubnets.
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8", "172.16.0.0/12"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:8000"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 172.16.0.5")

	resolved, err := xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.195:8000", resolved)
}

func TestProxyChain_MultiLineHeaders(t *testing.T) {
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8000"
	req.Header.Add("X-Forwarded-For", "1.1.1.1")
	req.Header.Add("X-Forwarded-For", "198.51.100.25")

	resolved, err := xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.25:8000", resolved)
}

func TestProxyChain_MaxHopsError(t *testing.T) {
	// User requirement: throw an error when MaxHops is exceeded while still traversing
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
		MaxHops:        2,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8000"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.3, 10.0.0.2")

	_, err = xffmw.ResolveRemoteAddr(req)
	assert.ErrorIs(t, err, ErrMaxHopsExceeded)

	// Verify Handler returns 400 Bad Request on error
	rec := httptest.NewRecorder()
	handler := xffmw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "maximum proxy hops exceeded")
}

func TestProxyChain_InvalidTokenError(t *testing.T) {
	// A trusted proxy forwarding an invalid IP token throws ErrInvalidHeader
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8000"
	req.Header.Set("X-Forwarded-For", "invalid-ip")

	_, err = xffmw.ResolveRemoteAddr(req)
	assert.ErrorIs(t, err, ErrInvalidHeader)

	// Verify Handler returns 400 Bad Request on error and aborts downstream execution
	rec := httptest.NewRecorder()
	downstreamCalled := false
	handler := xffmw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamCalled = true
	}))
	handler.ServeHTTP(rec, req)
	assert.False(t, downstreamCalled, "downstream handler must not be called on invalid token")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid IP in X-Forwarded-For header")
}

func TestProxyChain_CustomErrorHandler(t *testing.T) {
	var handledErr error
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
		MaxHops:        1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			handledErr = err
			http.Error(w, "custom error", http.StatusBadGateway)
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8000"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.2")

	rec := httptest.NewRecorder()
	handler := xffmw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.ErrorIs(t, handledErr, ErrMaxHopsExceeded)
}

func TestXFF_Handler(t *testing.T) {
	xffmw, err := Default()
	require.NoError(t, err)

	var recordedAddr string
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordedAddr = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	})

	handler := xffmw.Handler(nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "68.45.152.220")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "68.45.152.220:1234", recordedAddr)
}

func TestXFF_ContextPropagation(t *testing.T) {
	xffmw, err := Default()
	require.NoError(t, err)

	var extracted netip.Addr
	var hasAddr bool

	handler := xffmw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extracted, hasAddr = ClientAddrFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "68.45.152.220")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, hasAddr)
	assert.Equal(t, netip.MustParseAddr("68.45.152.220"), extracted)

	// Context without client addr
	_, emptyHas := ClientAddrFromContext(nil)
	assert.False(t, emptyHas)
}

func TestXFF_ServeHTTP(t *testing.T) {
	xffmw, err := Default()
	require.NoError(t, err)

	var recordedAddr string
	var extracted netip.Addr
	next := func(w http.ResponseWriter, r *http.Request) {
		recordedAddr = r.RemoteAddr
		extracted, _ = ClientAddrFromContext(r.Context())
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "68.45.152.220")

	rec := httptest.NewRecorder()
	xffmw.ServeHTTP(rec, req, next)

	assert.Equal(t, "68.45.152.220:1234", recordedAddr)
	assert.Equal(t, netip.MustParseAddr("68.45.152.220"), extracted)
}

func TestXFF_HandlerFunc(t *testing.T) {
	xffmw, err := Default()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "68.45.152.220")

	rec := httptest.NewRecorder()
	xffmw.HandlerFunc(rec, req)

	assert.Equal(t, "68.45.152.220:1234", req.RemoteAddr)
}

func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add("68.45.152.220")
	f.Add("12.13.14.15, 68.45.152.220")
	f.Add("[2001:db8::1]:8080")
	f.Add(strings.Repeat(",", 500))
	f.Add(strings.Repeat("1.2.3.4,", 100))

	f.Fuzz(func(t *testing.T, input string) {
		_ = Parse(input)
	})
}

func FuzzResolveRemoteAddr(f *testing.F) {
	xffmw, _ := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8", "127.0.0.0/8"},
	})

	f.Add("10.0.0.1:1234", "68.45.152.220")
	f.Add("127.0.0.1:80", "127.0.0.1")
	f.Add("invalid", "invalid")
	f.Add("10.0.0.1:443", strings.Repeat("1.1.1.1,", 100))

	f.Fuzz(func(t *testing.T, remoteAddr, headerVal string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", headerVal)
		_, _ = xffmw.ResolveRemoteAddr(req)
	})
}

func TestTrimToken_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"   ", ""},
		{"\"\"", ""},
		{"''", ""},
		{"\t' 1.2.3.4 ' \t", "1.2.3.4"},
		{"\"192.168.1.1\"", "192.168.1.1"},
		{"'2001:db8::1'", "2001:db8::1"},
		{"  \"10.0.0.1\"  ", "10.0.0.1"},
		{"'\"nested\"'", "nested"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("trim_%s", tc.input), func(t *testing.T) {
			assert.Equal(t, tc.expected, trimToken(tc.input))
		})
	}
}

func TestParseIPToken_Matrix(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected netip.Addr
		valid    bool
	}{
		{"IPv4 standard", "1.2.3.4", netip.MustParseAddr("1.2.3.4"), true},
		{"IPv4 with port", "1.2.3.4:1234", netip.MustParseAddr("1.2.3.4"), true},
		{"IPv4 with port 0", "1.2.3.4:0", netip.MustParseAddr("1.2.3.4"), true},
		{"IPv4 with max port", "1.2.3.4:65535", netip.MustParseAddr("1.2.3.4"), true},
		{"IPv4 with invalid port number", "1.2.3.4:999999", netip.Addr{}, false},
		{"IPv4 with alphabetic port", "1.2.3.4:abc", netip.Addr{}, false},
		{"IPv4 with negative port", "1.2.3.4:-80", netip.Addr{}, false},
		{"IPv4 with colon only", "1.2.3.4:", netip.Addr{}, false},
		{"IPv6 unbracketed", "2001:db8::1", netip.MustParseAddr("2001:db8::1"), true},
		{"IPv6 bracketed without port", "[2001:db8::1]", netip.MustParseAddr("2001:db8::1"), true},
		{"IPv6 bracketed with port", "[2001:db8::1]:8080", netip.MustParseAddr("2001:db8::1"), true},
		{"IPv6 bracketed loopback with port", "[::1]:443", netip.MustParseAddr("::1"), true},
		{"IPv6 unclosed bracket", "[2001:db8::1", netip.Addr{}, false},
		{"IPv6 missing open bracket", "2001:db8::1]", netip.Addr{}, false},
		{"IPv6 empty brackets", "[]", netip.Addr{}, false},
		{"IPv6 bracketed invalid IP", "[invalid-ip]", netip.Addr{}, false},
		{"IPv6 bracketed invalid with port", "[invalid-ip]:8080", netip.Addr{}, false},
		{"IPv6 bracketed with invalid port", "[::1]:badport", netip.Addr{}, false},
		{"Empty string", "", netip.Addr{}, false},
		{"Whitespace only", "   ", netip.Addr{}, false},
		{"Invalid hostname string", "example.com", netip.Addr{}, false},
		{"Random noise", "!@#$%^", netip.Addr{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok := parseIPToken(tc.token)
			assert.Equal(t, tc.valid, ok)
			if tc.valid {
				assert.Equal(t, tc.expected, addr)
			}
		})
	}
}

func TestFormatAddrPort_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		addr     netip.Addr
		port     string
		expected string
	}{
		{"IPv4 with port", netip.MustParseAddr("1.2.3.4"), "1234", "1.2.3.4:1234"},
		{"IPv4 without port", netip.MustParseAddr("1.2.3.4"), "", "1.2.3.4"},
		{"IPv6 with port", netip.MustParseAddr("2001:db8::1"), "8080", "[2001:db8::1]:8080"},
		{"IPv6 without port", netip.MustParseAddr("2001:db8::1"), "", "2001:db8::1"},
		{"IPv6 loopback with port", netip.MustParseAddr("::1"), "443", "[::1]:443"},
		{"IPv6 loopback without port", netip.MustParseAddr("::1"), "", "::1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := formatAddrPort(tc.addr, tc.port)
			assert.Equal(t, tc.expected, res)
		})
	}
}

func TestIsPublicIP_EdgeCases(t *testing.T) {
	assert.False(t, IsPublicIP(nil), "nil net.IP must return false")
	assert.False(t, IsPublicIP(net.IP([]byte{})), "empty IP slice must return false")
	assert.False(t, IsPublicIP(net.IP([]byte{1, 2, 3})), "3-byte slice must return false")
	assert.False(t, IsPublicIP(net.IP([]byte{1, 2, 3, 4, 5})), "5-byte slice must return false")
	assert.False(t, IsPublicIP(net.IP(make([]byte, 17))), "17-byte slice must return false")
	assert.True(t, IsPublicIP(net.ParseIP("1.1.1.1")))
	assert.True(t, IsPublicIP(net.ParseIP("2606:4700:4700::1111")))
}

func TestBogonRanges_Exhaustive(t *testing.T) {
	tests := []struct {
		ip       string
		isPublic bool
		reason   string
	}{
		// IPv4 Bogon & Reserved
		{"0.0.0.0", false, "RFC 791 Current network"},
		{"0.255.255.255", false, "RFC 791 Current network end"},
		{"100.64.0.0", false, "RFC 6598 CGNAT start"},
		{"100.127.255.255", false, "RFC 6598 CGNAT end"},
		{"100.63.255.255", true, "Immediately before CGNAT"},
		{"100.128.0.0", true, "Immediately after CGNAT"},
		{"192.0.0.1", false, "RFC 6890 IETF Protocol Assignments"},
		{"192.0.2.1", false, "RFC 5737 TEST-NET-1"},
		{"192.88.99.1", false, "RFC 7526 6to4 Relay Anycast"},
		{"198.18.0.1", false, "RFC 2544 Benchmarking start"},
		{"198.19.255.254", false, "RFC 2544 Benchmarking end"},
		{"198.20.0.1", true, "Immediately after Benchmarking"},
		{"198.51.100.1", false, "RFC 5737 TEST-NET-2"},
		{"203.0.113.1", false, "RFC 5737 TEST-NET-3"},
		{"240.0.0.1", false, "RFC 1112 Reserved/Class E"},
		{"255.255.255.254", false, "RFC 1112 Reserved/Class E"},
		{"255.255.255.255", false, "RFC 919 Broadcast"},

		// IPv6 Bogon & Reserved
		{"::1.2.3.4", false, "RFC 4291 IPv4-compatible IPv6"},
		{"100::1", false, "RFC 6666 Discard prefix"},
		{"2001::1", false, "RFC 2928 IETF Protocol Assignments"},
		{"2001:db8::1", false, "RFC 3849 Documentation"},

		// Valid Public
		{"1.1.1.1", true, "Cloudflare DNS"},
		{"8.8.8.8", true, "Google DNS"},
		{"2001:4860:4860::8888", true, "Google Public IPv6 DNS"},
		{"2606:4700:4700::1111", true, "Cloudflare Public IPv6 DNS"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s (%s)", tc.ip, tc.reason), func(t *testing.T) {
			addr := netip.MustParseAddr(tc.ip)
			assert.Equal(t, tc.isPublic, IsPublicAddr(addr))
			assert.Equal(t, tc.isPublic, IsPublicIP(net.ParseIP(tc.ip)))
		})
	}
}

func TestNew_EdgeCases(t *testing.T) {
	// Empty strings and whitespace in AllowedSubnets are ignored
	m, err := New(Options{
		AllowedSubnets: []string{"", "   ", "\t", "10.0.0.0/8"},
	})
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Len(t, m.trustedV4, 1)

	// MaxHops <= 0 defaults to defaultMaxHops (30)
	mZeroHops, err := New(Options{MaxHops: 0})
	require.NoError(t, err)
	assert.Equal(t, defaultMaxHops, mZeroHops.maxHops)

	mNegativeHops, err := New(Options{MaxHops: -10})
	require.NoError(t, err)
	assert.Equal(t, defaultMaxHops, mNegativeHops.maxHops)

	// Debug without custom Logger initializes os.Stdout logger
	mDebug, err := New(Options{Debug: true})
	require.NoError(t, err)
	assert.NotNil(t, mDebug.log)
}

func TestInsecureTrustAll(t *testing.T) {
	xffmw, err := New(Options{
		InsecureTrustAll: true,
	})
	require.NoError(t, err)

	// Direct connecting peer is an untrusted public IP
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 9.9.9.9")

	resolved, err := xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	// InsecureTrustAll trusts all proxies in chain and resolves the leftmost origin IP
	assert.Equal(t, "8.8.8.8:1234", resolved)
}

func TestIPv6TrustedProxies(t *testing.T) {
	xffmw, err := New(Options{
		AllowedSubnets: []string{"fd00::/8", "2001:db8::/32"},
	})
	require.NoError(t, err)

	// Trusted IPv6 ULA peer
	reqULA := httptest.NewRequest(http.MethodGet, "/", nil)
	reqULA.RemoteAddr = "[fd00::1]:5000"
	reqULA.Header.Set("X-Forwarded-For", "8.8.8.8")
	resULA, err := xffmw.ResolveRemoteAddr(reqULA)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:5000", resULA)

	// Trusted IPv6 documentation peer
	reqDoc := httptest.NewRequest(http.MethodGet, "/", nil)
	reqDoc.RemoteAddr = "[2001:db8::10]:5000"
	reqDoc.Header.Set("X-Forwarded-For", "8.8.8.8")
	resDoc, err := xffmw.ResolveRemoteAddr(reqDoc)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:5000", resDoc)

	// Untrusted IPv6 peer (outside fd00::/8 and 2001:db8::/32)
	reqUntrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	reqUntrusted.RemoteAddr = "[2606:4700::1]:5000"
	reqUntrusted.Header.Set("X-Forwarded-For", "8.8.8.8")
	resUntrusted, err := xffmw.ResolveRemoteAddr(reqUntrusted)
	require.NoError(t, err)
	assert.Equal(t, "[2606:4700::1]:5000", resUntrusted)
}

func TestEntireChainTrusted(t *testing.T) {
	// When all IPs in the X-Forwarded-For header are trusted proxies,
	// the leftmost proxy IP should be selected as the candidate.
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8000"
	req.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.2")

	resolved, err := xffmw.ResolveRemoteAddr(req)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.3:8000", resolved)
}

func TestResolveClientAddr_NilHeaderAndPortless(t *testing.T) {
	xffmw, err := Default()
	require.NoError(t, err)

	// Request with nil Header
	reqNilHeader := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header:     nil,
	}
	res, err := xffmw.ResolveRemoteAddr(reqNilHeader)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:1234", res)

	// Request with IPv4 without port
	reqNoPortV4 := &http.Request{
		RemoteAddr: "127.0.0.1",
		Header: http.Header{
			"X-Forwarded-For": []string{"8.8.8.8"},
		},
	}
	resV4, err := xffmw.ResolveRemoteAddr(reqNoPortV4)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8", resV4)

	// Request with IPv6 without port
	reqNoPortV6 := &http.Request{
		RemoteAddr: "::1",
		Header: http.Header{
			"X-Forwarded-For": []string{"8.8.8.8"},
		},
	}
	resV6, err := xffmw.ResolveRemoteAddr(reqNoPortV6)
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8", resV6)

	// Request with empty RemoteAddr
	reqEmpty := &http.Request{
		RemoteAddr: "",
	}
	resEmpty, err := xffmw.ResolveRemoteAddr(reqEmpty)
	require.NoError(t, err)
	assert.Equal(t, "", resEmpty)

	// Request with empty slice for X-Forwarded-For
	reqEmptySlice := &http.Request{
		RemoteAddr: "127.0.0.1:1234",
		Header: http.Header{
			"X-Forwarded-For": []string{},
		},
	}
	resEmptySlice, err := xffmw.ResolveRemoteAddr(reqEmptySlice)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:1234", resEmptySlice)
}

func TestServeHTTP_ErrorHandling(t *testing.T) {
	// 1. ErrMaxHopsExceeded with default 400 Bad Request
	xffmwHops, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
		MaxHops:        1,
	})
	require.NoError(t, err)

	reqHops := httptest.NewRequest(http.MethodGet, "/", nil)
	reqHops.RemoteAddr = "10.0.0.1:8000"
	reqHops.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.2")

	recHops := httptest.NewRecorder()
	nextCalled := false
	xffmwHops.ServeHTTP(recHops, reqHops, func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	assert.False(t, nextCalled, "next handler must NOT be called on MaxHops error")
	assert.Equal(t, http.StatusBadRequest, recHops.Code)
	assert.Contains(t, recHops.Body.String(), "maximum proxy hops exceeded")

	// 2. ErrInvalidHeader with default 400 Bad Request
	xffmwInvalid, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
	})
	require.NoError(t, err)

	reqInvalid := httptest.NewRequest(http.MethodGet, "/", nil)
	reqInvalid.RemoteAddr = "10.0.0.1:8000"
	reqInvalid.Header.Set("X-Forwarded-For", "malformed-ip")

	recInvalid := httptest.NewRecorder()
	nextCalled = false
	xffmwInvalid.ServeHTTP(recInvalid, reqInvalid, func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	assert.False(t, nextCalled, "next handler must NOT be called on invalid token")
	assert.Equal(t, http.StatusBadRequest, recInvalid.Code)
	assert.Contains(t, recInvalid.Body.String(), "invalid IP in X-Forwarded-For header")

	// 3. Custom ErrorHandler
	var customErr error
	xffmwCustom, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			customErr = err
			http.Error(w, "gateway error", http.StatusBadGateway)
		},
	})
	require.NoError(t, err)

	recCustom := httptest.NewRecorder()
	nextCalled = false
	xffmwCustom.ServeHTTP(recCustom, reqInvalid, func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusBadGateway, recCustom.Code)
	assert.ErrorIs(t, customErr, ErrInvalidHeader)
}

func TestHandlerFunc_ErrorHandling(t *testing.T) {
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8000"
	req.Header.Set("X-Forwarded-For", "invalid-ip")

	rec := httptest.NewRecorder()
	xffmw.HandlerFunc(rec, req)

	// RemoteAddr should remain unchanged on error
	assert.Equal(t, "10.0.0.1:8000", req.RemoteAddr)
}

func TestDebugLogging_Complete(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "[xff-test] ", 0)

	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8"},
		MaxHops:        1,
		Debug:          true,
		Logger:         logger,
	})
	require.NoError(t, err)

	// 1. Invalid remote addr logging
	buf.Reset()
	reqInvalidRemote := httptest.NewRequest(http.MethodGet, "/", nil)
	reqInvalidRemote.RemoteAddr = "invalid-peer"
	_, _ = xffmw.ResolveRemoteAddr(reqInvalidRemote)
	assert.Contains(t, buf.String(), "invalid remote addr: invalid-peer")

	// 2. Max hops exceeded logging
	buf.Reset()
	reqMaxHops := httptest.NewRequest(http.MethodGet, "/", nil)
	reqMaxHops.RemoteAddr = "10.0.0.1:8000"
	reqMaxHops.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.2")
	_, _ = xffmw.ResolveRemoteAddr(reqMaxHops)
	assert.Contains(t, buf.String(), "max hops 1 exceeded for remote peer 10.0.0.1")

	// 3. Invalid IP token logging
	buf.Reset()
	reqInvalidToken := httptest.NewRequest(http.MethodGet, "/", nil)
	reqInvalidToken.RemoteAddr = "10.0.0.1:8000"
	reqInvalidToken.Header.Set("X-Forwarded-For", "bad-ip")
	_, _ = xffmw.ResolveRemoteAddr(reqInvalidToken)
	assert.Contains(t, buf.String(), "invalid IP token \"bad-ip\" from trusted proxy 10.0.0.1")
}

func TestConcurrency_RaceAudit(t *testing.T) {
	xffmw, err := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8", "127.0.0.0/8"},
		TrustLoopback:  true,
	})
	require.NoError(t, err)

	handler := xffmw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, ok := ClientAddrFromContext(r.Context())
		if !ok || !addr.IsValid() {
			http.Error(w, "missing context addr", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	const concurrency = 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()

			clientIP := fmt.Sprintf("198.51.100.%d", (id%200)+1)

			// 1. Test Handler
			reqHandler := httptest.NewRequest(http.MethodGet, "/", nil)
			reqHandler.RemoteAddr = "10.0.0.1:8000"
			reqHandler.Header.Set("X-Forwarded-For", clientIP)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, reqHandler)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, fmt.Sprintf("%s:8000", clientIP), reqHandler.RemoteAddr)

			// 2. Test ServeHTTP
			reqServeHTTP := httptest.NewRequest(http.MethodGet, "/", nil)
			reqServeHTTP.RemoteAddr = "10.0.0.1:8000"
			reqServeHTTP.Header.Set("X-Forwarded-For", clientIP)
			rec2 := httptest.NewRecorder()
			xffmw.ServeHTTP(rec2, reqServeHTTP, func(w http.ResponseWriter, r *http.Request) {
				extracted, ok := ClientAddrFromContext(r.Context())
				assert.True(t, ok)
				assert.Equal(t, netip.MustParseAddr(clientIP), extracted)
			})

			// 3. Test GetRemoteAddr (stresses sync.Once concurrent safety)
			reqLoopback := httptest.NewRequest(http.MethodGet, "/", nil)
			reqLoopback.RemoteAddr = "127.0.0.1:9000"
			reqLoopback.Header.Set("X-Forwarded-For", clientIP)
			ra, err := GetRemoteAddr(reqLoopback)
			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("%s:9000", clientIP), ra)
		}(i)
	}

	wg.Wait()
}
