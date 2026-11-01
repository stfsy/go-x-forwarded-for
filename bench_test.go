package xff

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

func BenchmarkParseSingle(b *testing.B) {
	header := "68.45.152.220"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Parse(header)
	}
}

func BenchmarkParseAddrSingle(b *testing.B) {
	header := "68.45.152.220"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseAddr(header)
	}
}

func BenchmarkParseMulti(b *testing.B) {
	header := "192.168.1.1, 10.0.0.1, 68.45.152.220"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Parse(header)
	}
}

func BenchmarkGetRemoteAddrNoHeader(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetRemoteAddr(req)
	}
}

func BenchmarkGetRemoteAddrWithHeader(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "68.45.152.220")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetRemoteAddr(req)
	}
}

func BenchmarkHandlerDefault(b *testing.B) {
	xffmw, _ := Default()
	handler := xffmw.Handler(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.Header.Set("X-Forwarded-For", "68.45.152.220")
	w := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.RemoteAddr = "127.0.0.1:1234"
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkHandlerAllowedSubnets(b *testing.B) {
	xffmw, _ := New(Options{
		AllowedSubnets: []string{"1.2.0.0/16"},
	})
	handler := xffmw.Handler(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.Header.Set("X-Forwarded-For", "68.45.152.220")
	w := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkHandlerMultiHop(b *testing.B) {
	xffmw, _ := New(Options{
		AllowedSubnets: []string{"10.0.0.0/8", "172.16.0.0/12"},
	})
	handler := xffmw.Handler(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 172.16.0.2")
	w := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.RemoteAddr = "10.0.0.1:1234"
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkIsPublicAddr_IPv4(b *testing.B) {
	addr, _ := parseIPToken("68.45.152.220")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsPublicAddr(addr)
	}
}

func BenchmarkIsPublicAddr_IPv6(b *testing.B) {
	addr, _ := parseIPToken("2604:2000:71a9:bf00:f178:a500:9a2d:670d")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsPublicAddr(addr)
	}
}

func BenchmarkFormatAddrPort(b *testing.B) {
	addr, _ := parseIPToken("68.45.152.220")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = formatAddrPort(addr, "1234")
	}
}

func BenchmarkParseTokenWithPort(b *testing.B) {
	token := "68.45.152.220:1234"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseIPToken(token)
	}
}

func BenchmarkIsAllowed_DualStack(b *testing.B) {
	xffmw, _ := New(Options{
		AllowedSubnets: []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"2001:db8::/32", "2606:4700::/32", "2400:cb00::/32",
		},
	})
	addr, _ := parseIPToken("192.168.1.1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = xffmw.isAllowed(addr)
	}
}

func BenchmarkAllowedAddrFunc(b *testing.B) {
	trusted := netip.MustParseAddr("10.0.0.1")
	xffmw, _ := New(Options{
		AllowedAddrFunc: func(addr netip.Addr) bool {
			return addr == trusted
		},
	})
	addr, _ := parseIPToken("10.0.0.1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = xffmw.isAllowed(addr)
	}
}


