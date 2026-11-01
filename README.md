# Go X-Forwarded-For Handler

`xff` is a high-performance, security-hardened `net/http` middleware and IP resolver for `X-Forwarded-For` headers in Golang using standard library `net/netip`.

## Security Architecture & Design

### Right-to-Left Proxy Chain Traversal (Anti-Spoofing)
In standard HTTP proxy architectures, downstream reverse proxies append client IP addresses to the **right** of the `X-Forwarded-For` chain. Evaluating from left to right allows untrusted clients to inject arbitrary public IPs.

`xff` evaluates proxy chains **backwards (right to left)**:
1. Inspects the immediate connecting peer (`r.RemoteAddr`).
2. Verifies whether the peer belongs to `AllowedSubnets` (or trusted loopback). If untrusted, the `X-Forwarded-For` header is safely ignored.
3. If trusted, traverses `X-Forwarded-For` entries from right to left across all trusted proxy hops.
4. The first untrusted IP address encountered is resolved as the authentic client IP. Any entries further to the left are untrusted client input and discarded.

### Strict Error Enforcement (No Insecure Fallbacks)
- If `MaxHops` is exceeded while still traversing trusted proxies, `xff` returns `ErrMaxHopsExceeded` and replies with `http.StatusBadRequest` (or invokes a custom `ErrorHandler`) rather than falling back to an internal proxy IP.
- If a trusted proxy provides a malformed IP address, `xff` returns `ErrInvalidHeader`.

### Secure by Default
- `xff.Default()` only trusts loopback reverse proxies (`127.0.0.0/8`, `::1/128`).
- Direct internet connections cannot spoof client IPs.
- Open proxy trust requires explicit opt-in via `InsecureTrustAll: true`.

### Complete Bogon & Special-Use IP Filtering
`IsPublicAddr` and `IsPublicIP` filter private, loopback, link-local, multicast, and all special-use bogon ranges per RFC 6890, RFC 6598 (CGNAT `100.64.0.0/10`), RFC 1112 (Class E `240.0.0.0/4`), RFC 2544 (Benchmarking), RFC 5737 (Test nets), RFC 791, RFC 919, RFC 4291 (`::/96`), RFC 6666, RFC 2928, RFC 3849, and normalize IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`).

---

## Getting Started

Add `go-x-forwarded-for` to your Go project:

```bash
go get github.com/stfsy/go-x-forwarded-for
```

Create your server:

```go
package main

import (
	"log"
	"net/http"

	xff "github.com/stfsy/go-x-forwarded-for"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from " + r.RemoteAddr + "\n"))
	})

	// Configure trusted upstream proxy CIDRs (e.g. ALB, Cloudflare, VPC proxies)
	xffmw, err := xff.New(xff.Options{
		AllowedSubnets: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		TrustLoopback: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	http.ListenAndServe(":8080", xffmw.Handler(handler))
}
```

### Framework Examples

* `net/http`: [examples/nethttp/server.go](examples/nethttp/server.go)
* [Chi](https://github.com/go-chi/chi): [examples/chi/server.go](examples/chi/server.go)
* [Gin](https://gin-gonic.github.io/gin): [examples/gin/server.go](examples/gin/server.go)
* [Gorilla](https://github.com/gorilla/mux): [examples/gorilla/server.go](examples/gorilla/server.go)
* [Negroni](https://github.com/codegangsta/negroni): [examples/negroni/server.go](examples/negroni/server.go)
* [Alice](https://github.com/justinas/alice): [examples/alice/server.go](examples/alice/server.go)
* [HttpRouter](https://github.com/julienschmidt/httprouter): [examples/httprouter/server.go](examples/httprouter/server.go)

---

## Configuration Options

Pass options to `xff.New`:

```go
xffmw, err := xff.New(xff.Options{
	AllowedSubnets: []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	},
	TrustLoopback: true,
	MaxHops:       30,
	Debug:         false,
})
```

* **`AllowedSubnets`** `[]string`: List of trusted proxy CIDRs (IPv4 and IPv6). Must be valid CIDR notation with subnet mask (e.g. `"10.0.0.0/8"`, `"192.168.1.1/32"`, `"::1/128"`).
* **`TrustLoopback`** `bool`: Automatically trusts `127.0.0.0/8` and `::1/128`. Default is `true` in `xff.Default()`.
* **`AllowedFunc`** `func(sip string) bool`: Optional custom predicate function to dynamically check trusted proxy IPs by string.
* **`AllowedAddrFunc`** `func(addr netip.Addr) bool`: High-performance custom predicate checking trusted proxy IPs directly as `netip.Addr` with zero heap allocations.
* **`InsecureTrustAll`** `bool`: Disables proxy verification. **WARNING**: Enables arbitrary IP spoofing if exposed to untrusted clients.
* **`MaxHops`** `int`: Maximum proxy hops to inspect from right to left (default 30) to guard against resource exhaustion DoS.
* **`ErrorHandler`** `func(w http.ResponseWriter, r *http.Request, err error)`: Optional error handler invoked when proxy validation fails (e.g. `ErrMaxHopsExceeded`). Defaults to returning `http.StatusBadRequest`.
* **`Debug`** `bool`: Enables diagnostic resolution logging.
* **`Logger`** `*log.Logger`: Custom logger instance. If nil and `Debug` is true, logs to `os.Stdout`.

---

## Direct Parsing Helpers & Context Integration

* **`xff.Parse(ipList string) string`**: Returns the rightmost public, routable IP address from an `X-Forwarded-For` header.
* **`xff.ParseAddr(ipList string) (netip.Addr, bool)`**: Allocation-free variant returning a strongly-typed `netip.Addr`.
* **`xff.IsPublicAddr(addr netip.Addr) bool`**: Returns true if the IP address is a globally routable public address.
* **`xff.IsPublicIP(ip net.IP) bool`**: Standard library `net.IP` wrapper for `IsPublicAddr`.
* **`xff.GetRemoteAddr(r *http.Request) (string, error)`**: Resolves remote address using safe defaults (trusting loopback proxies).
* **`xff.ClientAddrFromContext(ctx context.Context) (netip.Addr, bool)`**: Retrieves the resolved client `netip.Addr` directly from the request context with zero string parsing or heap allocations.

---

## Benchmarks

```
goos: windows
goarch: amd64
pkg: github.com/stfsy/go-x-forwarded-for
BenchmarkParseSingle-16                	11992588	       111.4 ns/op	      16 B/op	       1 allocs/op
BenchmarkParseAddrSingle-16            	17749167	        69.28 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseMulti-16                 	11317818	       104.2 ns/op	      16 B/op	       1 allocs/op
BenchmarkGetRemoteAddrNoHeader-16      	22042371	        49.18 ns/op	       0 B/op	       0 allocs/op
BenchmarkGetRemoteAddrWithHeader-16    	 6941937	       180.5 ns/op	      24 B/op	       1 allocs/op
BenchmarkHandlerDefault-16             	 2902144	       420.1 ns/op	     416 B/op	       4 allocs/op
BenchmarkHandlerAllowedSubnets-16      	 3040252	       398.4 ns/op	     416 B/op	       4 allocs/op
BenchmarkHandlerMultiHop-16            	 2377977	       459.0 ns/op	     416 B/op	       4 allocs/op
BenchmarkIsPublicAddr_IPv4-16          	61441729	        21.01 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsPublicAddr_IPv6-16          	33503362	        35.33 ns/op	       0 B/op	       0 allocs/op
BenchmarkFormatAddrPort-16             	29794491	        36.58 ns/op	      24 B/op	       1 allocs/op
BenchmarkParseTokenWithPort-16         	24154977	        52.29 ns/op	       0 B/op	       0 allocs/op
BenchmarkIsAllowed_DualStack-16        	60139824	        19.31 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllowedAddrFunc-16            	282242301	         4.11 ns/op	       0 B/op	       0 allocs/op
PASS
```

## License

All source code is licensed under the [MIT License](LICENSE).
