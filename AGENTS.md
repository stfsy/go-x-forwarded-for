# Project Guidelines

Security-hardened, high-performance Go HTTP middleware and IP resolver for `X-Forwarded-For` headers using standard library `net/netip`.

## Architecture

- **Core Module (`github.com/stfsy/go-x-forwarded-for`)**:
  - [xff.go](xff.go): Middleware implementation (`XFF`, `Options`), right-to-left reverse traversal IP resolution, zero-allocation token parsers (`parseIPToken`, `trimToken`), bogon/special-use address checkers (`IsPublicAddr`, `isIPv4Bogon`), context helpers, and HTTP handler wrappers (`Handler`, `ServeHTTP`).
  - [xff_test.go](xff_test.go): Unit tests, IP token edge cases, spoofing prevention tests, and hop limit verifications.
  - [bench_test.go](bench_test.go): Benchmarks for parsing latency and memory allocations.

For detailed security architecture and RFC specifications, see [README.md](README.md).

## Build, Test, and Lint

- **Run Tests**:
  - Script: `./test.sh`
  - Command: `go test -v -race -cover -timeout 60s ./...`
- **Run Benchmarks**:
  - `go test -benchmem -run=^$ -bench=. .`
- **Run Linter**:
  - Script (Docker): `./lint.sh`
  - Local CLI: `golangci-lint run -v`

## Conventions & Security Invariants

- **Standard Library Only**: The core library avoids external runtime dependencies and relies solely on the Go standard library (`net/netip`, `net/http`). `testify` is permitted only in tests.
- **Zero/Low Allocation Parsing**: Prefer `netip.Addr` and `netip.Prefix` value types over heap-allocated strings or `net.IP` slices. Avoid intermediate string allocations in hot paths.
- **Right-to-Left Traversal (Anti-Spoofing)**: Always evaluate `X-Forwarded-For` from right to left (downstream trusted proxies to upstream). The first untrusted IP encountered is the client; never trust or evaluate leftmost entries beyond the client.
- **Fail Closed on Errors**: Exceeding `MaxHops` or encountering malformed IPs from trusted proxies must return sentinel errors (`ErrMaxHopsExceeded`, `ErrInvalidHeader`) and reject the request (HTTP 400 Bad Request or custom `ErrorHandler`). Do not fall back to internal proxy IPs.
- **Go Style & Error Handling**: Follow [.github/instructions/go.instructions.md](.github/instructions/go.instructions.md):
  - Separate error declaration and error checking (`result, err := fn() \n if err != nil`).
  - Context propagation: avoid `context.Background()` except in tests; pass request context through.
- **Conventional Commits**: Commit messages must follow Conventional Commits (`feat:`, `fix:`, `chore:`, etc.) to support automated changelog and semver releases via Release Please ([.github/workflows/release.yml](.github/workflows/release.yml)).
