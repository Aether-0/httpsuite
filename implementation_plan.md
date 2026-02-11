# Implementation Plan

[Overview]
Enhance the existing httpsuite unified HTTP security testing tool to be fully functional by incorporating all missing techniques, payloads, and features from the five reference repositories (nomore403, crlfuzz, corser, httpc, smugglefuzz).

The httpsuite project at `~/Desktop/httpsuite` already has a well-structured codebase with 5 modules (bypass, crlf, cors, methods, smuggle), shared types, an HTTP client, output formatting, and utility functions. However, each module is missing significant techniques, payloads, and edge-case handling compared to the original tools they were inspired by. This plan details every enhancement needed to bring each module to full feature parity with its reference implementation, while maintaining the unified architecture and adding `golang.org/x/net` for proper HTTP/2 support in the smuggle module.

[Types]
Add new fields to Config for delay, rate-limit detection, unique output deduplication, and cookie support. Add a Confirmation field to smuggle results.

### Changes to `pkg/common/types.go` — Config struct additions:
```go
type Config struct {
    // ... existing fields ...
    Delay       int               // Delay between requests in milliseconds (new)
    RateLimit   bool              // Halt on HTTP 429 (new)
    UniqueOutput bool             // Deduplicate results by status+content-length (new)
    Cookies     string            // Cookie header value (new)
}
```

### Changes to `pkg/common/types.go` — ScanResult struct additions:
```go
type ScanResult struct {
    // ... existing fields ...
    Technique   string `json:"technique,omitempty"`   // Which technique produced this result (new)
    Confirmed   bool   `json:"confirmed,omitempty"`   // Whether smuggle was confirmed (new)
}
```

### DefaultConfig updates:
- `Delay: 0`
- `RateLimit: false`
- `UniqueOutput: false`
- `Cookies: ""`

[Files]
Modify 11 existing files and create 0 new files. Add `golang.org/x/net` dependency.

### Files to modify:

1. **`go.mod`** — Add `golang.org/x/net` dependency for HTTP/2 framer in smuggle module
2. **`pkg/common/types.go`** — Add Delay, RateLimit, UniqueOutput, Cookies fields to Config; add Technique, Confirmed fields to ScanResult
3. **`pkg/httpclient/client.go`** — Add rate-limit detection (return special error on 429), add cookie support, add `SimpleRequestWithBody` method for POST requests
4. **`pkg/output/output.go`** — Add unique output deduplication logic, add technique-based deduplication
5. **`pkg/utils/utils.go`** — Add more user agents from nomore403 list (expand from 8 to 20+)
6. **`cmd/root.go`** — Add new CLI flags: `--delay`, `--rate-limit`, `--unique`, `--cookies`; add `verbs-case` and `http-versions` to bypass techniques; pass new config fields
7. **`internal/bypass/bypass.go`** — Add `verbsCaseSwitching()` technique, add `httpVersions()` technique, add delay support, add rate-limit handling, add unique result deduplication, expand header bypass to use full IP list and simpleheaders
8. **`internal/bypass/payloads.go`** — Massively expand: add all 55 headers from nomore403, add full 25-entry IP list, add all endpath payloads (~70 entries from nomore403), add all midpath payloads (~200+ entries from nomore403), add simpleheaders list, add full HTTP methods list including POUET/TRACK/LABEL
9. **`internal/crlf/crlf.go`** — Add ~15 missing escape sequences from crlfuzz (`\r`, `\r\n`, `%u0000`, `%25%30`, `%3f%0a`, `%3f%0d`, `%23%0a%20`, `%23%oa`, `%3f`, etc.)
10. **`internal/cors/cors.go`** — Add PortManipulation, SubdomainFlipping, JoinTwice payload generators; expand SpecialChars list to match corser (`_`, `-`, `{`, `}`, `^`, `` %60 ``, `!`, `~`, `` ` ``, `;`, `|`, `&`, `(`, `)`, `*`, `'`, `"`, `$`, `=`, `+`, `%0b`); add cookie support; add `user@domain` bypass with `%40` and `%23@`
11. **`internal/smuggle/smuggle.go`** — Rewrite to use `golang.org/x/net/http2` framer and hpack encoder; add WINDOW_UPDATE frame; add confirmation request flow (send `3\r\nABC\r\n0\r\n\r\n` after timeout); add keyword detection; add `[HOSTNAME]` replacement in gadgets; add proper GOAWAY reconnection; add custom data frame support
12. **`internal/smuggle/gadgets.go`** — Replace with complete gadget lists from smugglefuzz (DefaultGadgetList and ExtendedGadgetList), which include many more payloads than current
13. **`internal/methods/methods.go`** — Add POUET, TRACK, LABEL methods; add delay support; improve vulnerability detection heuristics

[Functions]
Add new functions for missing techniques and enhance existing ones with full feature parity.

### New functions to add:

**`internal/bypass/bypass.go`:**
- `func (s *Scanner) verbsCaseSwitching()` — Generates case combinations of HTTP methods that produced unique responses in verb tampering, tests up to 50 random combinations per method (from nomore403 `requestMethodsCaseSwitching`)
- `func (s *Scanner) httpVersions()` — Tests HTTP/1.0 via raw connection to detect version-specific bypasses (from nomore403 `requestHttpVersions`)
- `func (s *Scanner) simpleHeaderBypass()` — Tests simple header payloads like `X-Original-URL /admin`, `X-HTTP-Method-Override POST` (from nomore403 simpleheaders file)

**`internal/bypass/payloads.go`:**
- `var IPList []string` — Full list of 25 bypass IPs from nomore403 (127.0.0.1, 0.0.0.0, 10.0.0.0, localhost, etc.)
- `var SimpleHeaders []SimpleHeaderPayload` — Struct with Key+Value for simple headers
- Expand `BypassHeaders` to include all 55 headers from nomore403 headers file
- Expand `EndPathPayloads` to include all ~70 entries from nomore403 endpaths file
- Expand `MidPathPayloads` to include all ~200+ entries from nomore403 midpaths file
- Expand `HTTPMethods` to include POUET, TRACK, LABEL

**`internal/cors/cors.go`:**
- `func (s *Scanner) generatePortManipulation(host *parsedHost) []string` — Generates origin payloads with different ports (8080, 443, 80) (from corser `PortManipulation`)
- `func (s *Scanner) generateSubdomainFlipping(host *parsedHost) []string` — Flips subdomain positions (from corser `SubdomainFlipping`)
- `func (s *Scanner) generateJoinTwice(host *parsedHost) []string` — Joins evil domain with target domain (from corser `JoinTwoice`)
- `type parsedHost struct` — Struct with Full, Domain, TLD, Subdomain fields (from corser `Host`)
- `func parseHost(rawURL string) (*parsedHost, error)` — Parses URL into host components (from corser `NetParser`)

**`internal/smuggle/smuggle.go`:**
- `func (s *Scanner) testPayloadWithFramer(host, port, path, query string, payload Payload) string` — New implementation using `golang.org/x/net/http2` framer for proper frame construction
- `func (s *Scanner) sendConfirmation(host, port, path, query string, payload Payload) string` — Sends confirmation request with `3\r\nABC\r\n0\r\n\r\n` body after timeout detection (from smugglefuzz confirmation flow)
- `func generateWindowUpdateFrame(streamID uint32) []byte` — Generates WINDOW_UPDATE frame (from smugglefuzz)
- `func generateSettingsFrame() []byte` — Generates proper SETTINGS frame with ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1000, INITIAL_WINDOW_SIZE=6291456 (from smugglefuzz)

**`pkg/httpclient/client.go`:**
- `func (c *Client) SimpleRequestWithBody(method, targetURL string, body []byte, extraHeaders map[string]string) (int, []byte, http.Header, error)` — For requests that need a body (POST)
- `func (c *Client) RawRequest(method, targetURL string, extraHeaders map[string]string) (int, []byte, http.Header, error)` — Returns response headers too for CRLF/CORS checking

**`pkg/output/output.go`:**
- `func (p *Printer) IsUnique(statusCode int, contentLength int) bool` — Deduplication check
- `func (p *Printer) IsUniqueByTechnique(technique string, contentLength int, line string) bool` — Per-technique deduplication

### Modified functions:

**`cmd/root.go`:**
- `parseGlobalFlags()` — Add parsing for `--delay`, `--rate-limit`, `--unique`, `--cookies` flags; pass to Config
- `runBypass()` — Pass `verbs-case` and `http-versions` as valid techniques
- `runAll()` — Use new techniques in bypass module

**`internal/bypass/bypass.go`:**
- `Run()` — Add cases for `verbs-case`, `http-versions`, `simpleheaders` techniques; add delay between requests
- `headerBypass()` — Use expanded IP list, iterate all IPs × all headers (like nomore403); add delay
- `verbTampering()` — Store results for case-switching; add delay; add rate-limit check
- `endPathBypass()` — Use expanded payload list; add delay
- `midPathBypass()` — Use expanded payload list; add delay

**`internal/crlf/crlf.go`:**
- `escapeList` variable — Expand with 15+ missing sequences from crlfuzz
- `appendList` variable — Add `%3f` entry from crlfuzz

**`internal/cors/cors.go`:**
- `generatePayloads()` — Integrate PortManipulation, SubdomainFlipping, JoinTwice; expand SpecialChars; add user@domain bypass
- `testOrigin()` — Add cookie header support
- `preflightCheck()` — Add cookie header support

**`internal/smuggle/smuggle.go`:**
- `testPayload()` — Rewrite to use proper HTTP/2 framer, add WINDOW_UPDATE, add confirmation flow
- `loadPayloads()` — Add `[HOSTNAME]` replacement in gadget values
- `Run()` — Add confirmation mode, keyword detection

**`internal/smuggle/gadgets.go`:**
- `DefaultGadgetList` — Replace with complete list from smugglefuzz (includes ~20 more gadgets)
- `ExtendedGadgetList` — Replace with complete list from smugglefuzz (includes ~100+ more gadgets with all byte-value variations)

**`internal/methods/methods.go`:**
- `defaultMethods` — Add POUET, TRACK, LABEL
- `Run()` — Add delay support

[Classes]
No new classes/structs beyond those listed in Types and Functions sections. Go uses structs, not classes.

### Modified structs:
- `common.Config` — Add 4 new fields (Delay, RateLimit, UniqueOutput, Cookies)
- `common.ScanResult` — Add 2 new fields (Technique, Confirmed)
- `bypass.Scanner` — Add `verbResults map[string]int` field to track verb tampering results for case-switching
- `cors.Scanner` — No struct changes, but add `parsedHost` helper struct
- `smuggle.Scanner` — Add `confirm bool`, `keyword string`, `dataFrame string` fields

### New structs:
- `bypass.SimpleHeaderPayload` — `struct { Key string; Value string }` for simpleheaders
- `cors.parsedHost` — `struct { Full, Domain, TLD, Subdomain string }` for URL parsing

[Dependencies]
Add `golang.org/x/net` for proper HTTP/2 framing in the smuggle module.

### New dependencies:
- `golang.org/x/net` — Required for `golang.org/x/net/http2` (framer) and `golang.org/x/net/http2/hpack` (header compression). Used in `internal/smuggle/smuggle.go` for proper HTTP/2 frame construction, HPACK encoding, and frame reading. This replaces the current manual binary frame construction with the standard library's robust implementation.

### Installation:
```bash
cd ~/Desktop/httpsuite
go get golang.org/x/net
```

### No other external dependencies needed:
- All other modules use only Go standard library (`net/http`, `crypto/tls`, `net`, `net/url`, `sync`, `fmt`, `strings`, `io`, `os`, `bufio`, `encoding/binary`, `encoding/json`, `flag`, `time`, `math/rand`, `strconv`, `unicode`)

[Testing]
Manual testing approach — verify each module compiles and runs against test targets.

### Build verification:
```bash
cd ~/Desktop/httpsuite
go build -o httpsuite .
```

### Functional tests per module:
1. **bypass**: `./httpsuite bypass -u https://httpbin.org/status/403 -v`
2. **crlf**: `./httpsuite crlf -u https://httpbin.org -v`
3. **cors**: `./httpsuite cors -u https://httpbin.org --deep -v`
4. **methods**: `./httpsuite methods -u https://httpbin.org -v`
5. **smuggle**: `./httpsuite smuggle -u https://httpbin.org -v`
6. **all**: `./httpsuite all -u https://httpbin.org -v`
7. **stdin pipe**: `echo "https://httpbin.org" | ./httpsuite methods`
8. **JSON output**: `./httpsuite methods -u https://httpbin.org -j`
9. **File output**: `./httpsuite methods -u https://httpbin.org -o results.txt`

### Verify new features:
- `./httpsuite bypass -u https://httpbin.org/status/403 --techniques verbs-case,http-versions -v`
- `./httpsuite cors -u https://httpbin.org --deep --origin https://evil.com -v`
- `./httpsuite smuggle -u https://example.com --extended --interval 10 -v`

[Implementation Order]
Implement changes bottom-up: shared types/utils first, then each module, then CLI, then build and test.

1. **Update `go.mod`** — Add `golang.org/x/net` dependency via `go get`
2. **Update `pkg/common/types.go`** — Add new Config and ScanResult fields
3. **Update `pkg/utils/utils.go`** — Expand user agent list
4. **Update `pkg/httpclient/client.go`** — Add RawRequest, SimpleRequestWithBody, rate-limit detection, cookie support
5. **Update `pkg/output/output.go`** — Add unique deduplication methods
6. **Update `internal/bypass/payloads.go`** — Massively expand all payload lists (headers, IPs, endpaths, midpaths, methods, simpleheaders)
7. **Update `internal/bypass/bypass.go`** — Add verbsCaseSwitching, httpVersions, simpleHeaderBypass techniques; add delay; integrate expanded payloads
8. **Update `internal/crlf/crlf.go`** — Add all missing escape sequences and append entries
9. **Update `internal/cors/cors.go`** — Add parsedHost, PortManipulation, SubdomainFlipping, JoinTwice, expanded SpecialChars, cookie support
10. **Update `internal/methods/methods.go`** — Add missing methods, delay support
11. **Update `internal/smuggle/gadgets.go`** — Replace with complete gadget lists from smugglefuzz
12. **Update `internal/smuggle/smuggle.go`** — Rewrite with golang.org/x/net/http2 framer, add WINDOW_UPDATE, confirmation flow, keyword detection, GOAWAY reconnection, [HOSTNAME] replacement
13. **Update `cmd/root.go`** — Add new CLI flags, wire up new techniques and config fields
14. **Build and test** — `go build -o httpsuite .` and run verification commands
