# httpsuite

**Unified HTTP Security Testing Tool**

httpsuite combines the best ideas from multiple open-source HTTP security tools into a single, zero-dependency Go binary:

| Module | Inspired By | Description |
|---------|-------------|-------------|
| `bypass` | [nomore403](https://github.com/devploit/nomore403) | 403/401 bypass via verb tampering, header injection, path manipulation, double encoding, case switching |
| `crlf` | [crlfuzz](https://github.com/dwisiswant0/crlfuzz) | CRLF injection scanning with multiple escape sequence payloads |
| `cors` | [corser](https://github.com/cyinnove/corser) | CORS misconfiguration detection (origin reflection, wildcard, null origin, prefix/suffix bypass) |
| `methods` | [httpc](https://github.com/Aether-0/httpc) | HTTP method enumeration across 17+ methods with status code filtering |
| `smuggle` | [smugglefuzz](https://github.com/Moopinger/smugglefuzz) | HTTP request smuggling via HTTP/2 downgrade with 80+ built-in gadgets |

## Installation

```bash
go build -o httpsuite .
```

## Usage

```
httpsuite <command> [flags]
```

### Commands

```
bypass      Test for 403/401 bypass techniques
crlf        Test for CRLF injection vulnerabilities
cors        Test for CORS misconfiguration
methods     Test allowed HTTP methods on targets
smuggle     Test for HTTP request smuggling via H2 downgrade
all         Run all modules against target(s)
```

### Global Flags

```
-u  string    Target URL
-l  string    File containing list of URLs (one per line)
-c  int       Concurrency level (default: 10)
-t  int       Timeout in seconds (default: 10)
-x  string    Proxy URL (e.g., http://127.0.0.1:8080)
-H  string    Custom header (Key: Value) — repeatable
-o  string    Output file path
-j            JSON output mode
-s            Silent mode
-v            Verbose mode
--no-color    Disable colored output
--redirect    Follow redirects
--random-agent Use random User-Agent
```

### Examples

```bash
# 403 Bypass scan
httpsuite bypass -u https://example.com/admin
httpsuite bypass -u https://example.com/admin -techniques headers,endpaths

# CRLF Injection scan
httpsuite crlf -u https://example.com
httpsuite crlf -l urls.txt -c 20

# CORS Misconfiguration scan
httpsuite cors -u https://example.com
httpsuite cors -u https://example.com --deep --origin https://attacker.com

# HTTP Method scan
httpsuite methods -u https://example.com
httpsuite methods -u https://example.com --methods GET,POST,PUT,DELETE --status 200,201

# HTTP Smuggling scan
httpsuite smuggle -u https://example.com
httpsuite smuggle -u https://example.com --extended --interval 10

# Run ALL modules
httpsuite all -u https://example.com

# Pipe URLs from stdin
cat urls.txt | httpsuite cors
echo "https://example.com" | httpsuite methods

# JSON output
httpsuite methods -u https://example.com -j -o results.json
```

### Module-Specific Flags

#### bypass
- `--techniques` — Comma-separated techniques: headers, endpaths, midpaths, verbs, double-encoding, path-case
- `--bypass-ip` — Custom IP for header-based bypass (default: 127.0.0.1)

#### cors
- `--origin` — Custom origin for testing (default: https://evil.com)
- `--deep` — Enable deep scan with special chars and additional bypass techniques

#### methods
- `--methods` — Custom comma-separated HTTP methods
- `--status` — Filter results by comma-separated status codes

#### smuggle
- `--extended` — Use extended gadget list (more payloads)
- `--wordlist` — Custom gadget/payload file
- `--interval` — Detection timeout in seconds (default: 5)

## Architecture

```
httpsuite/
├── main.go                      # Entry point
├── cmd/
│   └── root.go                  # CLI routing & flag parsing
├── internal/
│   ├── bypass/                  # 403 bypass module
│   │   ├── bypass.go
│   │   └── payloads.go
│   ├── crlf/                    # CRLF injection module
│   │   └── crlf.go
│   ├── cors/                    # CORS misconfiguration module
│   │   └── cors.go
│   ├── methods/                 # HTTP methods module
│   │   └── methods.go
│   └── smuggle/                 # HTTP smuggling module
│       ├── smuggle.go
│       └── gadgets.go
├── pkg/
│   ├── common/                  # Shared types (Config, ScanResult)
│   │   └── types.go
│   ├── httpclient/              # Unified HTTP client with retries
│   │   └── client.go
│   ├── output/                  # Colored output & JSON formatting
│   │   └── output.go
│   └── utils/                   # URL normalization, file reading, etc.
│       └── utils.go
└── payloads/                    # Optional external payload files
```

## Credits

Built by combining techniques from:
- **nomore403** by devploit — 403 bypass techniques
- **crlfuzz** by dwisiswant0 — CRLF injection testing
- **corser** by cyinnove — CORS misconfiguration scanning
- **httpc** by Aether-0 — HTTP method testing
- **smugglefuzz** by Moopinger — HTTP/2 smuggling detection

## License

MIT
