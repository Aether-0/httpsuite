<p align="center">
  <img src="logo.png" alt="httpsuite logo" width="400">
</p>

<h1 align="center">httpsuite</h1>

<p align="center">
  <b>Unified HTTP Security Testing Tool</b><br>
  <i>Bypass • CRLF • CORS • Methods • Smuggle — all in a single binary.</i>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#modules">Modules</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#credits">Credits</a>
</p>

---

**httpsuite** combines the best ideas from multiple open-source HTTP security tools into a single Go binary. Instead of juggling separate tools with different flags, payload files, and output formats, run one tool with a shared workflow, shared client, synced payload support, and smarter triage.

### Why It Is Useful

- Smart bypass filtering suppresses fake `200` or `3xx` responses that still look like blocked templates
- `sync-payloads` refreshes current payloads from upstream projects into `payloads/`
- JSON output now carries richer bypass evidence such as `reason`, `title`, and `fingerprint`
- A shared HTTP client provides retries, proxy support, custom headers, and TLS handling across modules

| Module | Inspired By | What It Does |
|--------|-------------|--------------|
| `bypass` | [nomore403](https://github.com/devploit/nomore403) | 403/401 bypass via verb tampering, verb case switching, header injection, path manipulation, double encoding, HTTP version probing, and block-page fingerprinting |
| `crlf` | [crlfuzz](https://github.com/dwisiswant0/crlfuzz) | CRLF injection scanning with multiple encoded escape payloads and reflected canary-header detection |
| `cors` | [CORStest](https://github.com/RUB-NDS/CORStest) / [corser](https://github.com/cyinnove/corser) | CORS misconfiguration detection for reflection, null, wildcard, prefix/suffix, subdomain, non-SSL, and alternate-port cases |
| `methods` | [httpc](https://github.com/Aether-0/httpc) | HTTP method enumeration across 30+ methods with filtering and optional synced method payloads |
| `smuggle` | [smugglefuzz](https://github.com/Moopinger/smugglefuzz) | HTTP request smuggling via HTTP/2 downgrade with refreshed gadget parsing and synced default/extended gadget lists |

---

## Installation

### From Source

```bash
git clone https://github.com/Aether-0/httpsuite.git
cd httpsuite
go build -o httpsuite .
```

### Go Install

```bash
go install github.com/aether-0/httpsuite@latest
```

### Move to PATH (optional)

```bash
sudo mv httpsuite /usr/local/bin/
```

### Refresh Payload Files (optional)

```bash
httpsuite sync-payloads
```

---

## Modules

### Bypass

Tests a wide range of 403/401 bypass techniques against restricted endpoints:

- Header injection with IP, host, URL, origin, and proxy-style headers
- End-path and mid-path payload insertion
- Verb tampering and verb case switching
- Double URL encoding of path segments
- Path case switching
- Raw HTTP version probing with `HTTP/1.0` and `HTTP/1.1`
- Smart suppression of fake success responses that still look like blocked pages

### CRLF

Tests for CRLF injection by generating encoded path payloads and looking for a reflected canary header:

- Multiple encoded escape variants such as `%0d%0a`, `%23%0d%0a`, `%u000d`, `%e5%98%8a%e5%98%8d`, and more
- Reflected header detection using `X-Injected-Header-By: httpsuite`
- Works against single targets, files, or piped input

### CORS

Detects several classes of CORS misconfiguration:

- Origin reflection
- Null-origin acceptance
- Wildcard ACAO, including credential-related misconfigurations
- Developer-backdoor origins
- Prefix and suffix domain tricks
- Subdomain trust issues
- Non-SSL and alternate-port origin handling
- Preflight inspection with `OPTIONS`

### Methods

Enumerates allowed or interesting HTTP methods on target endpoints:

- Built-in list of 30+ methods
- Custom method lists with `--methods`
- Status filtering with `--status`
- Optional synced method payloads from `payloads/bypass/httpmethods`

### Smuggle

Tests for HTTP request smuggling via HTTP/2 downgrade:

- Raw HTTP/2 TLS connection setup with ALPN
- Default and extended gadget banks
- Support for custom gadget files with `--wordlist`
- Synced gadget files from `payloads/smuggle/`
- Configurable detection timeout with `--interval`

---

## Usage

```text
httpsuite <command> [flags]
```

### Commands

| Command | Description |
|---------|-------------|
| `bypass` | Test for 403/401 bypass techniques |
| `crlf` | Test for CRLF injection vulnerabilities |
| `cors` | Test for CORS misconfiguration |
| `methods` | Test allowed HTTP methods on targets |
| `smuggle` | Test for HTTP request smuggling via HTTP/2 downgrade |
| `all` | Run all modules against target(s) |
| `sync-payloads` | Download current upstream payload files into a local payload directory |
| `version` | Show version information |
| `help` | Show help message |

### Global Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-u` | string | | Target URL |
| `-l` | string | | File containing list of URLs |
| `-c` | int | `10` | Concurrency level |
| `-t` | int | `10` | Timeout in seconds |
| `-x` | string | | Proxy URL |
| `-H` | string | | Custom header (`Key: Value`) — repeatable |
| `-o` | string | | Output file path |
| `-j` | bool | `false` | JSON output mode |
| `-s` | bool | `false` | Silent mode |
| `-v` | bool | `false` | Verbose mode |
| `-ua` | string | `httpsuite/1.0` | Custom User-Agent string |
| `--payload-dir` | string | `payloads` | Local payload override directory |
| `--no-color` | bool | `false` | Disable colored output |
| `--redirect` | bool | `false` | Follow redirects |
| `--random-agent` | bool | `false` | Use a random User-Agent |

### Module-Specific Flags

#### `bypass`

| Flag | Default | Description |
|------|---------|-------------|
| `--techniques` | `headers,endpaths,midpaths,verbs,verbs-case,double-encoding,http-versions,path-case` | Comma-separated bypass techniques |
| `--bypass-ip` | *(none)* | Custom IP for header-based bypass generation |

Notes:
- Verbose mode explains why blocked-template responses were suppressed.
- JSON output includes `reason`, `title`, and `fingerprint` fields for bypass findings.

#### `cors`

| Flag | Default | Description |
|------|---------|-------------|
| `--origin` | `https://evil.com` | Custom attacker origin |
| `--deep` | `false` | Enable deeper origin mutation coverage |

#### `methods`

| Flag | Default | Description |
|------|---------|-------------|
| `--methods` | *(all built-in)* | Custom comma-separated HTTP methods |
| `--status` | *(all)* | Filter results by status codes |

#### `smuggle`

| Flag | Default | Description |
|------|---------|-------------|
| `--extended` | `false` | Use the extended gadget list |
| `--wordlist` | | Custom gadget file |
| `--interval` | `5` | Detection timeout in seconds |

Notes:
- The smuggling module targets `https://` endpoints that negotiate HTTP/2 over TLS.

#### `sync-payloads`

| Flag | Default | Description |
|------|---------|-------------|
| `--payload-dir` | `payloads` | Destination payload directory |
| `-t` | `20` | Sync timeout in seconds |
| `-s` | `false` | Silent mode |
| `--no-color` | `false` | Disable colored output |

---

## Examples

### Bypass

```bash
# Basic 403/401 bypass scan
httpsuite bypass -u https://example.com/admin

# Focus on specific techniques
httpsuite bypass -u https://example.com/admin --techniques headers,endpaths,http-versions

# Show suppression reasons and richer bypass triage
httpsuite bypass -u https://example.com/admin -v -j

# Use a custom bypass IP
httpsuite bypass -u https://example.com/admin --bypass-ip 10.0.0.1
```

### CRLF

```bash
# Basic CRLF scan
httpsuite crlf -u https://example.com

# Scan a URL list with higher concurrency
httpsuite crlf -l urls.txt -c 50

# Through a proxy
httpsuite crlf -u https://example.com -x http://127.0.0.1:8080
```

### CORS

```bash
# Basic CORS scan
httpsuite cors -u https://example.com

# Deep scan with custom origin
httpsuite cors -u https://example.com --deep --origin https://attacker.com

# Multiple targets
httpsuite cors -l urls.txt -c 20
```

### Methods

```bash
# Enumerate all built-in methods
httpsuite methods -u https://example.com

# Test specific methods and filter by status
httpsuite methods -u https://example.com --methods GET,POST,PUT,DELETE --status 200,201,405

# JSON output
httpsuite methods -u https://example.com -j -o results.json
```

### Smuggle

```bash
# Basic smuggling scan
httpsuite smuggle -u https://example.com

# Extended gadget list with longer detection timeout
httpsuite smuggle -u https://example.com --extended --interval 10

# Custom gadget file
httpsuite smuggle -u https://example.com --wordlist gadgets.txt
```

### Payload Sync

```bash
# Sync payloads into the default directory
httpsuite sync-payloads

# Sync into a custom payload directory
httpsuite sync-payloads --payload-dir payloads-custom
```

### Run All Modules

```bash
# Full scan
httpsuite all -u https://example.com

# Full scan with verbose output and higher concurrency
httpsuite all -u https://example.com -v -c 20
```

### Piping and Output

```bash
# Pipe targets from stdin
cat urls.txt | httpsuite cors
echo "https://example.com" | httpsuite methods

# Plain text output
httpsuite all -u https://example.com -o scan.log

# JSON output
httpsuite bypass -u https://example.com/admin -j -o bypass.json
```

---

## Architecture

```text
httpsuite/
├── main.go                      # Entry point
├── cmd/
│   └── root.go                  # CLI routing & flag parsing
├── internal/
│   ├── bypass/
│   │   ├── bypass.go            # Scanner logic, triage, raw HTTP version checks
│   │   └── payloads.go          # Embedded payloads + synced payload loaders
│   ├── crlf/
│   │   └── crlf.go              # Encoded CRLF payload generation and reflection checks
│   ├── cors/
│   │   └── cors.go              # Origin generation, preflight, response analysis
│   ├── methods/
│   │   └── methods.go           # Method enumeration logic
│   └── smuggle/
│       ├── smuggle.go           # HTTP/2 downgrade testing
│       └── gadgets.go           # Embedded gadget banks
├── pkg/
│   ├── common/
│   │   └── types.go             # Shared config and result types
│   ├── httpclient/
│   │   ├── client.go            # Shared HTTP client
│   │   └── summary.go           # Response fingerprinting and HTML normalization
│   ├── output/
│   │   └── output.go            # Banner, terminal, JSON, and file output
│   ├── payloadsync/
│   │   └── payloadsync.go       # Upstream payload downloader/extractor
│   └── utils/
│       └── utils.go             # URL helpers, case variants, file helpers
└── payloads/
    ├── bypass/                  # Synced bypass payload files
    └── smuggle/                 # Synced smuggle gadget files
```

---

## How It Works

1. **Input**: accepts a single URL, a list file, or piped stdin
2. **Dispatch**: routes to a specific module or runs all modules in sequence
3. **Shared Client**: applies timeout, retries, proxy, headers, and TLS settings consistently
4. **Concurrent Workers**: each module runs with a worker pool controlled by `-c`
5. **Triage**: bypass responses are fingerprinted and compared against blocked baselines
6. **Output**: results stream to stdout and optionally to text or JSON output files

---

## Credits

httpsuite is built by combining techniques and ideas from these projects:

| Tool | Author | Contribution |
|------|--------|-------------|
| [nomore403](https://github.com/devploit/nomore403) | devploit | Header and path-based bypass techniques |
| [crlfuzz](https://github.com/dwisiswant0/crlfuzz) | dwisiswant0 | CRLF escape sequence inspiration |
| [CORStest](https://github.com/RUB-NDS/CORStest) | RUB-NDS | CORS payload classes and evaluation patterns |
| [corser](https://github.com/cyinnove/corser) | cyinnove | Lightweight CORS testing workflow |
| [httpc](https://github.com/Aether-0/httpc) | Aether-0 | HTTP method testing ideas |
| [smugglefuzz](https://github.com/Moopinger/smugglefuzz) | Moopinger | HTTP/2 smuggling gadget ideas and payload format |

---

## Disclaimer

This tool is intended for **authorized security testing and educational use only**. Always obtain proper authorization before testing systems you do not own or manage.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
