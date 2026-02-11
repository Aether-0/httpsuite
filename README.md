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

**httpsuite** combines the best ideas from multiple open-source HTTP security tools into a single, zero-dependency Go binary. Instead of juggling five different tools with different flags, output formats, and quirks — run one tool that does it all.

| Module | Inspired By | What It Does |
|--------|-------------|--------------|
| `bypass` | [nomore403](https://github.com/devploit/nomore403) | 403/401 bypass via verb tampering, header injection, path manipulation, double encoding, case switching |
| `crlf` | [crlfuzz](https://github.com/dwisiswant0/crlfuzz) | CRLF injection scanning with multiple escape sequence payloads |
| `cors` | [corser](https://github.com/cyinnove/corser) | CORS misconfiguration detection (origin reflection, wildcard, null origin, prefix/suffix bypass) |
| `methods` | [httpc](https://github.com/Aether-0/httpc) | HTTP method enumeration across 17+ methods with status code filtering |
| `smuggle` | [smugglefuzz](https://github.com/Moopinger/smugglefuzz) | HTTP request smuggling via HTTP/2 downgrade with 80+ built-in gadgets |

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

---

## Modules

### 🔓 Bypass — 403/401 Forbidden Bypass

Tests a wide range of bypass techniques against restricted endpoints:

- **Header Injection** — Injects headers like `X-Forwarded-For`, `X-Original-URL`, `X-Custom-IP-Authorization`, etc. with various IP values
- **End-Path Payloads** — Appends path suffixes like `/%2e/`, `/..;/`, `/.;/`, `/./`, etc.
- **Mid-Path Payloads** — Inserts path traversal sequences in the middle of the URL path
- **Verb Tampering** — Tests alternate HTTP methods (`POST`, `PUT`, `PATCH`, `TRACE`, `OPTIONS`, etc.)
- **Double Encoding** — Double URL-encodes path segments to bypass WAFs
- **Path Case Switching** — Randomizes the case of path characters

### 💉 CRLF — CRLF Injection Scanner

Tests for CRLF injection vulnerabilities by injecting various escape sequences:

- Multiple encoding schemes: `%0d%0a`, `%0D%0A`, `%E5%98%8A%E5%98%8D`, `\r\n`, `%23%0d%0a`, and more
- Injects a canary header (`Injected: httpsuite`) and checks for reflection in the response
- Supports both path-based and parameter-based injection points

### 🌐 CORS — CORS Misconfiguration Detection

Detects various CORS misconfigurations:

- **Origin Reflection** — Server reflects any arbitrary origin
- **Null Origin** — Server accepts `Origin: null`
- **Wildcard with Credentials** — `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`
- **Prefix/Suffix Bypass** — Prepending or appending to the target domain (e.g., `evil-example.com`, `example.com.evil.com`)
- **Special Character Bypass** — Using special characters to confuse origin parsing
- **Subdomain Wildcard** — Server trusts any subdomain
- **Preflight Analysis** — Tests `OPTIONS` request handling

### 📡 Methods — HTTP Method Enumeration

Enumerates allowed HTTP methods on target endpoints:

- Tests 17+ methods: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `TRACE`, `CONNECT`, `PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`, `PURGE`
- Status code filtering to focus on interesting responses
- Custom method list support

### 🚂 Smuggle — HTTP Request Smuggling

Tests for HTTP/2 downgrade request smuggling:

- Establishes raw HTTP/2 connections with `h2c` upgrade
- Sends crafted requests with manipulated `Transfer-Encoding` and `Content-Length` headers
- 80+ built-in gadgets covering header mutations, byte injections, and encoding tricks
- Extended gadget list with additional payload variations
- Configurable detection timeout (interval)

---

## Usage

```
httpsuite <command> [flags]
```

### Commands

| Command | Description |
|---------|-------------|
| `bypass` | Test for 403/401 bypass techniques |
| `crlf` | Test for CRLF injection vulnerabilities |
| `cors` | Test for CORS misconfiguration |
| `methods` | Test allowed HTTP methods on targets |
| `smuggle` | Test for HTTP request smuggling via H2 downgrade |
| `all` | Run all modules against target(s) |
| `version` | Show version information |
| `help` | Show help message |

### Global Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-u` | string | | Target URL |
| `-l` | string | | File containing list of URLs (one per line) |
| `-c` | int | `10` | Concurrency level |
| `-t` | int | `10` | Timeout in seconds |
| `-x` | string | | Proxy URL (e.g., `http://127.0.0.1:8080`) |
| `-H` | string | | Custom header (`Key: Value`) — repeatable |
| `-o` | string | | Output file path |
| `-j` | | | JSON output mode |
| `-s` | | | Silent mode (suppress info messages) |
| `-v` | | | Verbose mode |
| `--no-color` | | | Disable colored output |
| `--redirect` | | | Follow redirects |
| `--random-agent` | | | Use a random User-Agent per request |

### Module-Specific Flags

#### `bypass`

| Flag | Default | Description |
|------|---------|-------------|
| `--techniques` | `headers,endpaths,midpaths,verbs,double-encoding,path-case` | Comma-separated list of bypass techniques |
| `--bypass-ip` | `127.0.0.1` | Custom IP for header-based bypass |

#### `cors`

| Flag | Default | Description |
|------|---------|-------------|
| `--origin` | `https://evil.com` | Custom attacker origin for testing |
| `--deep` | `false` | Enable deep scan with special characters and extra bypass techniques |

#### `methods`

| Flag | Default | Description |
|------|---------|-------------|
| `--methods` | *(all built-in)* | Custom comma-separated HTTP methods |
| `--status` | *(all)* | Filter results by comma-separated status codes |

#### `smuggle`

| Flag | Default | Description |
|------|---------|-------------|
| `--extended` | `false` | Use extended gadget list (more payloads) |
| `--wordlist` | | Custom gadget/payload file |
| `--interval` | `5` | Detection timeout in seconds |

---

## Examples

### 🔓 Bypass

```bash
# Basic 403 bypass scan
httpsuite bypass -u https://example.com/admin

# Use only specific techniques
httpsuite bypass -u https://example.com/admin --techniques headers,endpaths

# With custom bypass IP and verbose output
httpsuite bypass -u https://example.com/admin --bypass-ip 10.0.0.1 -v

# Scan multiple URLs from file
httpsuite bypass -l urls.txt -c 20
```

### 💉 CRLF

```bash
# Basic CRLF scan
httpsuite crlf -u https://example.com

# Scan URL list with high concurrency
httpsuite crlf -l urls.txt -c 50

# Through a proxy
httpsuite crlf -u https://example.com -x http://127.0.0.1:8080
```

### 🌐 CORS

```bash
# Basic CORS scan
httpsuite cors -u https://example.com

# Deep scan with custom origin
httpsuite cors -u https://example.com --deep --origin https://attacker.com

# Scan multiple targets
httpsuite cors -l urls.txt -c 20
```

### 📡 Methods

```bash
# Enumerate all methods
httpsuite methods -u https://example.com

# Test specific methods and filter by status
httpsuite methods -u https://example.com --methods GET,POST,PUT,DELETE --status 200,201,405

# JSON output to file
httpsuite methods -u https://example.com -j -o results.json
```

### 🚂 Smuggle

```bash
# Basic smuggling scan
httpsuite smuggle -u https://example.com

# Extended gadgets with longer timeout
httpsuite smuggle -u https://example.com --extended --interval 10

# Custom wordlist
httpsuite smuggle -u https://example.com --wordlist gadgets.txt
```

### 🔁 Run All Modules

```bash
# Full scan with all modules
httpsuite all -u https://example.com

# Full scan with options
httpsuite all -u https://example.com -v -c 20
```

### 📥 Piping & Stdin

```bash
# Pipe URLs from a file
cat urls.txt | httpsuite cors

# Pipe a single URL
echo "https://example.com" | httpsuite methods

# Chain with other tools
subfinder -d example.com -silent | httpx -silent | httpsuite crlf -c 30
```

### 💾 Output Options

```bash
# Plain text output to file
httpsuite methods -u https://example.com -o results.txt

# JSON output to file
httpsuite cors -u https://example.com -j -o results.json

# Silent mode (only findings, no banners/info)
httpsuite bypass -u https://example.com/admin -s

# No color (for log files or CI/CD)
httpsuite all -u https://example.com --no-color -o scan.log
```

---

## Architecture

```
httpsuite/
├── main.go                      # Entry point
├── cmd/
│   └── root.go                  # CLI routing & flag parsing
├── internal/
│   ├── bypass/                  # 403/401 bypass module
│   │   ├── bypass.go            #   Scanner logic & techniques
│   │   └── payloads.go          #   Headers, paths, methods lists
│   ├── crlf/                    # CRLF injection module
│   │   └── crlf.go              #   Escape sequences & detection
│   ├── cors/                    # CORS misconfiguration module
│   │   └── cors.go              #   Origin generation & analysis
│   ├── methods/                 # HTTP methods module
│   │   └── methods.go           #   Method enumeration logic
│   └── smuggle/                 # HTTP request smuggling module
│       ├── smuggle.go           #   H2 downgrade & detection
│       └── gadgets.go           #   80+ smuggling gadgets
├── pkg/
│   ├── common/                  # Shared types
│   │   └── types.go             #   Config, ScanResult, Target
│   ├── httpclient/              # Unified HTTP client
│   │   └── client.go            #   Retries, proxy, TLS config
│   ├── output/                  # Output formatting
│   │   └── output.go            #   Colors, JSON, file output
│   └── utils/                   # Utility functions
│       └── utils.go             #   URL normalization, stdin, user-agents
└── payloads/                    # Optional external payload files
```

---

## How It Works

1. **Target Input** — Accepts targets via `-u` (single URL), `-l` (file), or `stdin` (piped input)
2. **Module Dispatch** — Routes to the selected module (or all modules with `all`)
3. **Concurrent Scanning** — Each module spawns a worker pool based on `-c` concurrency setting
4. **HTTP Client** — Shared client with configurable timeout, proxy support, TLS settings, and retry logic
5. **Result Collection** — Results are collected thread-safely and can be output as colored terminal text or JSON
6. **Output** — Findings are printed in real-time and optionally saved to a file

---

## Credits

httpsuite is built by combining techniques and ideas from these excellent tools:

| Tool | Author | Contribution |
|------|--------|-------------|
| [nomore403](https://github.com/devploit/nomore403) | devploit | 403 bypass techniques, header/path payloads |
| [crlfuzz](https://github.com/dwisiswant0/crlfuzz) | dwisiswant0 | CRLF injection escape sequences |
| [corser](https://github.com/cyinnove/corser) | cyinnove | CORS misconfiguration detection patterns |
| [httpc](https://github.com/Aether-0/httpc) | Aether-0 | HTTP method enumeration |
| [smugglefuzz](https://github.com/Moopinger/smugglefuzz) | Moopinger | HTTP/2 smuggling gadgets & detection |

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Always obtain proper authorization before testing targets you do not own. The authors are not responsible for any misuse of this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
