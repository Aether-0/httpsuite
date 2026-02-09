package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/aether-0/httpsuite/pkg/common"
)

// ANSI color codes
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
)

// Printer handles all output formatting
type Printer struct {
	mu       sync.Mutex
	silent   bool
	noColor  bool
	jsonMode bool
	outFile  *os.File
	results  []common.ScanResult
}

// NewPrinter creates a new Printer instance
func NewPrinter(silent, noColor, jsonMode bool, outputFile string) *Printer {
	p := &Printer{
		silent:   silent,
		noColor:  noColor,
		jsonMode: jsonMode,
		results:  make([]common.ScanResult, 0),
	}
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		} else {
			p.outFile = f
		}
	}
	return p
}

// Close cleans up resources
func (p *Printer) Close() {
	if p.outFile != nil {
		if p.jsonMode {
			data, _ := json.MarshalIndent(p.results, "", "  ")
			p.outFile.Write(data)
		}
		p.outFile.Close()
	}
}

// colorForStatus returns the color code for a given HTTP status code
func (p *Printer) colorForStatus(code int) string {
	if p.noColor {
		return ""
	}
	switch {
	case code >= 200 && code < 300:
		return Green
	case code >= 300 && code < 400:
		return Blue
	case code >= 400 && code < 500:
		return Magenta
	case code >= 500:
		return Yellow
	default:
		return White
	}
}

func (p *Printer) reset() string {
	if p.noColor {
		return ""
	}
	return Reset
}

func (p *Printer) cyan() string {
	if p.noColor {
		return ""
	}
	return Cyan
}

func (p *Printer) red() string {
	if p.noColor {
		return ""
	}
	return Red
}

func (p *Printer) green() string {
	if p.noColor {
		return ""
	}
	return Green
}

func (p *Printer) bold() string {
	if p.noColor {
		return ""
	}
	return Bold
}

func (p *Printer) magenta() string {
	if p.noColor {
		return ""
	}
	return Magenta
}

// Banner prints the tool banner
func (p *Printer) Banner() {
	if p.silent {
		return
	}
	fmt.Printf(`%s
   __    __  __
  / /   / /_/ /_____ ___  __(_) /____
 / _ \ / __/ __/ __ \/ ___/ / __/ _ \
/ / / / /_/ /_/ /_/ (__  ) / /_/  __/
\/ /_/\__/\__/ .___/____/_/\__/\___/
            /_/  %sv1.0%s

  %sUnified HTTP Security Testing Tool%s
  %sBypass • CRLF • CORS • Methods • Smuggle%s

%s`, p.cyan(), p.bold(), p.reset(), p.green(), p.reset(), Dim, p.reset(), p.reset())
}

// Info prints an info message
func (p *Printer) Info(format string, args ...interface{}) {
	if p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Printf("%s[INF]%s %s\n", p.cyan(), p.reset(), fmt.Sprintf(format, args...))
}

// Error prints an error message
func (p *Printer) Error(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s[ERR]%s %s\n", p.red(), p.reset(), fmt.Sprintf(format, args...))
}

// Success prints a success message
func (p *Printer) Success(format string, args ...interface{}) {
	if p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Printf("%s[OK]%s %s\n", p.green(), p.reset(), fmt.Sprintf(format, args...))
}

// Warning prints a warning message
func (p *Printer) Warning(format string, args ...interface{}) {
	if p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Printf("%s[WRN]%s %s\n", Yellow, p.reset(), fmt.Sprintf(format, args...))
}

// SectionHeader prints a section header
func (p *Printer) SectionHeader(title string) {
	if p.silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Printf("\n%s━━━━━━━━━━━━━━ %s ━━━━━━━━━━━━━━%s\n", p.magenta(), title, p.reset())
}

// Result prints a scan result
func (p *Printer) Result(r common.ScanResult) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.results = append(p.results, r)

	if p.jsonMode {
		data, _ := json.Marshal(r)
		fmt.Println(string(data))
	} else {
		color := p.colorForStatus(r.StatusCode)
		vuln := ""
		if r.Vulnerable {
			vuln = fmt.Sprintf(" %s[VULNERABLE]%s", p.green(), p.reset())
		}
		module := fmt.Sprintf("%s[%s]%s", Dim, r.Module, p.reset())
		detail := ""
		if r.Detail != "" {
			detail = fmt.Sprintf(" (%s)", r.Detail)
		}
		method := ""
		if r.Method != "" {
			method = fmt.Sprintf(" %s", r.Method)
		}
		fmt.Printf("%s%d%s%s %s %d bytes%s%s %s\n",
			color, r.StatusCode, p.reset(),
			method,
			r.URL,
			r.ContentLength,
			detail,
			vuln,
			module,
		)
	}

	// Write to file if configured (non-JSON mode writes line by line)
	if p.outFile != nil && !p.jsonMode {
		line := fmt.Sprintf("%d %s %s %d bytes", r.StatusCode, r.Method, r.URL, r.ContentLength)
		if r.Detail != "" {
			line += " (" + r.Detail + ")"
		}
		if r.Vulnerable {
			line += " [VULNERABLE]"
		}
		line += " [" + r.Module + "]"
		fmt.Fprintln(p.outFile, line)
	}
}

// GetResults returns all collected results
func (p *Printer) GetResults() []common.ScanResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]common.ScanResult{}, p.results...)
}
