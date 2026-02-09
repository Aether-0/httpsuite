package cmd

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aether-0/httpsuite/internal/bypass"
	"github.com/aether-0/httpsuite/internal/cors"
	"github.com/aether-0/httpsuite/internal/crlf"
	"github.com/aether-0/httpsuite/internal/methods"
	"github.com/aether-0/httpsuite/internal/smuggle"
	"github.com/aether-0/httpsuite/pkg/common"
	"github.com/aether-0/httpsuite/pkg/output"
	"github.com/aether-0/httpsuite/pkg/utils"
)

// Execute parses CLI arguments and runs the appropriate module
func Execute() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "bypass":
		return runBypass(os.Args[2:])
	case "crlf":
		return runCRLF(os.Args[2:])
	case "cors":
		return runCORS(os.Args[2:])
	case "methods":
		return runMethods(os.Args[2:])
	case "smuggle":
		return runSmuggle(os.Args[2:])
	case "all":
		return runAll(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "version", "--version":
		fmt.Println("httpsuite v1.0.0")
		return nil
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", subcommand)
		printUsage()
		return fmt.Errorf("unknown command: %s", subcommand)
	}
}

func printUsage() {
	// ANSI color codes
	cyan := "\033[36m"
	bold := "\033[1m"
	reset := "\033[0m"

	fmt.Print(`
`)
	fmt.Printf("%s%s   __   __  __                _ __        \n", cyan, bold)
	fmt.Printf("  / /  / /_/ /____  ___ __ __(_) /____    \n")
	fmt.Printf(" / _ \\/ __/ __/ _ \\(_-</ // / / __/ -_)   \n")
	fmt.Printf("/_//_/\\__/\\__/ .__/___\\_,_/_/\\__/\\__/    \n")
	fmt.Printf("            /_/ Version 1.0.0%s\n", reset)
	fmt.Printf("%s\n", reset)
	fmt.Print(`  Unified HTTP Security Testing Tool
  Bypass • CRLF • CORS • Methods • Smuggle

Usage:
  httpsuite <command> [flags]

Available Commands:
  bypass      Test for 403/401 bypass techniques (inspired by nomore403)
  crlf        Test for CRLF injection vulnerabilities (inspired by crlfuzz)
  cors        Test for CORS misconfiguration (inspired by corser)
  methods     Test allowed HTTP methods on targets (inspired by httpc)
  smuggle     Test for HTTP request smuggling via H2 downgrade (inspired by smugglefuzz)
  all         Run all modules against target(s)
  help        Show this help message
  version     Show version

Global Flags (available for all commands):
  -u  string    Target URL
  -l  string    File containing list of URLs (one per line)
  -c  int       Concurrency level (default: 10)
  -t  int       Timeout in seconds (default: 10)
  -x  string    Proxy URL (e.g., http://127.0.0.1:8080)
  -H  string    Custom header (Key: Value) — can be repeated
  -o  string    Output file path
  -j            JSON output mode
  -s            Silent mode
  -v            Verbose mode
  --no-color    Disable colored output

Examples:
  httpsuite bypass -u https://example.com/admin
  httpsuite crlf -u https://example.com
  httpsuite cors -l urls.txt -c 20
  httpsuite methods -u https://example.com
  httpsuite smuggle -u https://example.com
  httpsuite all -u https://example.com
  cat urls.txt | httpsuite crlf

`)
}

// multiFlag allows repeating -H flags
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(val string) error {
	*m = append(*m, val)
	return nil
}

// parseGlobalFlags parses global flags shared by all subcommands
func parseGlobalFlags(args []string, name string) (*common.Config, error) {
	cfg := common.DefaultConfig()
	fs := flag.NewFlagSet(name, flag.ContinueOnError)

	var headers multiFlag
	var proxyStr string
	var timeoutSec int
	var listFile string

	fs.StringVar(&cfg.URL, "u", "", "Target URL")
	fs.StringVar(&listFile, "l", "", "File containing list of URLs")
	fs.IntVar(&cfg.Concurrency, "c", 10, "Concurrency level")
	fs.IntVar(&timeoutSec, "t", 10, "Timeout in seconds")
	fs.StringVar(&proxyStr, "x", "", "Proxy URL")
	fs.Var(&headers, "H", "Custom header (Key: Value)")
	fs.StringVar(&cfg.OutputFile, "o", "", "Output file")
	fs.BoolVar(&cfg.JSONOutput, "j", false, "JSON output")
	fs.BoolVar(&cfg.Silent, "s", false, "Silent mode")
	fs.BoolVar(&cfg.Verbose, "v", false, "Verbose mode")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable color")
	fs.BoolVar(&cfg.Redirect, "redirect", false, "Follow redirects")
	fs.StringVar(&cfg.UserAgent, "ua", "httpsuite/1.0", "User-Agent string")
	fs.BoolVar(&cfg.RandomAgent, "random-agent", false, "Use random User-Agent")

	// Module-specific flags (ignored if not relevant)
	var techniques, bypassIP, origin, methodList, filterStatus, gadgetFile string
	var deepScan, extended bool
	var smuggleTimeout int
	fs.StringVar(&techniques, "techniques", "headers,endpaths,midpaths,verbs,double-encoding,path-case", "Bypass techniques")
	fs.StringVar(&bypassIP, "bypass-ip", "", "Custom IP for header-based bypass")
	fs.StringVar(&origin, "origin", "https://evil.com", "Custom origin for CORS testing")
	fs.BoolVar(&deepScan, "deep", false, "Enable deep CORS scan")
	fs.StringVar(&methodList, "methods", "", "Comma-separated HTTP methods")
	fs.StringVar(&filterStatus, "status", "", "Filter by status codes")
	fs.BoolVar(&extended, "extended", false, "Use extended gadget list")
	fs.StringVar(&gadgetFile, "wordlist", "", "Custom gadget/payload file")
	fs.IntVar(&smuggleTimeout, "interval", 5, "Detection timeout in seconds")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.Timeout = time.Duration(timeoutSec) * time.Second

	if proxyStr != "" {
		cfg.ProxyStr = proxyStr
		p, err := url.Parse(proxyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		cfg.Proxy = p
	}

	// Parse custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			cfg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Collect URLs
	if cfg.URL != "" {
		cfg.URLs = append(cfg.URLs, utils.NormalizeURL(cfg.URL))
	}

	if listFile != "" {
		lines, err := utils.ReadLines(listFile)
		if err != nil {
			return nil, fmt.Errorf("error reading URL list: %w", err)
		}
		for _, line := range lines {
			cfg.URLs = append(cfg.URLs, utils.NormalizeURL(line))
		}
	}

	if utils.HasStdin() && len(cfg.URLs) == 0 {
		cfg.URLs = utils.ReadURLsFromStdin()
	}

	if cfg.RandomAgent {
		cfg.UserAgent = utils.RandomUserAgent()
	}

	return cfg, nil
}

// helper to get a string flag value by name from args (silently ignores unknown flags)
func getFlagStr(args []string, name, defaultVal string) string {
	fs := flag.NewFlagSet("temp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	val := fs.String(name, defaultVal, "")
	fs.Parse(args)
	return *val
}

func getFlagBool(args []string, name string) bool {
	fs := flag.NewFlagSet("temp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	val := fs.Bool(name, false, "")
	fs.Parse(args)
	return *val
}

func getFlagInt(args []string, name string, defaultVal int) int {
	fs := flag.NewFlagSet("temp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	val := fs.Int(name, defaultVal, "")
	fs.Parse(args)
	return *val
}

// runBypass handles the bypass subcommand
func runBypass(args []string) error {
	cfg, err := parseGlobalFlags(args, "bypass")
	if err != nil {
		return err
	}

	if len(cfg.URLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide target URL(s) via -u, -l, or stdin")
		return fmt.Errorf("no targets specified")
	}

	printer := output.NewPrinter(cfg.Silent, cfg.NoColor, cfg.JSONOutput, cfg.OutputFile)
	defer printer.Close()
	printer.Banner()

	techniques := getFlagStr(args, "techniques", "headers,endpaths,midpaths,verbs,double-encoding,path-case")
	bypassIP := getFlagStr(args, "bypass-ip", "")
	techs := strings.Split(techniques, ",")

	for _, targetURL := range cfg.URLs {
		scanner := bypass.NewScanner(cfg, printer, targetURL, techs, bypassIP)
		scanner.Run()
	}
	return nil
}

// runCRLF handles the crlf subcommand
func runCRLF(args []string) error {
	cfg, err := parseGlobalFlags(args, "crlf")
	if err != nil {
		return err
	}

	if len(cfg.URLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide target URL(s) via -u, -l, or stdin")
		return fmt.Errorf("no targets specified")
	}

	printer := output.NewPrinter(cfg.Silent, cfg.NoColor, cfg.JSONOutput, cfg.OutputFile)
	defer printer.Close()
	printer.Banner()

	scanner := crlf.NewScanner(cfg, printer)
	scanner.Run()
	return nil
}

// runCORS handles the cors subcommand
func runCORS(args []string) error {
	cfg, err := parseGlobalFlags(args, "cors")
	if err != nil {
		return err
	}

	if len(cfg.URLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide target URL(s) via -u, -l, or stdin")
		return fmt.Errorf("no targets specified")
	}

	printer := output.NewPrinter(cfg.Silent, cfg.NoColor, cfg.JSONOutput, cfg.OutputFile)
	defer printer.Close()
	printer.Banner()

	origin := getFlagStr(args, "origin", "https://evil.com")
	deepScan := getFlagBool(args, "deep")

	scanner := cors.NewScanner(cfg, printer, origin, deepScan)
	scanner.Run()
	return nil
}

// runMethods handles the methods subcommand
func runMethods(args []string) error {
	cfg, err := parseGlobalFlags(args, "methods")
	if err != nil {
		return err
	}

	if len(cfg.URLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide target URL(s) via -u, -l, or stdin")
		return fmt.Errorf("no targets specified")
	}

	printer := output.NewPrinter(cfg.Silent, cfg.NoColor, cfg.JSONOutput, cfg.OutputFile)
	defer printer.Close()
	printer.Banner()

	methodList := getFlagStr(args, "methods", "")
	filterStatus := getFlagStr(args, "status", "")

	scanner := methods.NewScanner(cfg, printer, methodList, filterStatus)
	scanner.Run()
	return nil
}

// runSmuggle handles the smuggle subcommand
func runSmuggle(args []string) error {
	cfg, err := parseGlobalFlags(args, "smuggle")
	if err != nil {
		return err
	}

	if len(cfg.URLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide target URL(s) via -u, -l, or stdin")
		return fmt.Errorf("no targets specified")
	}

	printer := output.NewPrinter(cfg.Silent, cfg.NoColor, cfg.JSONOutput, cfg.OutputFile)
	defer printer.Close()
	printer.Banner()

	ext := getFlagBool(args, "extended")
	gadgetFile := getFlagStr(args, "wordlist", "")
	interval := getFlagInt(args, "interval", 5)

	scanner := smuggle.NewScanner(cfg, printer, ext, gadgetFile, interval)
	scanner.Run()
	return nil
}

// runAll runs all modules against the target(s)
func runAll(args []string) error {
	cfg, err := parseGlobalFlags(args, "all")
	if err != nil {
		return err
	}

	if len(cfg.URLs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: provide target URL(s) via -u, -l, or stdin")
		return fmt.Errorf("no targets specified")
	}

	printer := output.NewPrinter(cfg.Silent, cfg.NoColor, cfg.JSONOutput, cfg.OutputFile)
	defer printer.Close()
	printer.Banner()

	// Run bypass
	printer.SectionHeader("403 BYPASS SCAN")
	for _, targetURL := range cfg.URLs {
		techs := []string{"headers", "endpaths", "midpaths", "verbs", "double-encoding", "path-case"}
		scanner := bypass.NewScanner(cfg, printer, targetURL, techs, "")
		scanner.Run()
	}

	// Run CRLF
	printer.SectionHeader("CRLF INJECTION SCAN")
	crlfScanner := crlf.NewScanner(cfg, printer)
	crlfScanner.Run()

	// Run CORS
	printer.SectionHeader("CORS MISCONFIGURATION SCAN")
	corsScanner := cors.NewScanner(cfg, printer, "https://evil.com", false)
	corsScanner.Run()

	// Run Methods
	printer.SectionHeader("HTTP METHOD SCAN")
	methodsScanner := methods.NewScanner(cfg, printer, "", "")
	methodsScanner.Run()

	// Run Smuggle
	printer.SectionHeader("HTTP SMUGGLING SCAN")
	smuggleScanner := smuggle.NewScanner(cfg, printer, false, "", 5)
	smuggleScanner.Run()

	// Summary
	results := printer.GetResults()
	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}
	printer.Info("Scan complete. %d total results, %d potential vulnerabilities found.", len(results), vulnCount)

	return nil
}
