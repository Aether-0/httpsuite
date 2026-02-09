package methods

import (
	"strconv"
	"strings"
	"sync"

	"github.com/aether-0/httpsuite/pkg/common"
	"github.com/aether-0/httpsuite/pkg/httpclient"
	"github.com/aether-0/httpsuite/pkg/output"
)

// Default HTTP methods to test
var defaultMethods = []string{
	"GET", "POST", "PUT", "DELETE", "PATCH",
	"HEAD", "OPTIONS", "TRACE", "CONNECT",
	"PROPFIND", "PROPPATCH", "MKCOL", "COPY",
	"MOVE", "LOCK", "UNLOCK", "PURGE",
}

// Scanner performs HTTP method testing
type Scanner struct {
	config       *common.Config
	printer      *output.Printer
	client       *httpclient.Client
	methods      []string
	statusFilter map[int]bool
}

// NewScanner creates a new methods scanner
func NewScanner(cfg *common.Config, printer *output.Printer, methodList string, filterStatus string) *Scanner {
	client := httpclient.New(httpclient.Options{
		Timeout:   cfg.Timeout,
		Proxy:     cfg.Proxy,
		UserAgent: cfg.UserAgent,
		Headers:   cfg.Headers,
		Retries:   cfg.Retries,
		Redirect:  cfg.Redirect,
		Insecure:  true,
	})

	methods := defaultMethods
	if methodList != "" {
		methods = strings.Split(methodList, ",")
		for i := range methods {
			methods[i] = strings.TrimSpace(methods[i])
		}
	}

	statusFilter := make(map[int]bool)
	if filterStatus != "" {
		codes := strings.Split(filterStatus, ",")
		for _, code := range codes {
			c, err := strconv.Atoi(strings.TrimSpace(code))
			if err == nil {
				statusFilter[c] = true
			}
		}
	}

	return &Scanner{
		config:       cfg,
		printer:      printer,
		client:       client,
		methods:      methods,
		statusFilter: statusFilter,
	}
}

// Run executes the HTTP method scan against all targets
func (s *Scanner) Run() {
	s.printer.Info("Starting HTTP method scan for %d target(s) with %d methods",
		len(s.config.URLs), len(s.methods))
	s.printer.Info("Methods: %s", strings.Join(s.methods, ", "))

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, targetURL := range s.config.URLs {
		for _, method := range s.methods {
			wg.Add(1)
			sem <- struct{}{}
			go func(targetURL, method string) {
				defer wg.Done()
				defer func() { <-sem }()

				statusCode, body, err := s.client.SimpleRequest(method, targetURL, nil)
				if err != nil {
					if s.config.Verbose {
						s.printer.Error("Error with %s [%s]: %v", targetURL, method, err)
					}
					return
				}

				// Apply status code filter
				if len(s.statusFilter) > 0 && !s.statusFilter[statusCode] {
					return
				}

				// Determine if this looks interesting
				vulnerable := false
				detail := ""
				switch {
				case statusCode >= 200 && statusCode < 300:
					detail = "success"
					if method != "GET" && method != "HEAD" && method != "OPTIONS" {
						vulnerable = true
						detail = "unexpected success - method may be enabled"
					}
				case statusCode == 405:
					detail = "method not allowed"
				case statusCode == 501:
					detail = "not implemented"
				default:
					detail = "active"
				}

				s.printer.Result(common.ScanResult{
					URL:           targetURL,
					Method:        method,
					StatusCode:    statusCode,
					ContentLength: len(body),
					Module:        "methods",
					Detail:        detail,
					Vulnerable:    vulnerable,
				})
			}(targetURL, method)
		}
	}
	wg.Wait()
}
