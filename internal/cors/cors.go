package cors

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/aether-0/httpsuite/pkg/common"
	"github.com/aether-0/httpsuite/pkg/httpclient"
	"github.com/aether-0/httpsuite/pkg/output"
)

// Scanner performs CORS misconfiguration testing
type Scanner struct {
	config   *common.Config
	printer  *output.Printer
	client   *httpclient.Client
	origin   string
	deepScan bool
}

// NewScanner creates a new CORS scanner
func NewScanner(cfg *common.Config, printer *output.Printer, origin string, deepScan bool) *Scanner {
	client := httpclient.New(httpclient.Options{
		Timeout:   cfg.Timeout,
		Proxy:     cfg.Proxy,
		UserAgent: cfg.UserAgent,
		Headers:   cfg.Headers,
		Retries:   cfg.Retries,
		Redirect:  false,
		Insecure:  true,
	})

	return &Scanner{
		config:   cfg,
		printer:  printer,
		client:   client,
		origin:   origin,
		deepScan: deepScan,
	}
}

// Run executes the CORS scan across all targets
func (s *Scanner) Run() {
	s.printer.Info("Starting CORS misconfiguration scan for %d target(s)", len(s.config.URLs))

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, targetURL := range s.config.URLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.scanTarget(targetURL)
		}(targetURL)
	}
	wg.Wait()
}

func (s *Scanner) scanTarget(targetURL string) {
	// First, run preflight check
	s.preflightCheck(targetURL)

	// Generate origin payloads
	payloads := s.generatePayloads(targetURL)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, payload := range payloads {
		wg.Add(1)
		go func(origin string) {
			defer wg.Done()
			s.testOrigin(targetURL, origin, &mu)
		}(payload)
	}
	wg.Wait()
}

func (s *Scanner) preflightCheck(targetURL string) {
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		s.printer.Error("Preflight error for %s: %v", targetURL, err)
		return
	}

	req.Header.Set("Origin", s.origin)
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.printer.Error("Preflight request failed for %s: %v", targetURL, err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	acam := resp.Header.Get("Access-Control-Allow-Methods")
	acah := resp.Header.Get("Access-Control-Allow-Headers")

	if s.config.Verbose {
		s.printer.Info("Preflight for %s: ACAO=%s, ACAC=%s, Methods=%s, Headers=%s",
			targetURL, acao, acac, acam, acah)
	}
}

func (s *Scanner) testOrigin(targetURL, origin string, mu *sync.Mutex) {
	req, err := http.NewRequest(s.config.Method, targetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Connection", "close")

	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	vulnerable, details := evaluateResponse(origin, acao, acac)
	if vulnerable {
		mu.Lock()
		for _, detail := range details {
			s.printer.Result(common.ScanResult{
				URL:        targetURL,
				Method:     s.config.Method,
				StatusCode: resp.StatusCode,
				Module:     "cors",
				Detail:     fmt.Sprintf("Origin: %s → %s", origin, detail),
				Vulnerable: true,
			})
		}
		mu.Unlock()
	} else if s.config.Verbose {
		s.printer.Result(common.ScanResult{
			URL:        targetURL,
			Method:     s.config.Method,
			StatusCode: resp.StatusCode,
			Module:     "cors",
			Detail:     fmt.Sprintf("Origin: %s → not vulnerable", origin),
			Vulnerable: false,
		})
	}
}

// generatePayloads creates origin payloads for CORS testing
func (s *Scanner) generatePayloads(targetURL string) []string {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return []string{s.origin}
	}

	host := parsedURL.Hostname()
	parts := strings.Split(host, ".")
	var domain, tld string
	if len(parts) >= 2 {
		domain = parts[len(parts)-2]
		tld = parts[len(parts)-1]
	} else {
		domain = host
		tld = ""
	}

	payloads := []string{
		// Null origin
		"null",
		// Evil origin
		"https://evil.com",
		"http://evil.com",
		// Reflected origin (the target itself)
		targetURL,
		// Prefix match bypass
		fmt.Sprintf("https://%s.%s.evil.com", domain, tld),
		// Suffix match bypass
		fmt.Sprintf("https://evil%s.%s", domain, tld),
		// Subdomain
		fmt.Sprintf("https://sub.%s.%s", domain, tld),
		// With port
		fmt.Sprintf("https://%s.%s:8080", domain, tld),
		// Double domain
		fmt.Sprintf("https://%s.%s.%s.%s", domain, tld, domain, tld),
	}

	if s.deepScan {
		// Additional deep scan payloads
		specialChars := []string{
			"!", "'", "(", ")", "*", ",", ";", "_", "{", "}",
			"|", "~", "\"", "`", "+", "-",
		}
		for _, c := range specialChars {
			payloads = append(payloads, fmt.Sprintf("https://%s.%s%s.evil.com", domain, tld, c))
		}
		// User-at-domain bypass
		payloads = append(payloads, fmt.Sprintf("https://evil.com%%40%s.%s", domain, tld))
		payloads = append(payloads, fmt.Sprintf("https://evil.com%%23@%s.%s", domain, tld))
	}

	return payloads
}

// evaluateResponse checks for CORS misconfigurations
func evaluateResponse(payload, acao, acac string) (bool, []string) {
	var details []string

	// Check origin reflected
	if acao == payload {
		detail := fmt.Sprintf("ACAO reflects origin: %s", acao)
		if acac == "true" {
			detail += " (with credentials)"
		}
		details = append(details, detail)
	}

	// Check wildcard
	if acao == "*" {
		details = append(details, "Wildcard ACAO: *")
	}

	// Check null origin
	if acao == "null" && payload == "null" {
		details = append(details, "Null origin allowed in ACAO")
	}

	// Check credentials with reflected origin
	if acac == "true" && acao != "" && acao != "*" && acao == payload {
		details = append(details, fmt.Sprintf("Credentials allowed with reflected origin: ACAO=%s, ACAC=true", acao))
	}

	if len(details) > 0 {
		return true, details
	}
	return false, nil
}
