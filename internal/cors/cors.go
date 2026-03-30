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

type originPayload struct {
	value    string
	category string
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
		s.preflightCheck(targetURL)

		for _, payload := range s.generatePayloads(targetURL) {
			wg.Add(1)
			sem <- struct{}{}
			go func(targetURL string, payload originPayload) {
				defer wg.Done()
				defer func() { <-sem }()
				s.testOrigin(targetURL, payload)
			}(targetURL, payload)
		}
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

func (s *Scanner) testOrigin(targetURL string, payload originPayload) {
	req, err := http.NewRequest(s.config.Method, targetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("Origin", payload.value)
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
	vary := resp.Header.Get("Vary")

	vulnerable, details := evaluateResponse(payload, acao, acac, vary)
	if vulnerable {
		for _, detail := range details {
			s.printer.Result(common.ScanResult{
				URL:        targetURL,
				Method:     s.config.Method,
				StatusCode: resp.StatusCode,
				Module:     "cors",
				Detail:     fmt.Sprintf("Origin: %s → %s", payload.value, detail),
				Vulnerable: true,
			})
		}
	} else if s.config.Verbose {
		s.printer.Result(common.ScanResult{
			URL:        targetURL,
			Method:     s.config.Method,
			StatusCode: resp.StatusCode,
			Module:     "cors",
			Detail:     fmt.Sprintf("Origin: %s → not vulnerable", payload.value),
			Vulnerable: false,
		})
	}
}

// generatePayloads creates origin payloads for CORS testing
func (s *Scanner) generatePayloads(targetURL string) []originPayload {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return []originPayload{{value: s.origin, category: "custom"}}
	}

	host := parsedURL.Host
	hostname := parsedURL.Hostname()
	scheme := parsedURL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	payloads := []originPayload{
		{value: "null", category: "null"},
		{value: "https://evil.com", category: "reflection"},
		{value: "http://evil.com", category: "reflection"},
		{value: "https://fiddle.jshell.net", category: "developer-backdoor"},
		{value: "https://s.codepen.io", category: "developer-backdoor"},
		{value: scheme + "://" + host, category: "same-origin"},
		{value: scheme + "://sub." + hostname, category: "subdomain"},
		{value: scheme + "://not" + hostname, category: "predomain"},
		{value: scheme + "://" + hostname + ".evil.com", category: "postdomain"},
		{value: scheme + "://" + hostname + ".tk", category: "postdomain"},
		{value: scheme + "://" + hostname + ":8080", category: "alternate-port"},
		{value: s.origin, category: "custom"},
	}

	if scheme == "https" {
		payloads = append(payloads,
			originPayload{value: "http://" + host, category: "non-ssl"},
			originPayload{value: "http://sub." + hostname, category: "non-ssl"},
		)
	}

	if s.deepScan {
		specialChars := []string{
			"!", "'", "(", ")", "*", ",", ";", "_", "{", "}",
			"|", "~", "\"", "`", "+", "-",
		}
		for _, c := range specialChars {
			payloads = append(payloads, originPayload{
				value:    fmt.Sprintf("%s://%s%s.evil.com", scheme, hostname, c),
				category: "postdomain",
			})
		}
		payloads = append(payloads,
			originPayload{value: fmt.Sprintf("%s://evil.com%%40%s", scheme, hostname), category: "reflection"},
			originPayload{value: fmt.Sprintf("%s://evil.com%%23@%s", scheme, hostname), category: "reflection"},
		)
	}

	return dedupeOriginPayloads(payloads)
}

// evaluateResponse checks for CORS misconfigurations
func evaluateResponse(payload originPayload, acao, acac, vary string) (bool, []string) {
	var details []string
	creds := strings.EqualFold(acac, "true")
	credSuffix := ""
	if creds {
		credSuffix = " (with credentials)"
	}

	if strings.ContainsAny(acao, ",|") || (strings.Contains(acao, " ") && acao != "null") {
		details = append(details, "Invalid ACAO header formatting")
	}

	if strings.Contains(acao, "*.") {
		details = append(details, "Invalid wildcard use in ACAO")
	}

	if acao == "*" {
		details = append(details, "Wildcard ACAO: *"+credSuffix)
	}

	if payload.value == "null" && acao == "null" {
		details = append(details, "Null misconfiguration"+credSuffix)
	}

	if acao == payload.value {
		switch payload.category {
		case "developer-backdoor":
			details = append(details, "Developer backdoor"+credSuffix)
		case "reflection":
			details = append(details, "Origin reflection"+credSuffix)
		case "predomain":
			details = append(details, "Pre-domain wildcard"+credSuffix)
		case "postdomain":
			details = append(details, "Post-domain wildcard"+credSuffix)
		case "subdomain":
			details = append(details, "Arbitrary subdomains allowed"+credSuffix)
		case "non-ssl":
			details = append(details, "Non-ssl origin allowed"+credSuffix)
		case "alternate-port":
			details = append(details, "Arbitrary origin/port reflection"+credSuffix)
		case "custom":
			details = append(details, "Custom origin reflected"+credSuffix)
		}

		if creds && payload.category != "same-origin" && payload.category != "null" {
			details = append(details, fmt.Sprintf("Credentials allowed with reflected origin: ACAO=%s, ACAC=true", acao))
		}
	}

	if strings.Contains(vary, "Origin") && acao != "" && creds {
		details = append(details, "ACAO dynamically varies on Origin with credentials")
	}

	if len(details) > 0 {
		return true, details
	}
	return false, nil
}

func dedupeOriginPayloads(payloads []originPayload) []originPayload {
	seen := make(map[string]struct{}, len(payloads))
	deduped := make([]originPayload, 0, len(payloads))

	for _, payload := range payloads {
		if payload.value == "" {
			continue
		}
		if _, ok := seen[payload.value]; ok {
			continue
		}
		seen[payload.value] = struct{}{}
		deduped = append(deduped, payload)
	}

	return deduped
}
