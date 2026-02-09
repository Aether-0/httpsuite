package bypass

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/aether-0/httpsuite/pkg/common"
	"github.com/aether-0/httpsuite/pkg/httpclient"
	"github.com/aether-0/httpsuite/pkg/output"
	"github.com/aether-0/httpsuite/pkg/utils"
)

// Scanner performs 403 bypass testing
type Scanner struct {
	config     *common.Config
	printer    *output.Printer
	client     *httpclient.Client
	targetURL  string
	techniques []string
	bypassIP   string
	defaultCL  int
	mu         sync.Mutex
}

// NewScanner creates a new bypass scanner
func NewScanner(cfg *common.Config, printer *output.Printer, targetURL string, techniques []string, bypassIP string) *Scanner {
	client := httpclient.New(httpclient.Options{
		Timeout:   cfg.Timeout,
		Proxy:     cfg.Proxy,
		UserAgent: cfg.UserAgent,
		Headers:   cfg.Headers,
		Retries:   cfg.Retries,
		Redirect:  cfg.Redirect,
		Insecure:  true,
	})

	return &Scanner{
		config:     cfg,
		printer:    printer,
		client:     client,
		targetURL:  targetURL,
		techniques: techniques,
		bypassIP:   bypassIP,
	}
}

// Run executes the bypass scan
func (s *Scanner) Run() {
	s.printer.Info("Starting 403 bypass scan for: %s", s.targetURL)

	// Auto-calibrate: get default response
	s.calibrate()

	// Run default request
	s.defaultRequest()

	// Execute selected techniques
	for _, tech := range s.techniques {
		switch strings.TrimSpace(tech) {
		case "verbs":
			s.verbTampering()
		case "headers":
			s.headerBypass()
		case "endpaths":
			s.endPathBypass()
		case "midpaths":
			s.midPathBypass()
		case "double-encoding":
			s.doubleEncoding()
		case "path-case":
			s.pathCaseSwitching()
		default:
			s.printer.Warning("Unknown technique: %s", tech)
		}
	}
}

func (s *Scanner) calibrate() {
	calibrationURL := s.targetURL
	if !strings.HasSuffix(calibrationURL, "/") {
		calibrationURL += "/"
	}
	calibrationURL += "calibration_test_" + utils.RandomString(8)

	statusCode, body, err := s.client.SimpleRequest("GET", calibrationURL, nil)
	if err != nil {
		s.printer.Warning("Calibration failed: %v", err)
		return
	}

	s.defaultCL = len(body)
	s.printer.Info("Auto-calibration: status=%d, content-length=%d", statusCode, s.defaultCL)
}

func (s *Scanner) defaultRequest() {
	s.printer.SectionHeader("DEFAULT REQUEST")
	statusCode, body, err := s.client.SimpleRequest(s.config.Method, s.targetURL, nil)
	if err != nil {
		s.printer.Error("Default request failed: %v", err)
		return
	}

	s.printer.Result(common.ScanResult{
		URL:           s.targetURL,
		Method:        s.config.Method,
		StatusCode:    statusCode,
		ContentLength: len(body),
		Module:        "bypass",
		Detail:        "default request",
	})
}

func (s *Scanner) verbTampering() {
	s.printer.SectionHeader("VERB TAMPERING")

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, method := range HTTPMethods {
		wg.Add(1)
		sem <- struct{}{}
		go func(method string) {
			defer wg.Done()
			defer func() { <-sem }()

			statusCode, body, err := s.client.SimpleRequest(method, s.targetURL, nil)
			if err != nil {
				return
			}

			if len(body) == s.defaultCL {
				return
			}

			s.printer.Result(common.ScanResult{
				URL:           s.targetURL,
				Method:        method,
				StatusCode:    statusCode,
				ContentLength: len(body),
				Module:        "bypass",
				Detail:        "verb tampering",
			})
		}(method)
	}
	wg.Wait()
}

func (s *Scanner) headerBypass() {
	s.printer.SectionHeader("HEADER BYPASS")

	parsedURL, err := url.Parse(s.targetURL)
	if err != nil {
		s.printer.Error("Error parsing URL: %v", err)
		return
	}
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, hp := range BypassHeaders {
		wg.Add(1)
		sem <- struct{}{}
		go func(hp HeaderPayload) {
			defer wg.Done()
			defer func() { <-sem }()

			value := hp.Value
			if hp.ValueFunc != nil {
				value = hp.ValueFunc(s.targetURL, path)
			}

			// If a custom bypass IP is provided, use it for IP-related headers
			if s.bypassIP != "" && isIPHeader(hp.Key) {
				value = s.bypassIP
			}

			extraHeaders := map[string]string{
				hp.Key: value,
			}

			statusCode, body, err := s.client.SimpleRequest(s.config.Method, s.targetURL, extraHeaders)
			if err != nil {
				return
			}

			if len(body) == s.defaultCL {
				return
			}

			s.printer.Result(common.ScanResult{
				URL:           s.targetURL,
				Method:        s.config.Method,
				StatusCode:    statusCode,
				ContentLength: len(body),
				Module:        "bypass",
				Detail:        fmt.Sprintf("header: %s: %s", hp.Key, value),
			})
		}(hp)
	}
	wg.Wait()
}

func (s *Scanner) endPathBypass() {
	s.printer.SectionHeader("END PATH BYPASS")

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, payload := range EndPathPayloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(payload string) {
			defer wg.Done()
			defer func() { <-sem }()

			testURL := utils.JoinURL(s.targetURL, payload)
			statusCode, body, err := s.client.SimpleRequest(s.config.Method, testURL, nil)
			if err != nil {
				return
			}

			if len(body) == s.defaultCL {
				return
			}

			s.printer.Result(common.ScanResult{
				URL:           testURL,
				Method:        s.config.Method,
				StatusCode:    statusCode,
				ContentLength: len(body),
				Module:        "bypass",
				Detail:        "endpath",
			})
		}(payload)
	}
	wg.Wait()
}

func (s *Scanner) midPathBypass() {
	s.printer.SectionHeader("MID PATH BYPASS")

	parsedURL, err := url.Parse(s.targetURL)
	if err != nil {
		s.printer.Error("Error parsing URL: %v", err)
		return
	}

	pathValue := parsedURL.Path
	if pathValue == "" || pathValue == "/" {
		s.printer.Info("No path to modify for midpath bypass")
		return
	}

	trailingSlash := strings.HasSuffix(pathValue, "/")
	trimmedPath := strings.Trim(pathValue, "/")
	segments := strings.Split(trimmedPath, "/")
	if len(segments) == 0 {
		return
	}

	lastSegment := segments[len(segments)-1]
	baseSegments := segments[:len(segments)-1]
	basePath := "/"
	if len(baseSegments) > 0 {
		basePath = "/" + strings.Join(baseSegments, "/") + "/"
	}

	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, payload := range MidPathPayloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(payload string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullpath := baseURL + basePath + payload + lastSegment
			if trailingSlash {
				fullpath += "/"
			}

			statusCode, body, err := s.client.SimpleRequest(s.config.Method, fullpath, nil)
			if err != nil {
				return
			}

			if len(body) == s.defaultCL {
				return
			}

			s.printer.Result(common.ScanResult{
				URL:           fullpath,
				Method:        s.config.Method,
				StatusCode:    statusCode,
				ContentLength: len(body),
				Module:        "bypass",
				Detail:        "midpath",
			})
		}(payload)
	}
	wg.Wait()
}

func (s *Scanner) doubleEncoding() {
	s.printer.SectionHeader("DOUBLE ENCODING")

	parsedURL, err := url.Parse(s.targetURL)
	if err != nil {
		s.printer.Error("Error parsing URL: %v", err)
		return
	}

	originalPath := parsedURL.Path
	if len(originalPath) == 0 || originalPath == "/" {
		s.printer.Info("No path to modify for double encoding")
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for i, c := range originalPath {
		if c == '/' {
			continue
		}

		singleEncoded := fmt.Sprintf("%%%X", c)
		doubleEncoded := url.QueryEscape(singleEncoded)

		modifiedPath := originalPath[:i] + doubleEncoded + originalPath[i+1:]
		encodedURI := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, modifiedPath)

		wg.Add(1)
		sem <- struct{}{}
		go func(uri string) {
			defer wg.Done()
			defer func() { <-sem }()

			statusCode, body, err := s.client.SimpleRequest(s.config.Method, uri, nil)
			if err != nil {
				return
			}

			s.printer.Result(common.ScanResult{
				URL:           uri,
				Method:        s.config.Method,
				StatusCode:    statusCode,
				ContentLength: len(body),
				Module:        "bypass",
				Detail:        "double-encoding",
			})
		}(encodedURI)
	}
	wg.Wait()
}

func (s *Scanner) pathCaseSwitching() {
	s.printer.SectionHeader("PATH CASE SWITCHING")

	parsedURL, err := url.Parse(s.targetURL)
	if err != nil {
		s.printer.Error("Error parsing URL: %v", err)
		return
	}

	baseURI := parsedURL.Scheme + "://" + parsedURL.Host
	uriPath := strings.Trim(parsedURL.Path, "/")

	if len(uriPath) == 0 {
		s.printer.Info("No path to modify for case switching")
		return
	}

	combinations := utils.GenerateCaseCombinations(uriPath)
	selected := utils.SelectRandom(combinations, 20)

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, path := range selected {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			var fullpath string
			if strings.HasSuffix(s.targetURL, "/") {
				fullpath = baseURI + "/" + path + "/"
			} else {
				fullpath = baseURI + "/" + path
			}

			statusCode, body, err := s.client.SimpleRequest(s.config.Method, fullpath, nil)
			if err != nil {
				return
			}

			s.printer.Result(common.ScanResult{
				URL:           fullpath,
				Method:        s.config.Method,
				StatusCode:    statusCode,
				ContentLength: len(body),
				Module:        "bypass",
				Detail:        "path-case",
			})
		}(path)
	}
	wg.Wait()
}

// isIPHeader checks if a header typically carries an IP value
func isIPHeader(key string) bool {
	ipHeaders := map[string]bool{
		"X-Forwarded-For":           true,
		"X-Forwarded-Host":          true,
		"X-Host":                    true,
		"X-Custom-IP-Authorization": true,
		"X-Originating-IP":          true,
		"X-Remote-IP":               true,
		"X-Client-IP":               true,
		"X-Real-IP":                 true,
		"X-ProxyUser-Ip":            true,
		"X-Remote-Addr":             true,
		"True-Client-IP":            true,
		"Cluster-Client-IP":         true,
		"Proxy-Host":                true,
	}
	return ipHeaders[key]
}

// SimpleRequestRaw creates a raw http request for cases where we need more control
func (s *Scanner) simpleRequestRaw(method, targetURL string, headers []struct{ Key, Value string }) (int, []byte, error) {
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return 0, nil, err
	}

	for _, h := range headers {
		req.Header.Set(h.Key, h.Value)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if readErr != nil {
			break
		}
	}

	return resp.StatusCode, body, nil
}
