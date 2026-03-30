package bypass

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aether-0/httpsuite/pkg/common"
	"github.com/aether-0/httpsuite/pkg/httpclient"
	"github.com/aether-0/httpsuite/pkg/output"
	"github.com/aether-0/httpsuite/pkg/utils"
)

const maxRawResponseSample = 64 * 1024

// Scanner performs 403 bypass testing
type Scanner struct {
	config          *common.Config
	printer         *output.Printer
	client          *httpclient.Client
	targetURL       string
	techniques      []string
	bypassIP        string
	defaultCL       int
	defaultBody     httpclient.ResponseSummary
	calibrationBody httpclient.ResponseSummary

	verbResultsMu sync.Mutex
	verbResults   map[string]httpclient.ResponseSummary
}

type limitedBodyCapture struct {
	limit int
	buf   bytes.Buffer
}

type namedBaseline struct {
	name    string
	summary httpclient.ResponseSummary
}

type candidateDecision struct {
	interesting      bool
	reason           string
	suppressedReason string
}

func (c *limitedBodyCapture) Write(p []byte) (int, error) {
	if c.buf.Len() >= c.limit {
		return len(p), nil
	}

	remaining := c.limit - c.buf.Len()
	if remaining > len(p) {
		remaining = len(p)
	}

	if remaining > 0 {
		_, _ = c.buf.Write(p[:remaining])
	}

	return len(p), nil
}

func (c *limitedBodyCapture) Bytes() []byte {
	return c.buf.Bytes()
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
		config:      cfg,
		printer:     printer,
		client:      client,
		targetURL:   targetURL,
		techniques:  techniques,
		bypassIP:    bypassIP,
		verbResults: make(map[string]httpclient.ResponseSummary),
	}
}

// Run executes the bypass scan
func (s *Scanner) Run() {
	s.printer.Info("Starting 403 bypass scan for: %s", s.targetURL)

	s.calibrate()
	s.defaultRequest()

	for _, tech := range s.techniques {
		switch strings.TrimSpace(tech) {
		case "verbs":
			s.verbTampering()
		case "verbs-case":
			s.verbCaseSwitching()
		case "headers":
			s.headerBypass()
		case "endpaths":
			s.endPathBypass()
		case "midpaths":
			s.midPathBypass()
		case "double-encoding":
			s.doubleEncoding()
		case "http-versions":
			s.httpVersions()
		case "path-case":
			s.pathCaseSwitching()
		default:
			s.printer.Warning("Unknown technique: %s", tech)
		}
	}
}

func (s *Scanner) requestMethod() string {
	if s.config.Method == "" {
		return http.MethodGet
	}
	return s.config.Method
}

func (s *Scanner) calibrate() {
	calibrationURL := s.targetURL
	if !strings.HasSuffix(calibrationURL, "/") {
		calibrationURL += "/"
	}
	calibrationURL += "calibration_test_" + utils.RandomString(8)

	summary, err := s.client.InspectRequest(http.MethodGet, calibrationURL, nil)
	if err != nil {
		s.printer.Warning("Calibration failed: %v", err)
		return
	}

	s.defaultCL = summary.ContentLength
	s.calibrationBody = summary
	s.printer.Info("Auto-calibration: status=%d, content-length=%d", summary.StatusCode, summary.ContentLength)
}

func (s *Scanner) defaultRequest() {
	s.printer.SectionHeader("DEFAULT REQUEST")

	summary, err := s.client.InspectRequest(s.requestMethod(), s.targetURL, nil)
	if err != nil {
		s.printer.Error("Default request failed: %v", err)
		return
	}

	s.defaultBody = summary

	s.printer.Result(common.ScanResult{
		URL:           s.targetURL,
		Method:        s.requestMethod(),
		StatusCode:    summary.StatusCode,
		ContentLength: summary.ContentLength,
		Title:         summary.Title,
		Fingerprint:   summary.NormalizedHash,
		Module:        "bypass",
		Detail:        "default request",
	})
}

func (s *Scanner) verbTampering() {
	s.printer.SectionHeader("VERB TAMPERING")

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, method := range HTTPMethodsForDir(s.config.PayloadDir) {
		wg.Add(1)
		sem <- struct{}{}
		go func(method string) {
			defer wg.Done()
			defer func() { <-sem }()

			summary, err := s.client.InspectRequest(method, s.targetURL, nil)
			if err != nil {
				return
			}

			decision := s.decideCandidate(summary)
			if !decision.interesting {
				s.logSuppressed("verb tampering", s.targetURL, method, decision.suppressedReason)
				return
			}

			s.recordVerbResult(method, summary)

			s.emitBypassResult(s.targetURL, method, "verb tampering", summary, decision.reason)
		}(method)
	}

	wg.Wait()
}

func (s *Scanner) verbCaseSwitching() {
	s.printer.SectionHeader("VERB CASE SWITCHING")

	verbResults := s.verbResultsSnapshot()
	if len(verbResults) == 0 {
		s.printer.Info("No interesting verb tampering results to expand")
		return
	}

	type workItem struct {
		method   string
		original httpclient.ResponseSummary
	}

	workItems := make([]workItem, 0, len(verbResults)*8)
	for method, signature := range verbResults {
		for _, variant := range utils.GenerateCaseVariants(strings.ToLower(method), 12) {
			if variant == method {
				continue
			}
			workItems = append(workItems, workItem{
				method:   variant,
				original: signature,
			})
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, item := range workItems {
		wg.Add(1)
		sem <- struct{}{}
		go func(item workItem) {
			defer wg.Done()
			defer func() { <-sem }()

			summary, err := s.client.InspectRequest(item.method, s.targetURL, nil)
			if err != nil {
				return
			}

			if s.sameBlockedResponse(summary, item.original) {
				s.logSuppressed("verb case switching", s.targetURL, item.method, "matched existing interesting verb response")
				return
			}

			decision := s.decideCandidate(summary)
			if !decision.interesting {
				s.logSuppressed("verb case switching", s.targetURL, item.method, decision.suppressedReason)
				return
			}

			s.emitBypassResult(s.targetURL, item.method, "verb case switching", summary, decision.reason)
		}(item)
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

	payloads := BuildHeaderPayloadsForDir(
		s.config.PayloadDir,
		s.targetURL,
		path,
		parsedURL.Host,
		parsedURL.Scheme,
		s.bypassIP,
	)

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, hp := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(hp HeaderPayload) {
			defer wg.Done()
			defer func() { <-sem }()

			extraHeaders := map[string]string{
				hp.Key: hp.Value,
			}

			summary, err := s.client.InspectRequest(s.requestMethod(), s.targetURL, extraHeaders)
			if err != nil {
				return
			}

			decision := s.decideCandidate(summary)
			if !decision.interesting {
				s.logSuppressed("header bypass", s.targetURL, s.requestMethod(), decision.suppressedReason)
				return
			}

			reason := decision.reason
			if reason != "" {
				reason = fmt.Sprintf("%s; %s", fmt.Sprintf("%s: %s", hp.Key, hp.Value), reason)
			} else {
				reason = fmt.Sprintf("%s: %s", hp.Key, hp.Value)
			}

			s.emitBypassResult(s.targetURL, s.requestMethod(), "header bypass", summary, reason)
		}(hp)
	}

	wg.Wait()
}

func (s *Scanner) endPathBypass() {
	s.printer.SectionHeader("END PATH BYPASS")

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, payload := range EndPathPayloadsForDir(s.config.PayloadDir) {
		wg.Add(1)
		sem <- struct{}{}
		go func(payload string) {
			defer wg.Done()
			defer func() { <-sem }()

			testURL := utils.JoinURL(s.targetURL, payload)
			summary, err := s.client.InspectRequest(s.requestMethod(), testURL, nil)
			if err != nil {
				return
			}

			decision := s.decideCandidate(summary)
			if !decision.interesting {
				s.logSuppressed("endpath", testURL, s.requestMethod(), decision.suppressedReason)
				return
			}

			s.emitBypassResult(testURL, s.requestMethod(), "endpath", summary, decision.reason)
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

	for _, payload := range MidPathPayloadsForDir(s.config.PayloadDir) {
		wg.Add(1)
		sem <- struct{}{}
		go func(payload string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullpath := baseURL + basePath + payload + lastSegment
			if trailingSlash {
				fullpath += "/"
			}
			if parsedURL.RawQuery != "" {
				fullpath += "?" + parsedURL.RawQuery
			}

			summary, err := s.client.InspectRequest(s.requestMethod(), fullpath, nil)
			if err != nil {
				return
			}

			decision := s.decideCandidate(summary)
			if !decision.interesting {
				s.logSuppressed("midpath", fullpath, s.requestMethod(), decision.suppressedReason)
				return
			}

			s.emitBypassResult(fullpath, s.requestMethod(), "midpath", summary, decision.reason)
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
	if originalPath == "" || originalPath == "/" {
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
		if parsedURL.RawQuery != "" {
			encodedURI += "?" + parsedURL.RawQuery
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(uri string) {
			defer wg.Done()
			defer func() { <-sem }()

			summary, err := s.client.InspectRequest(s.requestMethod(), uri, nil)
			if err != nil {
				return
			}

			decision := s.decideCandidate(summary)
			if !decision.interesting {
				s.logSuppressed("double encoding", uri, s.requestMethod(), decision.suppressedReason)
				return
			}

			s.emitBypassResult(uri, s.requestMethod(), "double encoding", summary, decision.reason)
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
	queryStr := ""
	if parsedURL.RawQuery != "" {
		queryStr = "?" + parsedURL.RawQuery
	}

	if uriPath == "" {
		s.printer.Info("No path to modify for case switching")
		return
	}

	variants := utils.GenerateCaseVariants(uriPath, 20)

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for _, path := range variants {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullpath := baseURI + "/" + path
			if strings.HasSuffix(s.targetURL, "/") {
				fullpath += "/"
			}
			fullpath += queryStr

			summary, err := s.client.InspectRequest(s.requestMethod(), fullpath, nil)
			if err != nil {
				return
			}

			decision := s.decideCandidate(summary)
			if !decision.interesting {
				s.logSuppressed("path case", fullpath, s.requestMethod(), decision.suppressedReason)
				return
			}

			s.emitBypassResult(fullpath, s.requestMethod(), "path case", summary, decision.reason)
		}(path)
	}

	wg.Wait()
}

func (s *Scanner) httpVersions() {
	s.printer.SectionHeader("HTTP VERSIONS")

	if s.config.Proxy != nil {
		s.printer.Warning("Skipping HTTP version checks for %s: proxy mode is not supported", s.targetURL)
		return
	}

	for _, version := range HTTPVersions {
		summary, err := s.requestHTTPVersion(version)
		if err != nil {
			if s.config.Verbose {
				s.printer.Error("HTTP/%s request failed: %v", version, err)
			}
			continue
		}

		decision := s.decideCandidate(summary)
		if !decision.interesting {
			s.logSuppressed("http version", s.targetURL, s.requestMethod(), decision.suppressedReason)
			continue
		}

		reason := decision.reason
		if reason != "" {
			reason = "HTTP/" + version + "; " + reason
		} else {
			reason = "HTTP/" + version
		}

		s.emitBypassResult(s.targetURL, s.requestMethod(), "http version", summary, reason)
	}
}

func (s *Scanner) requestHTTPVersion(version string) (httpclient.ResponseSummary, error) {
	parsedURL, err := url.Parse(s.targetURL)
	if err != nil {
		return httpclient.ResponseSummary{}, err
	}

	addr := parsedURL.Host
	if parsedURL.Port() == "" {
		switch parsedURL.Scheme {
		case "https":
			addr = net.JoinHostPort(parsedURL.Hostname(), "443")
		case "http":
			addr = net.JoinHostPort(parsedURL.Hostname(), "80")
		default:
			return httpclient.ResponseSummary{}, fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
		}
	}

	dialer := &net.Dialer{Timeout: s.config.Timeout}
	var conn net.Conn
	switch parsedURL.Scheme {
	case "https":
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         parsedURL.Hostname(),
		})
	case "http":
		conn, err = dialer.Dial("tcp", addr)
	default:
		err = fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}
	if err != nil {
		return httpclient.ResponseSummary{}, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(s.config.Timeout)); err != nil {
		return httpclient.ResponseSummary{}, err
	}

	targetPath := parsedURL.RequestURI()
	if targetPath == "" {
		targetPath = "/"
	}

	method := s.requestMethod()

	var builder strings.Builder
	builder.WriteString(method)
	builder.WriteByte(' ')
	builder.WriteString(targetPath)
	builder.WriteString(" HTTP/")
	builder.WriteString(version)
	builder.WriteString("\r\n")
	builder.WriteString("Host: ")
	builder.WriteString(parsedURL.Host)
	builder.WriteString("\r\n")
	builder.WriteString("User-Agent: ")
	builder.WriteString(s.config.UserAgent)
	builder.WriteString("\r\n")
	builder.WriteString("Accept: */*\r\n")
	builder.WriteString("Connection: close\r\n")
	for key, value := range s.config.Headers {
		if strings.EqualFold(key, "Host") {
			continue
		}
		builder.WriteString(key)
		builder.WriteString(": ")
		builder.WriteString(value)
		builder.WriteString("\r\n")
	}
	builder.WriteString("\r\n")

	if _, err := io.WriteString(conn, builder.String()); err != nil {
		return httpclient.ResponseSummary{}, err
	}

	reader := bufio.NewReader(conn)
	dummyReq := &http.Request{
		Method: method,
		URL:    parsedURL,
	}
	resp, err := http.ReadResponse(reader, dummyReq)
	if err != nil {
		return httpclient.ResponseSummary{}, err
	}
	defer resp.Body.Close()

	capture := &limitedBodyCapture{limit: maxRawResponseSample}
	buf := make([]byte, 32*1024)
	contentLength, err := io.CopyBuffer(io.MultiWriter(io.Discard, capture), resp.Body, buf)
	summary := httpclient.SummarizeResponse(resp, capture.Bytes(), int(contentLength))
	if err != nil {
		return summary, err
	}

	return summary, nil
}

func (s *Scanner) isInteresting(summary httpclient.ResponseSummary) bool {
	return s.decideCandidate(summary).interesting
}

func (s *Scanner) decideCandidate(summary httpclient.ResponseSummary) candidateDecision {
	baselines := s.baselineResponses()
	if len(baselines) == 0 {
		if standaloneBlockLikeSuccess(summary) {
			return candidateDecision{
				suppressedReason: "success-like status but block-page markers detected",
			}
		}
		return candidateDecision{
			interesting: true,
			reason:      "no baseline available",
		}
	}

	for _, baseline := range s.namedBaselines() {
		if s.sameBlockedResponse(summary, baseline.summary) {
			return candidateDecision{
				suppressedReason: "matched " + baseline.name + " blocked template",
			}
		}
	}

	if s.probablyFakeBypass(summary, baselines) {
		return candidateDecision{
			suppressedReason: "success-like status but body still looks blocked",
		}
	}

	if s.defaultBody.StatusCode == 0 {
		return candidateDecision{
			interesting: true,
			reason:      "fingerprint changed from collected baselines",
		}
	}

	reasons := s.interestingReasons(summary)
	if summary.StatusCode != s.defaultBody.StatusCode {
		return candidateDecision{
			interesting: true,
			reason:      strings.Join(reasons, ", "),
		}
	}

	if absInt(summary.ContentLength-s.defaultBody.ContentLength) > similarityTolerance(s.defaultBody.ContentLength) {
		return candidateDecision{
			interesting: true,
			reason:      strings.Join(reasons, ", "),
		}
	}

	if summary.Title != "" && s.defaultBody.Title != "" && !strings.EqualFold(summary.Title, s.defaultBody.Title) {
		return candidateDecision{
			interesting: true,
			reason:      strings.Join(reasons, ", "),
		}
	}

	if summary.NormalizedHash != s.defaultBody.NormalizedHash {
		return candidateDecision{
			interesting: true,
			reason:      strings.Join(reasons, ", "),
		}
	}

	return candidateDecision{
		suppressedReason: "matched default status, size, and fingerprint",
	}
}

func (s *Scanner) baselineResponses() []httpclient.ResponseSummary {
	named := s.namedBaselines()
	baselines := make([]httpclient.ResponseSummary, 0, len(named))
	for _, baseline := range named {
		baselines = append(baselines, baseline.summary)
	}
	return baselines
}

func (s *Scanner) namedBaselines() []namedBaseline {
	baselines := make([]namedBaseline, 0, 2)
	if s.defaultBody.StatusCode != 0 {
		baselines = append(baselines, namedBaseline{
			name:    "default",
			summary: s.defaultBody,
		})
	}
	if s.calibrationBody.StatusCode != 0 {
		baselines = append(baselines, namedBaseline{
			name:    "calibration",
			summary: s.calibrationBody,
		})
	}
	return baselines
}

func (s *Scanner) sameBlockedResponse(left, right httpclient.ResponseSummary) bool {
	if right.StatusCode == 0 {
		return false
	}

	if left.NormalizedHash != "" && right.NormalizedHash != "" && left.NormalizedHash == right.NormalizedHash {
		return true
	}

	similarity := textSimilarity(left.TextSignature, right.TextSignature)
	lengthClose := absInt(left.ContentLength-right.ContentLength) <= similarityTolerance(maxInt(left.ContentLength, right.ContentLength))
	sameTitle := left.Title != "" && right.Title != "" && strings.EqualFold(left.Title, right.Title)
	sameType := normalizedContentType(left.ContentType) != "" &&
		normalizedContentType(left.ContentType) == normalizedContentType(right.ContentType)
	blockish := looksLikeBlockPage(left) || looksLikeBlockPage(right)

	if left.IsHTML && right.IsHTML {
		switch {
		case sameTitle && lengthClose && similarity >= 0.72:
			return true
		case sameTitle && similarity >= 0.82:
			return true
		case blockish && lengthClose && similarity >= 0.68:
			return true
		case similarity >= 0.93:
			return true
		}
	}

	if sameType && lengthClose && similarity >= 0.88 {
		return true
	}

	return lengthClose && similarity >= 0.94
}

func (s *Scanner) probablyFakeBypass(summary httpclient.ResponseSummary, baselines []httpclient.ResponseSummary) bool {
	if !looksLikeBlockPage(summary) || !isSuccessLikeStatus(summary.StatusCode) {
		return false
	}

	for _, baseline := range baselines {
		if baseline.StatusCode == 0 {
			continue
		}

		lengthClose := absInt(summary.ContentLength-baseline.ContentLength) <= similarityTolerance(maxInt(summary.ContentLength, baseline.ContentLength))
		similarity := textSimilarity(summary.TextSignature, baseline.TextSignature)
		sameTitle := summary.Title != "" && baseline.Title != "" && strings.EqualFold(summary.Title, baseline.Title)

		switch {
		case sameTitle:
			return true
		case lengthClose && similarity >= 0.45:
			return true
		case lengthClose && containsBlockStatusMarker(summary):
			return true
		case similarity >= 0.7:
			return true
		}
	}

	return containsBlockStatusMarker(summary)
}

func (s *Scanner) recordVerbResult(method string, summary httpclient.ResponseSummary) {
	s.verbResultsMu.Lock()
	defer s.verbResultsMu.Unlock()
	s.verbResults[method] = summary
}

func (s *Scanner) interestingReasons(summary httpclient.ResponseSummary) []string {
	reasons := make([]string, 0, 4)

	if s.defaultBody.StatusCode != 0 && summary.StatusCode != s.defaultBody.StatusCode {
		reasons = append(reasons, fmt.Sprintf("status %d->%d", s.defaultBody.StatusCode, summary.StatusCode))
	}

	if s.defaultBody.ContentLength != 0 && absInt(summary.ContentLength-s.defaultBody.ContentLength) > similarityTolerance(s.defaultBody.ContentLength) {
		reasons = append(reasons, fmt.Sprintf("size %d->%d", s.defaultBody.ContentLength, summary.ContentLength))
	}

	if summary.Title != "" && s.defaultBody.Title != "" && !strings.EqualFold(summary.Title, s.defaultBody.Title) {
		reasons = append(reasons, fmt.Sprintf("title %q->%q", s.defaultBody.Title, summary.Title))
	}

	if summary.NormalizedHash != "" && summary.NormalizedHash != s.defaultBody.NormalizedHash {
		reasons = append(reasons, "body fingerprint changed")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "response changed from baseline")
	}

	return reasons
}

func (s *Scanner) emitBypassResult(targetURL, method, technique string, summary httpclient.ResponseSummary, reason string) {
	detail := technique
	if reason != "" {
		detail += " -> " + reason
	}

	s.printer.Result(common.ScanResult{
		URL:           targetURL,
		Method:        method,
		StatusCode:    summary.StatusCode,
		ContentLength: summary.ContentLength,
		Detail:        detail,
		Reason:        reason,
		Title:         summary.Title,
		Fingerprint:   summary.NormalizedHash,
		Module:        "bypass",
	})
}

func (s *Scanner) logSuppressed(technique, targetURL, method, reason string) {
	if !s.config.Verbose || reason == "" {
		return
	}

	methodInfo := method
	if methodInfo == "" {
		methodInfo = s.requestMethod()
	}

	s.printer.Info("Suppressed %s [%s] %s: %s", technique, methodInfo, targetURL, reason)
}

func (s *Scanner) verbResultsSnapshot() map[string]httpclient.ResponseSummary {
	s.verbResultsMu.Lock()
	defer s.verbResultsMu.Unlock()

	snapshot := make(map[string]httpclient.ResponseSummary, len(s.verbResults))
	for method, summary := range s.verbResults {
		snapshot[method] = summary
	}
	return snapshot
}

func textSimilarity(left, right string) float64 {
	if left == "" || right == "" {
		if left == right && left != "" {
			return 1
		}
		return 0
	}

	leftTokens := tokenizeSignature(left)
	rightTokens := tokenizeSignature(right)
	if len(leftTokens) == 0 || len(rightTokens) == 0 {
		if left == right {
			return 1
		}
		return 0
	}

	intersection := 0
	for token := range leftTokens {
		if _, ok := rightTokens[token]; ok {
			intersection++
		}
	}

	union := len(leftTokens) + len(rightTokens) - intersection
	if union == 0 {
		return 1
	}

	return float64(intersection) / float64(union)
}

func tokenizeSignature(signature string) map[string]struct{} {
	tokens := make(map[string]struct{})
	for _, token := range strings.FieldsFunc(signature, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if len(token) < 2 {
			continue
		}
		tokens[token] = struct{}{}
	}
	return tokens
}

func normalizedContentType(contentType string) string {
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	if contentType == "" {
		return ""
	}
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	return contentType
}

func looksLikeBlockPage(summary httpclient.ResponseSummary) bool {
	text := strings.ToLower(summary.Title + " " + summary.TextSignature)
	for _, marker := range []string{
		"403 forbidden",
		"401 unauthorized",
		"404 not found",
		"forbidden",
		"access denied",
		"access forbidden",
		"directory access is forbidden",
		"unauthorized",
		"not authorized",
		"request blocked",
		"blocked request",
		"permission denied",
		"request forbidden",
		"error 403",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func containsBlockStatusMarker(summary httpclient.ResponseSummary) bool {
	text := strings.ToLower(summary.Title + " " + summary.TextSignature)
	return strings.Contains(text, "403") || strings.Contains(text, "401") || strings.Contains(text, "404")
}

func isSuccessLikeStatus(statusCode int) bool {
	return statusCode >= 200 && statusCode < 400
}

func standaloneBlockLikeSuccess(summary httpclient.ResponseSummary) bool {
	return isSuccessLikeStatus(summary.StatusCode) && looksLikeBlockPage(summary)
}

func similarityTolerance(contentLength int) int {
	tolerance := 32
	if contentLength > 0 {
		if dynamic := contentLength / 20; dynamic > tolerance {
			tolerance = dynamic
		}
	}
	return tolerance
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
