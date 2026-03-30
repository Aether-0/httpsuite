package httpclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxFingerprintBytes = 64 * 1024
	maxTextSignatureLen = 512
)

var (
	titlePattern   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	scriptPattern  = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	stylePattern   = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	commentPattern = regexp.MustCompile(`(?s)<!--.*?-->`)
	tagPattern     = regexp.MustCompile(`(?s)<[^>]+>`)
	spacePattern   = regexp.MustCompile(`\s+`)
)

// ResponseSummary stores a bounded fingerprint of a response body.
type ResponseSummary struct {
	StatusCode     int
	ContentLength  int
	ContentType    string
	Title          string
	NormalizedHash string
	TextSignature  string
	IsHTML         bool
}

type limitedCapture struct {
	limit int
	buf   bytes.Buffer
}

func (c *limitedCapture) Write(p []byte) (int, error) {
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

func (c *limitedCapture) Bytes() []byte {
	return c.buf.Bytes()
}

func buildResponseSummary(resp *http.Response, sample []byte, contentLength int) ResponseSummary {
	contentType := resp.Header.Get("Content-Type")
	title, text, normalizedHash, isHTML := fingerprintResponseSample(sample, contentType)

	return ResponseSummary{
		StatusCode:     resp.StatusCode,
		ContentLength:  contentLength,
		ContentType:    contentType,
		Title:          title,
		NormalizedHash: normalizedHash,
		TextSignature:  text,
		IsHTML:         isHTML,
	}
}

// SummarizeResponse builds a bounded response summary from a sampled body.
func SummarizeResponse(resp *http.Response, sample []byte, contentLength int) ResponseSummary {
	return buildResponseSummary(resp, sample, contentLength)
}

func fingerprintResponseSample(sample []byte, contentType string) (title, text, normalizedHash string, isHTML bool) {
	raw := string(sample)
	lowerRaw := strings.ToLower(raw)
	lowerContentType := strings.ToLower(contentType)

	isHTML = strings.Contains(lowerContentType, "text/html") ||
		strings.Contains(lowerRaw, "<html") ||
		strings.Contains(lowerRaw, "<!doctype html") ||
		strings.Contains(lowerRaw, "<body")

	if isHTML {
		if match := titlePattern.FindStringSubmatch(raw); len(match) == 2 {
			title = collapseWhitespace(html.UnescapeString(match[1]))
		}

		raw = scriptPattern.ReplaceAllString(raw, " ")
		raw = stylePattern.ReplaceAllString(raw, " ")
		raw = commentPattern.ReplaceAllString(raw, " ")
		raw = tagPattern.ReplaceAllString(raw, " ")
		raw = html.UnescapeString(raw)
	}

	text = truncateRunes(collapseWhitespace(strings.ToLower(raw)), maxTextSignatureLen)
	if text == "" {
		sum := sha256.Sum256(sample)
		return title, "", hex.EncodeToString(sum[:8]), isHTML
	}

	sum := sha256.Sum256([]byte(text))
	return title, text, hex.EncodeToString(sum[:8]), isHTML
}

func collapseWhitespace(s string) string {
	s = strings.ReplaceAll(s, "\x00", " ")
	s = spacePattern.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}

	count := 0
	for idx := range s {
		if count == maxRunes {
			return s[:idx]
		}
		count++
	}

	return s
}
