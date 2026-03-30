package bypass

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/aether-0/httpsuite/pkg/httpclient"
)

func TestIsInterestingRejectsSameBlockTemplateWithDifferentStatus(t *testing.T) {
	blocked := summarizeHTMLResponse(http.StatusForbidden, htmlPage("403 Forbidden", "Directory access is forbidden."))

	scanner := &Scanner{
		defaultBody: blocked,
	}

	candidate := summarizeHTMLResponse(http.StatusOK, htmlPage("403 Forbidden", "Directory access is forbidden."))
	if scanner.isInteresting(candidate) {
		t.Fatalf("expected identical blocked template with a different status to be ignored")
	}
}

func TestIsInterestingRejectsCalibrationTemplate(t *testing.T) {
	defaultBody := summarizeHTMLResponse(http.StatusForbidden, htmlPage("403 Forbidden", "Directory access is forbidden."))
	calibrationBody := summarizeHTMLResponse(http.StatusNotFound, htmlPage("404 Not Found", "The requested resource was not found."))

	scanner := &Scanner{
		defaultBody:     defaultBody,
		calibrationBody: calibrationBody,
	}

	candidate := summarizeHTMLResponse(http.StatusNotFound, htmlPage("404 Not Found", "The requested resource was not found."))
	if scanner.isInteresting(candidate) {
		t.Fatalf("expected calibration-like response to be ignored")
	}
}

func TestIsInterestingAcceptsDifferentBodyWithSameStatusAndLength(t *testing.T) {
	defaultBodyRaw := htmlPage("403 Forbidden", "Directory access is forbidden.")
	candidateRaw := padToLength(
		htmlPage("403 Forbidden", "Admin panel open."),
		len(defaultBodyRaw),
	)

	if len(defaultBodyRaw) != len(candidateRaw) {
		t.Fatalf("test setup failed: expected same response length, got %d and %d", len(defaultBodyRaw), len(candidateRaw))
	}

	scanner := &Scanner{
		defaultBody: summarizeHTMLResponse(http.StatusForbidden, defaultBodyRaw),
	}

	candidate := summarizeHTMLResponse(http.StatusForbidden, candidateRaw)
	if !scanner.isInteresting(candidate) {
		t.Fatalf("expected same-length but different body to be reported as interesting")
	}
}

func TestIsInterestingRejectsFake200BlockPageByMarkerAndLength(t *testing.T) {
	defaultBodyRaw := htmlPage("403 Forbidden", "Directory access is forbidden.")
	candidateRaw := padToLength(
		htmlPage("Access denied", "403 request blocked by policy."),
		len(defaultBodyRaw),
	)

	scanner := &Scanner{
		defaultBody: summarizeHTMLResponse(http.StatusForbidden, defaultBodyRaw),
	}

	candidate := summarizeHTMLResponse(http.StatusOK, candidateRaw)
	if scanner.isInteresting(candidate) {
		t.Fatalf("expected fake 200 block page with 403 markers to be ignored")
	}
}

func summarizeHTMLResponse(status int, body string) httpclient.ResponseSummary {
	resp := &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
	}

	return httpclient.SummarizeResponse(resp, []byte(body), len(body))
}

func htmlPage(title, message string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>`, title, title, message)
}

func padToLength(body string, size int) string {
	if len(body) >= size {
		return body
	}
	return body + strings.Repeat(" ", size-len(body))
}
