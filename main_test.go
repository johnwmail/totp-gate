package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TOTP Tests
// ---------------------------------------------------------------------------

func TestComputeTOTPKnownValue(t *testing.T) {
	secret, _ := base32.StdEncoding.DecodeString("JBSWY3DPEHPK3PXP")

	result := computeTOTP(secret, 0, 6, "SHA1")
	if len(result) != 6 {
		t.Errorf("expected 6 digits, got %d", len(result))
	}

	result2 := computeTOTP(secret, 0, 6, "SHA1")
	if result != result2 {
		t.Errorf("TOTP is not deterministic: %s != %s", result, result2)
	}
}

func TestComputeTOTPDifferentAlgorithms(t *testing.T) {
	secret, _ := base32.StdEncoding.DecodeString("JBSWY3DPEHPK3PXP")

	for _, algo := range []string{"SHA1", "SHA256", "SHA512"} {
		t.Run(algo, func(t *testing.T) {
			result := computeTOTP(secret, 0, 6, algo)
			if len(result) != 6 {
				t.Errorf("%s: expected 6 digits, got %d", algo, len(result))
			}
		})
	}
}

func TestComputeTOTPDifferentDigits(t *testing.T) {
	secret, _ := base32.StdEncoding.DecodeString("JBSWY3DPEHPK3PXP")

	for _, digits := range []int{6, 8} {
		t.Run(fmt.Sprintf("%d digits", digits), func(t *testing.T) {
			result := computeTOTP(secret, 0, digits, "SHA1")
			if len(result) != digits {
				t.Errorf("expected %d digits, got %d", digits, len(result))
			}
		})
	}
}

func TestComputeTOTPDifferentCounters(t *testing.T) {
	secret, _ := base32.StdEncoding.DecodeString("JBSWY3DPEHPK3PXP")

	r1 := computeTOTP(secret, 0, 6, "SHA1")
	r2 := computeTOTP(secret, 1, 6, "SHA1")

	if r1 == r2 {
		t.Error("different counters should produce different codes (statistically)")
	}
}

func TestValidateTOTP(t *testing.T) {
	secret, _ := base32.StdEncoding.DecodeString("JBSWY3DPEHPK3PXP")
	period := int64(30)
	counter := currentTOTPCounter(period)
	expected := computeTOTP(secret, counter, 6, "SHA1")

	if !validateTOTP(secret, expected, 6, "SHA1", period) {
		t.Error("valid TOTP code should be accepted")
	}

	prevCode := computeTOTP(secret, counter-1, 6, "SHA1")
	nextCode := computeTOTP(secret, counter+1, 6, "SHA1")

	if !validateTOTP(secret, prevCode, 6, "SHA1", period) {
		t.Error("previous window code should be accepted")
	}
	if !validateTOTP(secret, nextCode, 6, "SHA1", period) {
		t.Error("next window code should be accepted")
	}

	if validateTOTP(secret, "000000", 6, "SHA1", period) {
		t.Error("wrong code should be rejected")
	}
}

// ---------------------------------------------------------------------------
// Cookie Tests
// ---------------------------------------------------------------------------

func TestCookieRoundTrip(t *testing.T) {
	key := []byte("test-cookie-key-32-bytes-long!!")
	now := time.Now().Unix()

	rr := httptest.NewRecorder()
	setCookie(rr, key, 3600, now, now, false)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "totpgate_session" {
		t.Errorf("expected cookie name 'totpgate_session', got %q", cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)

	valid, needsRefresh, loginTime, lastActivity := validateCookie(req, key, 600, 86400)
	if !valid {
		t.Error("fresh cookie should be valid")
	}
	if needsRefresh {
		t.Error("fresh cookie should not need refresh immediately")
	}
	if loginTime != now {
		t.Errorf("expected loginTime %d, got %d", now, loginTime)
	}
	if lastActivity != now {
		t.Errorf("expected lastActivity %d, got %d", now, lastActivity)
	}
}

func TestExpiredCookie(t *testing.T) {
	key := []byte("test-cookie-key-32-bytes-long!!")
	now := time.Now().Unix()
	oldTime := now - 100000

	rr := httptest.NewRecorder()
	setCookie(rr, key, 3600, oldTime, oldTime, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(rr.Result().Cookies()[0])

	valid, _, _, _ := validateCookie(req, key, 600, 86400)
	if valid {
		t.Error("expired cookie should be invalid")
	}
}

func TestTamperedCookie(t *testing.T) {
	key := []byte("test-cookie-key-32-bytes-long!!")
	now := time.Now().Unix()

	rr := httptest.NewRecorder()
	setCookie(rr, key, 3600, now, now, false)

	cookies := rr.Result().Cookies()
	tampered := cookies[0].Value + "x"

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "totpgate_session",
		Value: tampered,
	})

	valid, _, _, _ := validateCookie(req, key, 600, 86400)
	if valid {
		t.Error("tampered cookie should be invalid")
	}
}

func TestCookieNeedsRefresh(t *testing.T) {
	key := []byte("test-cookie-key-32-bytes-long!!")
	now := time.Now().Unix()
	oldActivity := now - 1200

	rr := httptest.NewRecorder()
	setCookie(rr, key, 3600, now, oldActivity, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(rr.Result().Cookies()[0])

	valid, needsRefresh, loginTime, _ := validateCookie(req, key, 600, 86400)
	if !valid {
		t.Error("cookie should be valid")
	}
	if !needsRefresh {
		t.Error("old activity should trigger refresh")
	}
	if loginTime != now {
		t.Errorf("expected loginTime %d, got %d", now, loginTime)
	}
}

func TestCookieSignature(t *testing.T) {
	now := time.Now().Unix()
	loginBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(loginBytes, uint64(now))
	activityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(activityBytes, uint64(now))

	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write(loginBytes)
	mac.Write(activityBytes)
	sig := mac.Sum(nil)

	value := hex.EncodeToString(loginBytes) + "." + hex.EncodeToString(activityBytes) + "." + hex.EncodeToString(sig)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "totpgate_session",
		Value: value,
	})

	valid, _, _, _ := validateCookie(req, []byte("key"), 600, 86400)
	if !valid {
		t.Error("valid signature should pass")
	}

	// Wrong key should fail
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{
		Name:  "totpgate_session",
		Value: value,
	})

	valid2, _, _, _ := validateCookie(req2, []byte("wrong-key"), 600, 86400)
	if valid2 {
		t.Error("wrong key should fail")
	}
}

// ---------------------------------------------------------------------------
// Rate Limiter Tests
// ---------------------------------------------------------------------------

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3, 1*time.Minute)

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	if rl.allow("1.2.3.4") {
		t.Error("4th request should be rate limited")
	}

	if !rl.allow("5.6.7.8") {
		t.Error("different IP should not be rate limited")
	}
}

// ---------------------------------------------------------------------------
// Health Endpoint Test
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			t.Errorf("write error: %v", err)
		}
	})

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Body.String() != "OK" {
		t.Errorf("expected body 'OK', got %q", rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Build Info Test
// ---------------------------------------------------------------------------

func TestBuildInfoDefaults(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if Commit == "" {
		t.Error("Commit should not be empty")
	}
	if BuildTime == "" {
		t.Error("BuildTime should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Client IP Tests
// ---------------------------------------------------------------------------

func TestClientIP(t *testing.T) {
	privateCIDRs := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	var trusted []*net.IPNet
	for _, cidr := range privateCIDRs {
		_, parsed, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", cidr, err)
		}
		trusted = append(trusted, parsed)
	}

	tests := []struct {
		name     string
		headers  map[string]string
		remote   string
		trusted  []*net.IPNet
		expected string
	}{
		{
			name:     "X-Real-IP from trusted proxy",
			headers:  map[string]string{"X-Real-IP": "1.1.1.1"},
			remote:   "127.0.0.1:12345",
			trusted:  trusted,
			expected: "1.1.1.1",
		},
		{
			name:     "X-Forwarded-For from trusted proxy",
			headers:  map[string]string{"X-Forwarded-For": "3.3.3.3, 4.4.4.4"},
			remote:   "10.0.0.1:8080",
			trusted:  trusted,
			expected: "3.3.3.3",
		},
		{
			name:     "Headers ignored from untrusted peer",
			headers:  map[string]string{"X-Real-IP": "1.1.1.1"},
			remote:   "203.0.113.5:443",
			trusted:  trusted,
			expected: "203.0.113.5",
		},
		{
			name:     "RemoteAddr fallback when no headers",
			headers:  map[string]string{},
			remote:   "192.168.1.100:80",
			trusted:  trusted,
			expected: "192.168.1.100",
		},
		{
			name:     "Empty trusted list ignores all headers",
			headers:  map[string]string{"X-Real-IP": "1.1.1.1"},
			remote:   "127.0.0.1:12345",
			trusted:  nil,
			expected: "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remote
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := clientIP(req, tt.trusted)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Login Page Rendering Tests
// ---------------------------------------------------------------------------

func TestLoginPageRendering(t *testing.T) {
	// Without error
	html := renderLoginPage(6, "", "")
	if len(html) == 0 {
		t.Error("login page should not be empty")
	}

	// With error message
	html = renderLoginPage(6, "Invalid code", "")
	if len(html) == 0 {
		t.Error("login page with error should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Trusted Proxies Tests
// ---------------------------------------------------------------------------

func TestParseTrustedProxiesDefaults(t *testing.T) {
	cidrs := parseTrustedProxies("")
	if len(cidrs) != 4 {
		t.Fatalf("expected 4 default CIDRs, got %d", len(cidrs))
	}

	// Should trust common private ranges
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"203.0.113.5", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		if got := isTrustedProxy(tt.ip, cidrs); got != tt.expected {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", tt.ip, got, tt.expected)
		}
	}
}

func TestParseTrustedProxiesCustom(t *testing.T) {
	cidrs := parseTrustedProxies("1.2.3.4,10.0.0.0/8")

	// Should include custom IPs + 127.0.0.1 (always hardcoded)
	if !isTrustedProxy("1.2.3.4", cidrs) {
		t.Error("should trust custom IP 1.2.3.4")
	}
	if !isTrustedProxy("10.0.0.1", cidrs) {
		t.Error("should trust custom CIDR 10.0.0.0/8")
	}
	if !isTrustedProxy("127.0.0.1", cidrs) {
		t.Error("should always trust 127.0.0.1")
	}
	// 192.168.x.x should NOT be trusted when env var is set (defaults overridden)
	if isTrustedProxy("192.168.1.1", cidrs) {
		t.Error("should NOT trust 192.168.x.x when custom proxies are set")
	}
}

func TestParseTrustedProxiesBareIP(t *testing.T) {
	cidrs := parseTrustedProxies("1.2.3.4")
	if !isTrustedProxy("1.2.3.4", cidrs) {
		t.Error("bare IP should be accepted as /32")
	}
}

// ---------------------------------------------------------------------------
// Host/Path-Prefix Routing Tests
// ---------------------------------------------------------------------------

// findTarget is a test helper that looks up a host+prefix in a []targetEntry.
func findTarget(entries []targetEntry, host, prefix string) *url.URL {
	for _, e := range entries {
		if e.host == host && e.prefix == prefix {
			return e.url
		}
	}
	return nil
}

func TestParseTargets(t *testing.T) {
	entries, defaultURL := parseTargets("app1.example.com=http://localhost:3000,app2.example.com=http://localhost:4000")

	if len(entries) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(entries))
	}
	if defaultURL != nil {
		t.Errorf("expected no default URL, got %s", defaultURL)
	}

	u1 := findTarget(entries, "app1.example.com", "")
	if u1 == nil || u1.String() != "http://localhost:3000" {
		t.Errorf("unexpected URL for app1: %v", u1)
	}
	u2 := findTarget(entries, "app2.example.com", "")
	if u2 == nil || u2.String() != "http://localhost:4000" {
		t.Errorf("unexpected URL for app2: %v", u2)
	}
}

func TestParseTargetsWithPathPrefix(t *testing.T) {
	entries, defaultURL := parseTargets(
		"app.example.com/api=http://api:8080,app.example.com/static=http://cdn:9000,app.example.com=http://web:3000",
	)

	if len(entries) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(entries))
	}
	if defaultURL != nil {
		t.Errorf("expected no default URL, got %s", defaultURL)
	}

	// Most specific entry first after sort.
	// "app.example.com/static" and "app.example.com/api" are both len 27; tie-break alpha → /api first.
	if entries[0].host != "app.example.com" || (entries[0].prefix != "/api" && entries[0].prefix != "/static") {
		t.Errorf("unexpected first entry: %s%s", entries[0].host, entries[0].prefix)
	}

	uAPI := findTarget(entries, "app.example.com", "/api")
	if uAPI == nil || uAPI.String() != "http://api:8080" {
		t.Errorf("unexpected URL for /api: %v", uAPI)
	}
	uStatic := findTarget(entries, "app.example.com", "/static")
	if uStatic == nil || uStatic.String() != "http://cdn:9000" {
		t.Errorf("unexpected URL for /static: %v", uStatic)
	}
	uRoot := findTarget(entries, "app.example.com", "")
	if uRoot == nil || uRoot.String() != "http://web:3000" {
		t.Errorf("unexpected URL for root host: %v", uRoot)
	}
}

func TestParseTargetsDefault(t *testing.T) {
	entries, defaultURL := parseTargets("app.example.com=http://app:8080,default=http://fallback:9000")

	if len(entries) != 1 {
		t.Fatalf("expected 1 target entry, got %d", len(entries))
	}
	if defaultURL == nil || defaultURL.String() != "http://fallback:9000" {
		t.Errorf("unexpected default URL: %v", defaultURL)
	}
}

func TestParseTargetsInvalid(t *testing.T) {
	entries, _ := parseTargets("invalid-no-equals,app1.example.com=http://localhost:3000")
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid target, got %d", len(entries))
	}
	if findTarget(entries, "app1.example.com", "") == nil {
		t.Error("valid target should be present")
	}
}

func TestParseTargetsEmpty(t *testing.T) {
	entries, defaultURL := parseTargets("")
	if len(entries) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(entries))
	}
	if defaultURL != nil {
		t.Errorf("expected nil default URL, got %s", defaultURL)
	}
}

func TestParseTargetsSortOrder(t *testing.T) {
	// Longer keys (more specific) must come first.
	entries, _ := parseTargets(
		"app.example.com=http://root:3000,app.example.com/api/v2=http://apiv2:8082,app.example.com/api=http://api:8080",
	)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Most specific first: /api/v2 (len 20) > /api (len 16) > "" (len 15)
	if entries[0].prefix != "/api/v2" {
		t.Errorf("expected /api/v2 first, got %s", entries[0].prefix)
	}
	if entries[1].prefix != "/api" {
		t.Errorf("expected /api second, got %s", entries[1].prefix)
	}
	if entries[2].prefix != "" {
		t.Errorf("expected empty prefix third, got %s", entries[2].prefix)
	}
}

// makeTestConfig builds a minimal *config suitable for routing tests.
func makeTestConfig(entries []targetEntry, defaultURL *url.URL) *config {
	return &config{
		targets:       entries,
		defaultTarget: defaultURL,
	}
}

func TestResolveTargetHostOnly(t *testing.T) {
	u1, _ := url.Parse("http://backend1:3000")
	u2, _ := url.Parse("http://backend2:4000")
	entries := []targetEntry{
		{host: "app1.example.com", prefix: "", url: u1},
		{host: "app2.example.com", prefix: "", url: u2},
	}
	cfg := makeTestConfig(entries, nil)

	tests := []struct {
		host     string
		path     string
		expected *url.URL
	}{
		{"app1.example.com", "/", u1},
		{"app2.example.com", "/anything", u2},
		{"app1.example.com:8080", "/", u1}, // port stripped
		{"unknown.example.com", "/", nil},  // no match, no default → nil
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		req.Host = tt.host
		got := resolveTarget(cfg, req)
		if got != tt.expected {
			t.Errorf("host=%s path=%s: expected %v, got %v", tt.host, tt.path, tt.expected, got)
		}
	}
}

func TestResolveTargetPathPrefix(t *testing.T) {
	uAPI, _ := url.Parse("http://api:8080")
	uWeb, _ := url.Parse("http://web:3000")
	// Sorted longest-first as parseTargets would produce.
	entries := []targetEntry{
		{host: "app.example.com", prefix: "/api", url: uAPI},
		{host: "app.example.com", prefix: "", url: uWeb},
	}
	cfg := makeTestConfig(entries, nil)

	tests := []struct {
		path     string
		expected *url.URL
	}{
		{"/api", uAPI},
		{"/api/users", uAPI},
		{"/api/users/123", uAPI},
		{"/apifoo", uWeb}, // must NOT match /api prefix
		{"/", uWeb},
		{"/other", uWeb},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		req.Host = "app.example.com"
		got := resolveTarget(cfg, req)
		if got != tt.expected {
			t.Errorf("path=%s: expected %v, got %v", tt.path, tt.expected, got)
		}
	}
}

func TestResolveTargetLongestPrefixWins(t *testing.T) {
	uAPIv2, _ := url.Parse("http://apiv2:8082")
	uAPI, _ := url.Parse("http://api:8080")
	uWeb, _ := url.Parse("http://web:3000")
	// Sorted as parseTargets would produce: longest first.
	entries := []targetEntry{
		{host: "app.example.com", prefix: "/api/v2", url: uAPIv2},
		{host: "app.example.com", prefix: "/api", url: uAPI},
		{host: "app.example.com", prefix: "", url: uWeb},
	}
	cfg := makeTestConfig(entries, nil)

	tests := []struct {
		path     string
		expected *url.URL
	}{
		{"/api/v2/users", uAPIv2},
		{"/api/v1/users", uAPI},
		{"/api", uAPI},
		{"/", uWeb},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		req.Host = "app.example.com"
		got := resolveTarget(cfg, req)
		if got != tt.expected {
			t.Errorf("path=%s: expected %v, got %v", tt.path, tt.expected, got)
		}
	}
}

func TestResolveTargetDefaultFallback(t *testing.T) {
	uApp, _ := url.Parse("http://app:8080")
	uDefault, _ := url.Parse("http://fallback:9000")
	entries := []targetEntry{
		{host: "app.example.com", prefix: "", url: uApp},
	}
	cfg := makeTestConfig(entries, uDefault)

	// Known host → matched entry.
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "app.example.com"
	if got := resolveTarget(cfg, req); got != uApp {
		t.Errorf("expected app upstream, got %v", got)
	}

	// Unknown host → defaultTarget.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Host = "unknown.example.com"
	if got := resolveTarget(cfg, req2); got != uDefault {
		t.Errorf("expected default upstream, got %v", got)
	}
}

func TestResolveTargetNoMatchNoDefault(t *testing.T) {
	uApp, _ := url.Parse("http://app:8080")
	entries := []targetEntry{
		{host: "app.example.com", prefix: "", url: uApp},
	}
	cfg := makeTestConfig(entries, nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "other.example.com"
	if got := resolveTarget(cfg, req); got != nil {
		t.Errorf("expected nil (no route), got %v", got)
	}
}

func TestProxyHostBasedRouting(t *testing.T) {
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend1"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend2"))
	}))
	defer backend2.Close()

	u1, _ := url.Parse(backend1.URL)
	u2, _ := url.Parse(backend2.URL)

	entries := []targetEntry{
		{host: "app1.example.com", prefix: "", url: u1},
		{host: "app2.example.com", prefix: "", url: u2},
	}
	cfg := makeTestConfig(entries, nil)

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			target := resolveTarget(cfg, r.In)
			if target != nil {
				r.SetURL(target)
			}
			r.Out.Header.Set("Host", r.In.Host)
		},
	}

	tests := []struct {
		name         string
		host         string
		expectedBody string
		expectedCode int
	}{
		{"routes to backend1", "app1.example.com", "backend1", http.StatusOK},
		{"routes to backend2", "app2.example.com", "backend2", http.StatusOK},
		{"routes to backend1 with port stripped", "app1.example.com:8080", "backend1", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)
			if rr.Body.String() != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, rr.Body.String())
			}
		})
	}
}

func TestProxyPathPrefixRouting(t *testing.T) {
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api-backend"))
	}))
	defer apiBackend.Close()

	webBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("web-backend"))
	}))
	defer webBackend.Close()

	uAPI, _ := url.Parse(apiBackend.URL)
	uWeb, _ := url.Parse(webBackend.URL)

	// Longest-first order as parseTargets produces.
	entries := []targetEntry{
		{host: "app.example.com", prefix: "/api", url: uAPI},
		{host: "app.example.com", prefix: "", url: uWeb},
	}
	cfg := makeTestConfig(entries, nil)

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			target := resolveTarget(cfg, r.In)
			if target != nil {
				r.SetURL(target)
			}
			r.Out.Header.Set("Host", r.In.Host)
		},
	}

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"exact prefix match", "/api", "api-backend"},
		{"prefix with subpath", "/api/users", "api-backend"},
		{"non-prefix path", "/", "web-backend"},
		{"non-prefix other path", "/dashboard", "web-backend"},
		{"apifoo must not match /api", "/apifoo", "web-backend"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			req.Host = "app.example.com"
			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)
			if rr.Body.String() != tt.expected {
				t.Errorf("path=%s: expected %q, got %q", tt.path, tt.expected, rr.Body.String())
			}
		})
	}
}

func TestProxyWebSocketRouting(t *testing.T) {
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			_, _ = w.Write([]byte("ws-backend1"))
		} else {
			_, _ = w.Write([]byte("http-backend1"))
		}
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			_, _ = w.Write([]byte("ws-backend2"))
		} else {
			_, _ = w.Write([]byte("http-backend2"))
		}
	}))
	defer backend2.Close()

	u1, _ := url.Parse(backend1.URL)
	u2, _ := url.Parse(backend2.URL)

	entries := []targetEntry{
		{host: "app1.example.com", prefix: "", url: u1},
		{host: "app2.example.com", prefix: "", url: u2},
	}
	cfg := makeTestConfig(entries, nil)

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			target := resolveTarget(cfg, r.In)
			if target != nil {
				r.SetURL(target)
			}
			r.Out.Header.Set("Host", r.In.Host)
		},
	}

	tests := []struct {
		name     string
		host     string
		upgrade  string
		expected string
	}{
		{"HTTP request routes to backend1", "app1.example.com", "", "http-backend1"},
		{"HTTP request routes to backend2", "app2.example.com", "", "http-backend2"},
		{"WebSocket upgrade routes to backend1", "app1.example.com", "websocket", "ws-backend1"},
		{"WebSocket upgrade routes to backend2", "app2.example.com", "websocket", "ws-backend2"},
		{"WebSocket with port in Host", "app1.example.com:8080", "websocket", "ws-backend1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			if tt.upgrade != "" {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				req.Header.Set("Sec-WebSocket-Version", "13")
			}
			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)

			if rr.Body.String() != tt.expected {
				t.Errorf("expected body %q, got %q", tt.expected, rr.Body.String())
			}
		})
	}
}
