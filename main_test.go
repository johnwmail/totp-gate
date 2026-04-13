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
	html := renderLoginPage(6, "")
	if len(html) == 0 {
		t.Error("login page should not be empty")
	}

	// With error message
	html = renderLoginPage(6, "Invalid code")
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
// Host-Based Routing Tests
// ---------------------------------------------------------------------------

func TestParseTargets(t *testing.T) {
	targets := parseTargets("app1.example.com=http://localhost:3000,app2.example.com=http://localhost:4000")

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	if targets["app1.example.com"].String() != "http://localhost:3000" {
		t.Errorf("unexpected URL for app1: %s", targets["app1.example.com"].String())
	}
	if targets["app2.example.com"].String() != "http://localhost:4000" {
		t.Errorf("unexpected URL for app2: %s", targets["app2.example.com"].String())
	}
}

func TestParseTargetsInvalid(t *testing.T) {
	targets := parseTargets("invalid-no-equals,app1.example.com=http://localhost:3000")
	if len(targets) != 1 {
		t.Fatalf("expected 1 valid target, got %d", len(targets))
	}
	if _, ok := targets["app1.example.com"]; !ok {
		t.Error("valid target should be present")
	}
}

func TestParseTargetsEmpty(t *testing.T) {
	targets := parseTargets("")
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(targets))
	}
}

func TestProxyHostBasedRouting(t *testing.T) {
	// Create two test backends
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend1"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend2"))
	}))
	defer backend2.Close()

	u1, _ := url.Parse(backend1.URL)
	u2, _ := url.Parse(backend2.URL)

	targets := map[string]*url.URL{
		"app1.example.com": u1,
		"app2.example.com": u2,
	}

	// Create proxy with dynamic routing using Rewrite only.
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Default to first target (fallback).
			r.SetURL(u1)
			if len(targets) > 0 {
				host := r.In.Host
				if host == "" {
					host = r.In.Header.Get("Host")
				}
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				if target, ok := targets[host]; ok {
					r.SetURL(target)
				}
			}
			r.Out.Header.Set("Host", r.In.Host)
		},
	}

	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "routes to backend1",
			host:     "app1.example.com",
			expected: "backend1",
		},
		{
			name:     "routes to backend2",
			host:     "app2.example.com",
			expected: "backend2",
		},
		{
			name:     "routes to backend1 with port stripped",
			host:     "app1.example.com:8080",
			expected: "backend1",
		},
		{
			name:     "unknown host falls back to first target",
			host:     "unknown.example.com",
			expected: "backend1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)

			if rr.Body.String() != tt.expected {
				t.Errorf("expected body %q, got %q", tt.expected, rr.Body.String())
			}
		})
	}
}

func TestProxyWebSocketRouting(t *testing.T) {
	// Create two backends that detect WebSocket upgrades
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.Write([]byte("ws-backend1"))
		} else {
			w.Write([]byte("http-backend1"))
		}
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.Write([]byte("ws-backend2"))
		} else {
			w.Write([]byte("http-backend2"))
		}
	}))
	defer backend2.Close()

	u1, _ := url.Parse(backend1.URL)
	u2, _ := url.Parse(backend2.URL)

	targets := map[string]*url.URL{
		"app1.example.com": u1,
		"app2.example.com": u2,
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u1)
			if len(targets) > 0 {
				host := r.In.Host
				if host == "" {
					host = r.In.Header.Get("Host")
				}
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				if target, ok := targets[host]; ok {
					r.SetURL(target)
				}
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
		{
			name:     "HTTP request routes to backend1",
			host:     "app1.example.com",
			upgrade:  "",
			expected: "http-backend1",
		},
		{
			name:     "HTTP request routes to backend2",
			host:     "app2.example.com",
			upgrade:  "",
			expected: "http-backend2",
		},
		{
			name:     "WebSocket upgrade routes to backend1",
			host:     "app1.example.com",
			upgrade:  "websocket",
			expected: "ws-backend1",
		},
		{
			name:     "WebSocket upgrade routes to backend2",
			host:     "app2.example.com",
			upgrade:  "websocket",
			expected: "ws-backend2",
		},
		{
			name:     "WebSocket with port in Host",
			host:     "app1.example.com:8080",
			upgrade:  "websocket",
			expected: "ws-backend1",
		},
		{
			name:     "Unknown host falls back to first target (WebSocket)",
			host:     "unknown.example.com",
			upgrade:  "websocket",
			expected: "ws-backend1",
		},
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
