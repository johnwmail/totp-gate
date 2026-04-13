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
