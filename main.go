package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Build info (injected at compile time via -ldflags)
// ---------------------------------------------------------------------------

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// targetEntry represents a single routing rule in multi-target mode.
// Entries with a path prefix (e.g. host="/api") take precedence over
// host-only entries; the slice is sorted longest-match-first at parse time.
type targetEntry struct {
	host   string   // e.g. "app.example.com" (port-stripped)
	prefix string   // e.g. "/api" — empty means match all paths for this host
	url    *url.URL // upstream to forward to
}

type config struct {
	listenAddr         string
	upstreamURL        *url.URL      // fallback (single-target mode)
	targets            []targetEntry // sorted routing rules (multi-target mode)
	defaultTarget      *url.URL      // explicit default for unmatched requests in multi-target mode
	totpSecret         []byte        // raw bytes (decoded from base32)
	totpPeriod         int64
	totpDigits         int
	totpAlgo           string // "SHA1", "SHA256", "SHA512"
	cookieTTL          int    // max session lifetime (seconds)
	cookieSecure       bool   // secure flag on cookies
	refreshInterval    int    // activity refresh interval (seconds)
	authDisabled       bool
	cookieKey          []byte // derived from totpSecret
	trustedProxies     []*net.IPNet
	insecureSkipVerify bool // skip upstream TLS cert verification
}

func loadConfig() *config {
	c := &config{}

	c.listenAddr = parseListenAddr(envOrDefault("TOTPGATE_AUTH_LISTEN", "0.0.0.0:8080"))

	// Parse multi-target routing if set, otherwise fall back to single upstream.
	// Format: "host/path=http://backend:port,host=http://fallback:port,default=http://default:port"
	targetsEnv := os.Getenv("TOTPGATE_TARGETS")
	if targetsEnv != "" {
		var defaultURL *url.URL
		c.targets, defaultURL = parseTargets(targetsEnv)
		if len(c.targets) == 0 && defaultURL == nil {
			log.Fatalf("TOTPGATE_TARGETS is set but no valid targets were parsed")
		}
		c.defaultTarget = defaultURL
		// In single-upstream mode (used when no targets match and no defaultTarget),
		// upstreamURL stays nil — the proxy handler will return 404.
	} else {
		upstream := envOrDefault("TOTPGATE_UPSTREAM", "http://localhost:3000")
		u, err := url.Parse(upstream)
		if err != nil {
			log.Fatalf("invalid TOTPGATE_UPSTREAM %q: %v", upstream, err)
		}
		c.upstreamURL = u
	}

	c.authDisabled = strings.EqualFold(os.Getenv("TOTPGATE_AUTH_DISABLED"), "true")

	c.insecureSkipVerify = strings.EqualFold(os.Getenv("TOTPGATE_INSECURE_SKIP_VERIFY"), "true")

	// Allow configuring cookie Secure flag (default true for HTTPS deployments)
	cookieSecureEnv := os.Getenv("TOTPGATE_AUTH_COOKIE_SECURE")
	c.cookieSecure = !strings.EqualFold(cookieSecureEnv, "false")

	// Parse trusted proxies: always include 127.0.0.1.
	// If TOTPGATE_TRUSTED_PROXIES is not set, default to all private ranges.
	// If set, use the specified values + 127.0.0.1.
	c.trustedProxies = parseTrustedProxies(os.Getenv("TOTPGATE_TRUSTED_PROXIES"))

	if !c.authDisabled {
		// Load TOTP secret: file first (more secure), then env var (backward compatible)
		secretB32, err := loadTOTPSecret()
		if err != nil {
			log.Fatal(err)
		}
		// Be lenient with padding
		secretB32 = strings.TrimRight(strings.ToUpper(secretB32), "=")
		// Add padding
		if m := len(secretB32) % 8; m != 0 {
			secretB32 += strings.Repeat("=", 8-m)
		}
		raw, err := base32.StdEncoding.DecodeString(secretB32)
		if err != nil {
			log.Fatalf("failed to decode TOTPGATE_TOTP_SECRET: %v", err)
		}
		c.totpSecret = raw
	}

	c.totpPeriod = int64(envOrDefaultInt("TOTPGATE_TOTP_PERIOD", 30))
	c.totpDigits = envOrDefaultInt("TOTPGATE_TOTP_DIGITS", 6)
	c.totpAlgo = strings.ToUpper(envOrDefault("TOTPGATE_TOTP_ALGORITHM", "SHA1"))
	c.cookieTTL = envOrDefaultInt("TOTPGATE_AUTH_COOKIE_TTL", 86400)
	c.refreshInterval = envOrDefaultInt("TOTPGATE_AUTH_REFRESH_INTERVAL", 600)

	switch c.totpAlgo {
	case "SHA1", "SHA256", "SHA512":
	default:
		log.Fatalf("unsupported TOTPGATE_TOTP_ALGORITHM %q", c.totpAlgo)
	}

	// Derive cookie signing key from TOTP secret + random nonce.
	// The nonce is generated fresh each startup, so all sessions are
	// invalidated when the container restarts.
	if len(c.totpSecret) > 0 {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			log.Fatalf("failed to generate random nonce: %v", err)
		}
		mac := hmac.New(sha256.New, c.totpSecret)
		mac.Write([]byte("totpgate-cookie-key"))
		mac.Write(nonce)
		c.cookieKey = mac.Sum(nil)
		log.Printf("  cookie nonce generated (sessions reset on restart)")
	}

	return c
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseListenAddr(v string) string {
	if strings.HasPrefix(v, ":") {
		return "0.0.0.0" + v
	}
	if _, err := strconv.Atoi(v); err == nil {
		return "0.0.0.0:" + v
	}
	return v
}

// loadTOTPSecret loads the TOTP secret from file (preferred) or environment variable.
// Priority: 1) /run/secrets/totpgate_totp_secret, 2) TOTPGATE_TOTP_SECRET env var
func loadTOTPSecret() (string, error) {
	// Try file first (more secure - not visible in environment)
	secretFile := envOrDefault("TOTPGATE_TOTP_SECRET_FILE", "/run/secrets/totpgate_totp_secret")
	if data, err := os.ReadFile(secretFile); err == nil {
		secret := strings.TrimSpace(string(data))
		if secret != "" {
			log.Printf("  loaded TOTP secret from file: %s", secretFile)
			return secret, nil
		}
	}

	// Fallback to environment variable (backward compatible)
	if secret := os.Getenv("TOTPGATE_TOTP_SECRET"); secret != "" {
		log.Printf("  loaded TOTP secret from environment variable")
		return secret, nil
	}

	return "", fmt.Errorf("TOTP secret not found: set TOTPGATE_TOTP_SECRET or mount %s", secretFile)
}

func envOrDefaultInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("invalid integer for %s=%q: %v", key, v, err)
	}
	return n
}

// parseTrustedProxies builds the list of trusted proxy networks.
// Always includes 127.0.0.1. If env var is empty, defaults to all private ranges.
// If set, parses comma-separated CIDRs/IPs and appends 127.0.0.1.
func parseTrustedProxies(env string) []*net.IPNet {
	var cidrs []*net.IPNet

	if env == "" {
		// Default: all RFC 1918 private ranges + loopback
		for _, cidr := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
			_, parsed, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Fatalf("internal error: invalid default CIDR %q: %v", cidr, err)
			}
			cidrs = append(cidrs, parsed)
		}
		return cidrs
	}

	// Parse user-specified proxies
	for _, entry := range strings.Split(env, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Accept bare IPs as /32 CIDRs
		if !strings.Contains(entry, "/") {
			entry += "/32"
		}
		_, parsed, err := net.ParseCIDR(entry)
		if err != nil {
			log.Fatalf("invalid TOTPGATE_TRUSTED_PROXIES entry %q: %v", entry, err)
		}
		cidrs = append(cidrs, parsed)
	}

	// Always ensure 127.0.0.1 is included
	_, loopback, _ := net.ParseCIDR("127.0.0.1/32")
	cidrs = append(cidrs, loopback)

	return cidrs
}

// isTrustedProxy checks if the given IP matches any trusted proxy network.
func isTrustedProxy(ipStr string, trusted []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range trusted {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveTarget returns the upstream URL for the given request in multi-target mode.
// It matches entries in order (longest/most-specific first).
// Returns nil if no entry matches and no defaultTarget is configured.
func resolveTarget(cfg *config, r *http.Request) *url.URL {
	if len(cfg.targets) == 0 {
		return cfg.upstreamURL
	}

	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	reqPath := r.URL.Path

	for _, entry := range cfg.targets {
		if entry.host != host {
			continue
		}
		// Host-only entry (empty prefix) matches all paths for this host.
		// Prefix entry matches when the path starts with the prefix and
		// is followed by '/' or end-of-string (prevents /apifoo matching /api).
		if entry.prefix == "" ||
			(strings.HasPrefix(reqPath, entry.prefix) &&
				(len(reqPath) == len(entry.prefix) || reqPath[len(entry.prefix)] == '/')) {
			return entry.url
		}
	}

	// No specific rule matched — fall back to defaultTarget (may be nil).
	return cfg.defaultTarget
}

// parseTargets parses the TOTPGATE_TARGETS env var into a sorted slice of
// targetEntry and an optional default upstream URL.
//
// Supported key formats:
//
//	host                     → matches any path on that host
//	host/path-prefix         → matches requests on host whose path has the given prefix
//	default                  → catchall upstream used when no entry matches
//
// Example:
//
//	app.example.com/api=http://api:8080,app.example.com=http://web:3000,default=http://fallback:9000
//
// Rules are sorted longest-key-first so that more specific entries win.
// Duplicate keys (same host+prefix) cause a fatal error.
func parseTargets(env string) ([]targetEntry, *url.URL) {
	var entries []targetEntry
	var defaultURL *url.URL
	seen := make(map[string]bool)

	for _, raw := range strings.Split(env, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			log.Printf("warning: skipping invalid target %q (expected key=upstream)", raw)
			continue
		}
		key := strings.TrimSpace(parts[0])
		upstreamRaw := strings.TrimSpace(parts[1])

		upstreamURL, err := url.Parse(upstreamRaw)
		if err != nil {
			log.Printf("warning: skipping target %q: invalid upstream URL: %v", key, err)
			continue
		}

		// Special "default" key sets the catchall fallback.
		if strings.EqualFold(key, "default") {
			if defaultURL != nil {
				log.Fatalf("duplicate default target in TOTPGATE_TARGETS")
			}
			defaultURL = upstreamURL
			continue
		}

		// Split key into host and optional path prefix on the first '/'.
		var host, prefix string
		if idx := strings.Index(key, "/"); idx >= 0 {
			host = key[:idx]
			prefix = key[idx:] // keeps leading '/'
		} else {
			host = key
			prefix = ""
		}
		host = strings.TrimSpace(host)
		// Normalise: ensure prefix ends without a trailing slash (except root "/")
		if len(prefix) > 1 {
			prefix = strings.TrimRight(prefix, "/")
		}

		dupKey := host + prefix
		if seen[dupKey] {
			log.Fatalf("duplicate target %q in TOTPGATE_TARGETS", key)
		}
		seen[dupKey] = true

		entries = append(entries, targetEntry{host: host, prefix: prefix, url: upstreamURL})
	}

	// Sort longest (most specific) first: compare host+prefix length descending.
	sort.Slice(entries, func(i, j int) bool {
		li := len(entries[i].host) + len(entries[i].prefix)
		lj := len(entries[j].host) + len(entries[j].prefix)
		if li != lj {
			return li > lj
		}
		// Tie-break alphabetically for deterministic output.
		ki := entries[i].host + entries[i].prefix
		kj := entries[j].host + entries[j].prefix
		return ki < kj
	})

	return entries, defaultURL
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238 with configurable period)
// ---------------------------------------------------------------------------

func computeTOTP(secret []byte, counter int64, digits int, algorithm string) string {
	// Counter to big-endian 8 bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	var h func() hash.Hash
	switch algorithm {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}

	mac := hmac.New(h, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation
	offset := int(sum[len(sum)-1] & 0x0f)
	code := int64(binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff)

	mod := int64(math.Pow10(digits))
	code = code % mod

	return fmt.Sprintf("%0*d", digits, code)
}

func currentTOTPCounter(period int64) int64 {
	return time.Now().Unix() / period
}

// validateTOTP checks the provided code against the current, previous, and next
// time windows to handle clock skew and submission timing issues (RFC 6238).
func validateTOTP(secret []byte, code string, digits int, algo string, period int64) bool {
	counter := currentTOTPCounter(period)

	// Check current, previous, and next window (±1 tolerance)
	for _, offset := range []int64{-1, 0, 1} {
		expected := computeTOTP(secret, counter+offset, digits, algo)
		if hmac.Equal([]byte(code), []byte(expected)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

// setCookie creates a session cookie with expiry and timestamps.
// Format: <loginTime_hex>.<lastActivity_hex>.<signature_hex>
func setCookie(w http.ResponseWriter, cookieKey []byte, maxAge int, loginTime int64, lastActivity int64, secure bool) {
	loginBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(loginBytes, uint64(loginTime))

	activityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(activityBytes, uint64(lastActivity))

	mac := hmac.New(sha256.New, cookieKey)
	mac.Write(loginBytes)
	mac.Write(activityBytes)
	sig := mac.Sum(nil)

	value := hex.EncodeToString(loginBytes) + "." + hex.EncodeToString(activityBytes) + "." + hex.EncodeToString(sig)

	http.SetCookie(w, &http.Cookie{
		Name:     "totpgate_session",
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// validateCookie checks the session cookie and returns (valid, needsRefresh, loginTime, lastActivity).
// needsRefresh is true if the session is valid but should be refreshed (last activity > refreshInterval ago).
func validateCookie(r *http.Request, cookieKey []byte, refreshInterval int, maxLifetime int) (bool, bool, int64, int64) {
	c, err := r.Cookie("totpgate_session")
	if err != nil {
		return false, false, 0, 0
	}

	parts := strings.SplitN(c.Value, ".", 3)
	if len(parts) != 3 {
		return false, false, 0, 0
	}

	loginBytes, err := hex.DecodeString(parts[0])
	if err != nil || len(loginBytes) != 8 {
		return false, false, 0, 0
	}

	activityBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(activityBytes) != 8 {
		return false, false, 0, 0
	}

	sigBytes, err := hex.DecodeString(parts[2])
	if err != nil {
		return false, false, 0, 0
	}

	// Verify HMAC
	mac := hmac.New(sha256.New, cookieKey)
	mac.Write(loginBytes)
	mac.Write(activityBytes)
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(sigBytes, expectedSig) {
		return false, false, 0, 0
	}

	loginTime := int64(binary.BigEndian.Uint64(loginBytes))
	lastActivity := int64(binary.BigEndian.Uint64(activityBytes))
	now := time.Now().Unix()

	// Check if session has exceeded max lifetime (24h from login)
	if now-loginTime > int64(maxLifetime) {
		// Session expired - max lifetime exceeded
		return false, false, 0, 0
	}

	// Check if refresh is needed (activity older than refreshInterval)
	needsRefresh := (now - lastActivity) > int64(refreshInterval)

	return true, needsRefresh, loginTime, lastActivity
}

// ---------------------------------------------------------------------------
// Rate limiter (per-IP, in-memory)
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	max      int
	window   time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		attempts: make(map[string][]time.Time),
		max:      max,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter old entries
	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.max {
		rl.attempts[ip] = recent
		return false
	}

	rl.attempts[ip] = append(recent, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rl.window)
		for ip, times := range rl.attempts {
			var recent []time.Time
			for _, t := range times {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(rl.attempts, ip)
			} else {
				rl.attempts[ip] = recent
			}
		}
		rl.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Login page HTML
// ---------------------------------------------------------------------------

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TOTP Gate Login</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #1a1a2e;
    color: #e0e0e0;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 1rem;
  }
  .card {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 12px;
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  @media (max-width: 420px) {
    .card { padding: 2rem 1.25rem; border-radius: 8px; }
  }
  h1 {
    text-align: center;
    font-size: 1.5rem;
    margin-bottom: 0.5rem;
    color: #e94560;
  }
  .error {
    background: rgba(233,69,96,0.15);
    border: 1px solid #e94560;
    color: #e94560;
    padding: 0.6rem 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
    text-align: center;
    font-size: 0.9rem;
  }
  label {
    display: block;
    margin-bottom: 0.4rem;
    font-size: 0.9rem;
    color: #a0a0b8;
  }
  input[type="text"] {
    width: 100%;
    padding: 0.75rem 1rem;
    border: 1px solid #0f3460;
    border-radius: 6px;
    background: #1a1a2e;
    color: #e0e0e0;
    font-size: 1.25rem;
    letter-spacing: 0.5em;
    text-align: center;
    outline: none;
    transition: border-color 0.2s;
  }
  input[type="text"]:focus {
    border-color: #e94560;
  }
  button {
    width: 100%;
    margin-top: 1.25rem;
    padding: 0.75rem;
    border: none;
    border-radius: 6px;
    background: #e94560;
    color: #fff;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }
  button:hover { background: #c73652; }
  .access-url {
    text-align: center;
    font-size: 1rem;
    color: #a0a0b8;
    margin-top: 0;
    margin-bottom: 1.25rem;
    word-break: break-all;
    padding: 0.5rem 0.75rem;
    background: #0d1b2e;
    border: 1px solid #1a3a5c;
    border-radius: 6px;
  }
  .access-url a { color: #7ab3e0; text-decoration: underline; }
  .access-url a:hover { color: #add4f5; }
</style>
</head>
<body>
<div class="card">
  <h1>TOTP Gate Login</h1>
  {{ACCESS_URL}}
  {{ERROR}}
  <form method="POST" action="/totp-gate/login" autocomplete="off">
    <label for="code">Authentication Code</label>
    <input type="text" id="code" name="code" maxlength="{{DIGITS}}" pattern="[0-9]*" inputmode="numeric" autofocus required>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>`

func renderLoginPage(digits int, errMsg string, accessURL string) []byte {
	html := loginPageHTML
	html = strings.ReplaceAll(html, "{{DIGITS}}", strconv.Itoa(digits))
	if errMsg != "" {
		html = strings.ReplaceAll(html, "{{ERROR}}", `<div class="error">`+errMsg+`</div>`)
	} else {
		html = strings.ReplaceAll(html, "{{ERROR}}", "")
	}
	if accessURL != "" {
		displayURL := accessURL
		if parsed, err := url.Parse(accessURL); err == nil && (parsed.Path == "" || parsed.Path == "/") && parsed.RawQuery == "" {
			displayURL = parsed.Scheme + "://" + parsed.Host
		}
		display := truncateURL(displayURL, 60)
		html = strings.ReplaceAll(html, "{{ACCESS_URL}}", `<p class="access-url">`+display+`</p>`)
	} else {
		html = strings.ReplaceAll(html, "{{ACCESS_URL}}", "")
	}
	return []byte(html)
}

// truncateURL shortens a URL to at most maxLen characters by replacing the
// middle with "…", keeping the head and tail roughly equal in length.
// If the URL is already within maxLen it is returned unchanged.
func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	tail := maxLen / 2
	head := maxLen - tail - 1 // 1 for the ellipsis character
	return u[:head] + "…" + u[len(u)-tail:]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func logRequest(r *http.Request, status int, msg string) {
	log.Printf("[%s] %s %s %d - %s", time.Now().Format(time.RFC3339), r.Method, r.URL.Path, status, msg)
}

func clientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// Only trust forwarded headers when the immediate peer is a trusted proxy.
	if isTrustedProxy(host, trustedProxies) {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return ip
		}
		if ff := r.Header.Get("X-Forwarded-For"); ff != "" {
			return strings.TrimSpace(strings.SplitN(ff, ",", 2)[0])
		}
	}
	return host
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func printHelp() {
	fmt.Println(`TOTP Gate - TOTP-authenticated reverse proxy

Usage:
  totp-gate [options]

Options:
  -h, --help    Show this help message

Environment Variables:
  TOTPGATE_AUTH_LISTEN              Listen address, port or ip:port (default: 0.0.0.0:8080)
  TOTPGATE_UPSTREAM                Upstream URL (default: http://localhost:3000)
  TOTPGATE_TARGETS                 Multi-target mode: host=url,host/path-prefix=url,default=url
                                   Keys: "host", "host/path-prefix", or "default" (catchall fallback).
                                   More specific (longer) rules take precedence.
                                   Duplicate keys cause a startup error.
                                   Unmatched requests return 404 when no default is set.
  TOTPGATE_TOTP_SECRET             TOTP secret (base32 encoded, required)
  TOTPGATE_TOTP_SECRET_FILE        Path to TOTP secret file (recommended)
  TOTPGATE_TOTP_PERIOD             TOTP period in seconds (default: 30)
  TOTPGATE_TOTP_DIGITS             TOTP code length (default: 6)
  TOTPGATE_TOTP_ALGORITHM          TOTP algorithm: SHA1, SHA256, SHA512 (default: SHA1)
  TOTPGATE_AUTH_COOKIE_TTL         Session max lifetime in seconds (default: 86400)
  TOTPGATE_AUTH_COOKIE_SECURE      Set cookie Secure flag (default: true)
  TOTPGATE_AUTH_REFRESH_INTERVAL   Activity refresh interval in seconds (default: 600)
  TOTPGATE_AUTH_DISABLED           Disable authentication (for testing)
  TOTPGATE_TRUSTED_PROXIES         Comma-separated list of trusted proxy IPs/CIDRs
  TOTPGATE_INSECURE_SKIP_VERIFY    Skip upstream TLS certificate verification

Examples:
  # With secret from environment
  TOTPGATE_TOTP_SECRET=JBSWY3DPEHPK3PXP totp-gate

  # With secret from file (recommended)
  TOTPGATE_TOTP_SECRET_FILE=/run/secrets/totp totp-gate

  # Custom listen address and upstream
  TOTPGATE_AUTH_LISTEN=0.0.0.0:9000 TOTPGATE_UPSTREAM=http://backend:8080 totp-gate

  # Multi-target routing by host only
  TOTPGATE_TARGETS="app1.example.com=http://app1:8080,app2.example.com=http://app2:8080" totp-gate

  # Multi-target routing with path-prefix rules (more specific rules win)
  TOTPGATE_TARGETS="app.example.com/api=http://api:8080,app.example.com/static=http://cdn:9000,app.example.com=http://web:3000" totp-gate

  # Multi-target routing with explicit default fallback for unmatched requests
  TOTPGATE_TARGETS="app.example.com/api=http://api:8080,default=http://fallback:3000" totp-gate

Version: ` + Version + `, Commit: ` + Commit + `, Built: ` + BuildTime)
}

func main() {
	flag.Usage = func() { printHelp() }
	flag.Parse()

	if flag.NArg() > 0 {
		printHelp()
		os.Exit(1)
	}

	cfg := loadConfig()

	log.Printf("totp-gate starting version=%s commit=%s built=%s", Version, Commit, BuildTime)
	log.Printf("  listen:          %s", cfg.listenAddr)

	if len(cfg.targets) > 0 {
		// Multi-target mode: show sorted routing table (most-specific first).
		log.Printf("  targets (%d, sorted longest-match-first):", len(cfg.targets))
		for _, e := range cfg.targets {
			key := e.host + e.prefix
			if key == "" {
				key = "(default)"
			}
			log.Printf("    %-40s → %s", key, e.url.String())
		}
		if cfg.defaultTarget != nil {
			log.Printf("    %-40s → %s", "default", cfg.defaultTarget.String())
		} else {
			log.Printf("    %-40s → %s", "default", "(none — unmatched requests return 404)")
		}
	} else {
		log.Printf("  upstream:        %s", cfg.upstreamURL.String())
	}
	log.Printf("  period:          %d", cfg.totpPeriod)
	log.Printf("  digits:          %d", cfg.totpDigits)
	log.Printf("  algorithm:       %s", cfg.totpAlgo)
	log.Printf("  auth_disabled:   %v", cfg.authDisabled)
	log.Printf("  cookie_ttl:      %d", cfg.cookieTTL)
	log.Printf("  cookie_secure:   %v", cfg.cookieSecure)
	log.Printf("  refresh_interval: %d", cfg.refreshInterval)

	// Log trusted proxy networks (for debugging forwarded-header trust)
	trustedStrs := make([]string, len(cfg.trustedProxies))
	for i, cidr := range cfg.trustedProxies {
		trustedStrs[i] = cidr.String()
	}
	log.Printf("  trusted_proxies:   %s", strings.Join(trustedStrs, ", "))
	log.Printf("  insecure_skip_verify: %v", cfg.insecureSkipVerify)

	// Rate limiter: 5 attempts per IP per minute
	rl := newRateLimiter(5, 1*time.Minute)

	// Reverse proxy with dynamic host/path-prefix routing
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.Header.Set("X-Real-IP", clientIP(r.In, cfg.trustedProxies))

			// Resolve the target upstream for this request.
			target := resolveTarget(cfg, r.In)
			r.SetURL(target)

			// Preserve original Host header for upstream
			r.Out.Host = r.In.Host
			r.Out.Header.Set("Host", r.In.Host)
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.insecureSkipVerify, // nolint:gosec
			},
		},
	}

	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			log.Printf("health endpoint write error: %v", err)
		}
	})

	// Login page handlers
	mux.HandleFunc("/totp-gate/login", func(w http.ResponseWriter, r *http.Request) {
		nextURL := r.URL.Query().Get("next")
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if _, err := w.Write(renderLoginPage(cfg.totpDigits, "", nextURL)); err != nil {
				log.Printf("login page write error: %v", err)
			}

		case http.MethodPost:
			ip := clientIP(r, cfg.trustedProxies)

			// Rate limit check
			if !rl.allow(ip) {
				log.Printf("rate-limit hit for IP %s", ip)
				logRequest(r, http.StatusTooManyRequests, "rate limited")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				if _, err := w.Write(renderLoginPage(cfg.totpDigits, "Too many attempts, try again later", nextURL)); err != nil {
					log.Printf("rate limit page write error: %v", err)
				}
				return
			}

			if err := r.ParseForm(); err != nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				if _, err := w.Write(renderLoginPage(cfg.totpDigits, "Invalid request", nextURL)); err != nil {
					log.Printf("error page write error: %v", err)
				}
				return
			}

			submittedCode := strings.TrimSpace(r.FormValue("code"))
			if validateTOTP(cfg.totpSecret, submittedCode, cfg.totpDigits, cfg.totpAlgo, cfg.totpPeriod) {
				log.Printf("login success from IP %s", ip)
				logRequest(r, http.StatusOK, "login success")
				now := time.Now().Unix()
				// Use refreshInterval as cookie MaxAge (client-side inactivity timeout).
				// The browser discards the cookie after this period of inactivity.
				// cookieTTL serves as a server-side hard limit checked in validateCookie,
				// ensuring sessions never exceed the absolute max lifetime from login time.
				setCookie(w, cfg.cookieKey, cfg.refreshInterval, now, now, cfg.cookieSecure)
				redirect := "/"
				if nextURL != "" {
					redirect = nextURL
				}
				http.Redirect(w, r, redirect, http.StatusSeeOther)
			} else {
				log.Printf("login failure from IP %s", ip)
				logRequest(r, http.StatusUnauthorized, "login failure")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				if _, err := w.Write(renderLoginPage(cfg.totpDigits, "Invalid code. Please try again.", nextURL)); err != nil {
					log.Printf("login failure page write error: %v", err)
				}
			}

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// All other requests: auth check then proxy
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Auth check (unless disabled)
		if !cfg.authDisabled {
			valid, needsRefresh, loginTime, _ := validateCookie(r, cfg.cookieKey, cfg.refreshInterval, cfg.cookieTTL)
			if !valid {
				scheme := "https"
				if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
					scheme = "http"
				} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
					scheme = proto
				}
				fullURL := scheme + "://" + r.Host + r.RequestURI
				loginURL := "/totp-gate/login?next=" + url.QueryEscape(fullURL)
				http.Redirect(w, r, loginURL, http.StatusSeeOther)
				return
			}
			// Refresh cookie if needed (sliding session)
			if needsRefresh {
				// Renew the client-side inactivity timer (refreshInterval) while
				// preserving the original loginTime for the server-side hard limit (cookieTTL).
				setCookie(w, cfg.cookieKey, cfg.refreshInterval, loginTime, time.Now().Unix(), cfg.cookieSecure)
			}
		}

		// Normal HTTP → reverse proxy
		// In multi-target mode, check that a route exists before proxying.
		if len(cfg.targets) > 0 && resolveTarget(cfg, r) == nil {
			logRequest(r, http.StatusNotFound, "no matching target")
			http.Error(w, "404 no matching target", http.StatusNotFound)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         cfg.listenAddr,
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("listening on %s", cfg.listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("graceful shutdown failed: %v", err)
	}

	log.Println("server stopped")
}
