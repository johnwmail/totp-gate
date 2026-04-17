# totp-gate

[![Release](https://img.shields.io/github/v/release/johnwmail/totp-gate?sort=semver)](https://github.com/johnwmail/totp-gate/releases)

A lightweight TOTP (Time-based One-Time Password) authentication gateway written in Go. It sits in front of any HTTP service, requiring users to enter a valid TOTP code before granting access.

## Features

- **TOTP Authentication** — RFC 6238 compliant, supports SHA1, SHA256, and SHA512
- **Reverse Proxy** — forwards authenticated requests to an upstream service
- **Session Management** — HMAC-signed cookies with sliding expiration and max lifetime
- **Rate Limiting** — per-IP rate limiting to prevent brute-force attacks
- **Secret Loading** — supports both file-based secrets (Docker secrets) and environment variables
- **Graceful Shutdown** — handles SIGINT/SIGTERM with configurable timeout
- **Zero Dependencies** — uses only Go standard library

## Quick Start

### Pre-built Binaries

Download pre-compiled binaries from the [GitHub Releases](https://github.com/johnwmail/totp-gate/releases) page. Binaries are available for `linux/amd64` and `linux/arm64`. Each release includes SHA256 checksums for verification.

```bash
# Download and verify
curl -LO "https://github.com/johnwmail/totp-gate/releases/latest/download/totp-gate-linux-amd64"
curl -LO "https://github.com/johnwmail/totp-gate/releases/latest/download/totp-gate-linux-amd64.sha256"
sha256sum -c totp-gate-linux-amd64.sha256
chmod +x totp-gate-linux-amd64

# Run
TOTPGATE_TOTP_SECRET="JBSWY3DPEHPK3PXP" ./totp-gate-linux-amd64
```

### Build from Source

```bash
go build -ldflags "-s -w -X main.Version=v1.0.0" -o totp-gate .
TOTPGATE_TOTP_SECRET="JBSWY3DPEHPK3PXP" ./totp-gate
```

Access the gateway at `http://localhost:8080`. It will proxy requests to the upstream service after successful TOTP authentication.

## Configuration

All configuration is done via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TOTPGATE_AUTH_LISTEN` | `0.0.0.0:8080` | Address to listen on (port or ip:port) |
| `TOTPGATE_UPSTREAM` | `http://localhost:3000` | Upstream service URL to proxy to |
| `TOTPGATE_TARGETS` | *(empty)* | Multi-target routing: `host1=upstream1,host2=upstream2`. Overrides `TOTPGATE_UPSTREAM`. |
| `TOTPGATE_AUTH_DISABLED` | `false` | Disable authentication (bypass mode) |
| `TOTPGATE_TOTP_SECRET` | *(required)* | Base32-encoded TOTP secret (fallback) |
| `TOTPGATE_TOTP_SECRET_FILE` | `/run/secrets/totpgate_totp_secret` | Path to file containing TOTP secret |
| `TOTPGATE_TOTP_PERIOD` | `30` | TOTP time step in seconds |
| `TOTPGATE_TOTP_DIGITS` | `6` | Number of digits in TOTP code |
| `TOTPGATE_TOTP_ALGORITHM` | `SHA1` | Hash algorithm: `SHA1`, `SHA256`, `SHA512` |
| `TOTPGATE_AUTH_COOKIE_TTL` | `86400` | Max session lifetime in seconds (24h) |
| `TOTPGATE_AUTH_COOKIE_SECURE` | `true` | Set `Secure` flag on cookies (set `false` for local dev/test with HTTP-only) |
| `TOTPGATE_AUTH_REFRESH_INTERVAL` | `600` | Activity refresh interval in seconds (10m) |
| `TOTPGATE_TRUSTED_PROXIES` | *(see below)* | Comma-separated trusted proxy IPs or CIDRs for forwarded-header trust |
| `TOTPGATE_INSECURE_SKIP_VERIFY` | `false` | Skip TLS certificate verification for `https://` upstream targets (dev/testing only) |

### Secret Priority

The TOTP secret is loaded in this order:
1. File specified by `TOTPGATE_TOTP_SECRET_FILE` (default: `/run/secrets/totpgate_totp_secret`)
2. Environment variable `TOTPGATE_TOTP_SECRET`

Using file-based secrets is recommended for production, especially with Docker secrets.

### Trusted Proxies

The `X-Real-IP` and `X-Forwarded-For` headers are only trusted when the immediate peer matches a configured trusted proxy.

- **Default** (env var not set): `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **When set**: specified values + `127.0.0.1` (always included)
- **Examples**:
  - Cloudflare: `TOTPGATE_TRUSTED_PROXIES="173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"`
  - Local nginx: use defaults (nginx on `127.0.0.1` is already trusted)

If the request comes from an untrusted peer (e.g., direct internet connection), these headers are ignored and `r.RemoteAddr` is used.

### Upstream TLS Verification

When routing to `https://` upstream targets, totp-gate validates TLS certificates against the system CA store by default. For internal services with self-signed or private CA certificates, set:

```bash
TOTPGATE_INSECURE_SKIP_VERIFY=true
```

⚠️ **Warning**: Only use this in development or trusted networks. In production, mount your CA certificate into the container and ensure the system trust store includes it.

### Multi-Target Routing

When `TOTPGATE_TARGETS` is set, the gateway routes requests to different upstream services based on the `Host` header:

```bash
TOTPGATE_TARGETS="app1.example.com=http://localhost:3000,app2.example.com=http://localhost:4000" ./totp-gate
```

**Behavior:**

- The port is stripped from the `Host` before matching (e.g., `app1.example.com:8080` → `app1.example.com`).
- If no host matches, the **first target** in the list acts as the default fallback — this also covers HTTP/1.0 requests with no `Host` header.
- WebSocket upgrades are fully supported and routed to the correct backend.
- `TOTPGATE_UPSTREAM` is ignored when `TOTPGATE_TARGETS` is set.

**Docker Compose example:**

```yaml
services:
  totp-gate:
    image: johnwmail/totp-gate:latest
    ports:
      - "8080:8080"
    environment:
      TOTPGATE_TARGETS: "app1.example.com=http://app1:3000,app2.example.com=http://app2:4000"
    secrets:
      - totpgate_totp_secret
secrets:
  totpgate_totp_secret:
    file: ./secret.txt
```

## Architecture

### Single Target (default)

```
Client → totp-gate (:8080) → Upstream Service (:3000)
              ↑
         TOTP Gate
```

### Multi-Target (via TOTPGATE_TARGETS)

```
Client → totp-gate (:8080) ──Host: app1.example.com──→ Service A (:3000)
              ↑               └──Host: app2.example.com──→ Service B (:4000)
         TOTP Gate
```

1. User accesses the gateway
2. If no valid session cookie exists, user is redirected to `/totp-gate/login`
3. User enters their TOTP code
4. On success, a signed session cookie is set and user is redirected to the upstream service
5. Subsequent requests validate the cookie and proxy to upstream

### Session Management

- **Max Lifetime**: Sessions expire after `TOTPGATE_AUTH_COOKIE_TTL` (default 24h) from login time
- **Activity Refresh**: Cookie activity is refreshed every `TOTPGATE_AUTH_REFRESH_INTERVAL` (default 10m) of activity
- **Security**: Cookies are HMAC-signed with a key derived from the TOTP secret + random nonce (regenerated on each restart, invalidating all sessions)

## Endpoints

| Path | Description |
|------|-------------|
| `/health` | Health check, returns `OK` |
| `/totp-gate/login` | TOTP login page (GET) and submission (POST) |
| `/` | Authenticated reverse proxy |

## Rate Limiting

Built-in per-IP rate limiting: **5 attempts per minute**. Exceeding this returns HTTP 429.

## Docker Usage

```dockerfile
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY . .
RUN go build -o totp-gate .

FROM alpine:latest
COPY --from=builder /app/totp-gate /totp-gate
EXPOSE 8080
CMD ["/totp-gate"]
```

Run with Docker secrets:

```bash
echo "JBSWY3DPEHPK3PXP" | docker secret create totpgate_totp_secret -
docker service create \
  --name totp-gate \
  --secret totpgate_totp_secret \
  -p 8080:8080 \
  -e TOTPGATE_UPSTREAM=http://myapp:3000 \
  totp-gate
```

Or with multi-target routing:

```bash
docker run -d \
  --name totp-gate \
  -p 8080:8080 \
  -e TOTPGATE_TARGETS="app1.example.com=http://app1:3000,app2.example.com=http://app2:4000" \
  -e TOTPGATE_TOTP_SECRET="JBSWY3DPEHPK3PXP" \
  johnwmail/totp-gate:latest
```

## License

MIT License — see [LICENSE](LICENSE)
