FROM golang:1.26-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /app

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=unknown

COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
  -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILDTIME}" \
  -o totp-gate .

FROM gcr.io/distroless/static
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/totp-gate /totp-gate
USER 8080
EXPOSE 8080
ENTRYPOINT ["/totp-gate"]
