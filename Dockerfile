FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static'" \
    -o /app/firewall-analyzer \
    ./cmd/server

# ──────────────────────────────────────────────────────────────────────────────
FROM scratch AS final

COPY --from=builder /app/firewall-analyzer /app/firewall-analyzer
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

ENTRYPOINT ["/app/firewall-analyzer"]
