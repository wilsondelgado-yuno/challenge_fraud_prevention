# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o fraud-api ./cmd/server

# ── Run stage ─────────────────────────────────────────────────────────────────
FROM alpine:3.19

WORKDIR /app

# ca-certificates needed for outbound webhook HTTPS calls
RUN apk --no-cache add ca-certificates

COPY --from=builder /app/fraud-api .
COPY --from=builder /app/data ./data

EXPOSE 8080

CMD ["./fraud-api"]
