# Lumina Gaming — Chargeback Intelligence API

A real-time fraud risk scoring engine for Lumina Gaming's payment operations team. Built with Go and Chi.

---

## Quick Start

### Prerequisites

- Go 1.21+

### 1. Generate test data (optional — a pre-generated file is already included)

```bash
go run ./cmd/seed
# → writes data/seed.json  (~290 transactions with realistic fraud patterns)
```

### 2. Start the server

```bash
go run ./cmd/server
# Listening on :8080
# Seed data loaded automatically from data/seed.json
```

Flags:

| Flag    | Default          | Description                        |
|---------|------------------|------------------------------------|
| `-port` | `8080`           | HTTP port                          |
| `-seed` | `data/seed.json` | Path to seed data file             |

---

## API Reference

All endpoints return JSON with the envelope `{ "data": ... }` on success or `{ "error": { "code": "...", "message": "..." } }` on failure.

---

### Health Check

```
GET /health
```

```json
{ "data": { "status": "ok", "service": "lumina-fraud-api" } }
```

---

### Transactions

#### Submit a transaction for risk scoring

```
POST /api/v1/transactions
Content-Type: application/json
```

**Request body:**

```json
{
  "transaction_id":     "txn_demo_001",
  "timestamp":          "2026-02-25T14:30:00Z",
  "amount":             99.99,
  "currency":           "BRL",
  "user_email":         "user@example.com",
  "ip_address":         "201.22.33.44",
  "ip_country":         "BR",
  "card_bin":           "453211",
  "card_country":       "BR",
  "device_fingerprint": "abc123def456",
  "account_created_at": "2025-01-01T10:00:00Z",
  "merchant_country":   "BR"
}
```

**Response (201):**

```json
{
  "data": {
    "transaction_id": "txn_demo_001",
    "risk_score": 5,
    "risk_level": "low",
    "recommendation": "approve",
    "explanation": "Risk Score: 5. Factors: First transaction recorded for this email address (+5).",
    "factors": [
      {
        "name": "first_transaction",
        "description": "First transaction recorded for this email address",
        "score_delta": 5
      }
    ],
    "processed_at": "2026-02-25T14:30:01Z"
  }
}
```

#### Get a scored transaction

```
GET /api/v1/transactions/{id}
```

---

### Entity Activity Summary

Returns all transactions for a given entity over a configurable window.

```
GET /api/v1/entities/{type}/{value}?days=7
```

- `type`: `email` | `ip` | `bin` | `device`
- `value`: the entity's value (URL-encoded if needed)
- `days`: look-back window, 1–90 (default: 7)

**Example:**

```bash
curl "http://localhost:8080/api/v1/entities/email/carlos.silva%40gmail.com?days=7"
```

---

### Blocklist / Allowlist Management

#### List all entries

```
GET /api/v1/blocklist
```

#### Add an entry

```
POST /api/v1/blocklist
```

```json
{
  "type":       "email",
  "value":      "fraud_ring_1@tempbox.net",
  "list_type":  "block",
  "reason":     "confirmed fraud ring member",
  "expires_at": "2026-06-01T00:00:00Z"
}
```

- `type`: `email` | `ip` | `bin` | `device`
- `list_type`: `block` (score → 100) | `allow` (score → 0)
- `expires_at`: optional; omit for a permanent rule

#### Remove an entry

```
DELETE /api/v1/blocklist/{id}
```

---

### Fraud Pattern Report (last 24 hours)

```
GET /api/v1/reports/fraud-patterns
```

Returns a summary of detected patterns: IP velocity, email velocity, card cycling, and BIN concentration.

---

### Webhooks

High-risk transactions (score ≥ threshold) trigger a `POST` to the registered URL with the full transaction payload.

#### Register

```
POST /api/v1/webhooks
```

```json
{
  "url":       "https://your-ops-tool.example.com/lumina-alerts",
  "threshold": 80
}
```

#### Remove

```
DELETE /api/v1/webhooks/{id}
```

---

### Admin

#### Bulk load seed data

```
POST /api/v1/admin/seed
Content-Type: application/json
Body: [ <array of TransactionRequest objects> ]
```

---

## Fraud Scoring Methodology

The engine applies nine additive rules. The total is clamped to [0, 100].

| Rule | Signal | Max delta |
|------|--------|-----------|
| 1 | Email velocity (24h / 10min rapid burst) | +25 / +30 |
| 2 | IP velocity (1h window) | +30 |
| 3 | Device velocity (30min window) | +30 |
| 4 | Card cycling from same IP / BIN cross-user | +30 / +25 |
| 5 | IP ≠ card country (+25), high-risk origin (+15), 3-way mismatch (+10) | +50 |
| 6 | Account age: <1h (+25), <24h (+15), <7d (+5) | +25 |
| 7 | Amount anomaly vs 24h average: 3x (+10), 5x (+20), 10x (+30) | +30 |
| 8 | Known high-risk BIN (+30) or prepaid BIN (+15) | +30 |
| 9 | Off-hours transaction 02:00–06:00 UTC | +10 |

**Blocklist/allowlist entries override all rules** (instant 100 or 0).

**Recommendation thresholds:**

| Score | Level  | Action  |
|-------|--------|---------|
| 0–30  | Low    | Approve |
| 31–70 | Medium | Review  |
| 71–100| High   | Decline |

---

## Demo Guide

### Core scenario 1: Low-risk legitimate transaction

```bash
curl -X POST http://localhost:8080/api/v1/transactions \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id":     "demo_legit_001",
    "timestamp":          "2026-02-25T14:00:00Z",
    "amount":             35.00,
    "currency":           "BRL",
    "user_email":         "carlos.silva@gmail.com",
    "ip_address":         "177.23.45.12",
    "ip_country":         "BR",
    "card_bin":           "453211",
    "card_country":       "BR",
    "device_fingerprint": "dev_br_a1b2c3",
    "account_created_at": "2025-01-01T10:00:00Z",
    "merchant_country":   "BR"
  }'
```

Expected: low score (amount matches history, same IP/device/country).

---

### Core scenario 2: Rapid velocity abuse — watch the score rise

Submit three quick transactions from the same email within minutes:

```bash
for i in 1 2 3; do
  curl -s -X POST http://localhost:8080/api/v1/transactions \
    -H "Content-Type: application/json" \
    -d "{
      \"transaction_id\":     \"demo_vel_00${i}\",
      \"timestamp\":          \"2026-02-25T15:0${i}:00Z\",
      \"amount\":             49.99,
      \"currency\":           \"BRL\",
      \"user_email\":         \"velocity_test@example.com\",
      \"ip_address\":         \"201.99.11.22\",
      \"ip_country\":         \"BR\",
      \"card_bin\":           \"456789\",
      \"card_country\":       \"BR\",
      \"device_fingerprint\": \"dev_vel_test\",
      \"account_created_at\": \"2026-02-24T12:00:00Z\",
      \"merchant_country\":   \"BR\"
    }" | python3 -m json.tool | grep -E '"risk_score"|"recommendation"'
  echo "---"
done
```

Observe the risk score climbing as velocity rules activate.

---

### Core scenario 3: Obvious fraud — high BIN risk + new account + geo mismatch + off-hours

```bash
curl -X POST http://localhost:8080/api/v1/transactions \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id":     "demo_fraud_001",
    "timestamp":          "2026-02-25T03:30:00Z",
    "amount":             99.99,
    "currency":           "BRL",
    "user_email":         "obvious_fraud@disposable.xyz",
    "ip_address":         "185.100.87.12",
    "ip_country":         "RU",
    "card_bin":           "400000",
    "card_country":       "US",
    "device_fingerprint": "dev_fraud_demo",
    "account_created_at": "2026-02-25T03:15:00Z",
    "merchant_country":   "BR"
  }'
```

Expected: score ~100, recommendation: decline.

---

### Core scenario 4: Query entity history

```bash
# All activity from a known fraudster email
curl "http://localhost:8080/api/v1/entities/email/fraud_ring_1%40tempbox.net"

# All transactions from a suspicious IP
curl "http://localhost:8080/api/v1/entities/ip/185.220.101.5"
```

---

### Stretch goal: Add to blocklist and verify instant decline

```bash
# Block the fraud ring IP
ENTRY=$(curl -s -X POST http://localhost:8080/api/v1/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "type":      "ip",
    "value":     "185.100.87.12",
    "list_type": "block",
    "reason":    "confirmed fraud ring IP"
  }')
echo $ENTRY | python3 -m json.tool

# Any new transaction from that IP now scores 100
curl -X POST http://localhost:8080/api/v1/transactions \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id":     "demo_blocked_001",
    "timestamp":          "2026-02-25T16:00:00Z",
    "amount":             10.00,
    "currency":           "BRL",
    "user_email":         "innocent@example.com",
    "ip_address":         "185.100.87.12",
    "ip_country":         "RU",
    "card_bin":           "453211",
    "card_country":       "BR",
    "device_fingerprint": "dev_any",
    "account_created_at": "2026-01-01T00:00:00Z",
    "merchant_country":   "BR"
  }' | python3 -m json.tool
```

---

### Stretch goal: Fraud pattern report

```bash
curl http://localhost:8080/api/v1/reports/fraud-patterns | python3 -m json.tool
```

---

## Test Data

The seeded dataset (`data/seed.json`, ~290 transactions) includes:

| Category | Count | Description |
|----------|-------|-------------|
| Normal users | ~220 | 10 consistent LATAM players, 20-24 txns each over 7 days |
| Velocity abuse | ~40 | Email burst, IP burst, device sharing |
| Geo mismatches | ~20 | RU/NG/CN/UA IPs with LATAM cards |
| High-value outliers | ~12 | New accounts or 10x purchases |
| Obvious fraudsters | ~15 | 3am accounts, stolen card batches, card cycling |

Regenerate at any time: `go run ./cmd/seed`
