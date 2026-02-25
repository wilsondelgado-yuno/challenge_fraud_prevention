# Architecture Document — Lumina Fraud Detection API

## Overview

This service implements a real-time fraud risk scoring engine for Lumina Gaming, exposing a RESTful API built with Go and Chi. All state is kept in-memory for the scope of this challenge, with a clear abstraction boundary that makes it straightforward to swap in Redis or PostgreSQL.

---

## Key Technical Decisions

### 1. How historical patterns are tracked

The store (`internal/store/memory.go`) maintains a primary `map[string]*Transaction` and four secondary indexes keyed by entity value (email, IP, device fingerprint, card BIN), each holding a slice of transaction IDs. An additional `cardsByIP` map tracks the set of distinct card BINs seen per IP address.

**Why this structure:**
- O(1) write (append to slice + map upsert)
- O(k) read where k = transactions for that entity, which is small in practice
- The time-window filter is a linear scan over k, acceptable for demo-scale data

**Trade-off vs production:** A real deployment would use Redis sorted sets (keyed by entity, scored by Unix timestamp) to support O(log n) time-range lookups and automatic TTL expiry. For the 2-hour scope, in-memory with a sync.RWMutex is sufficient and keeps the code readable.

---

### 2. How risk scores are calculated

The engine (`internal/scoring/engine.go`) follows a **pipeline architecture**:

```
TransactionRequest
       │
       ▼
[Blocklist/Allowlist check] ─── immediate 0 or 100 ──→ result
       │ (no match)
       ▼
[buildContext] → fetch historical data from store (read-only)
       │
       ▼
[Rule 1] email velocity   ─┐
[Rule 2] IP velocity       │
[Rule 3] device velocity   │  additive deltas
[Rule 4] card cycling      ├─────────────────→ sum → clamp(0,100) → score
[Rule 5] geography         │
[Rule 6] account age       │
[Rule 7] purchase amount   │
[Rule 8] card BIN pattern  │
[Rule 9] timing            ─┘
       │
       ▼
   (score, []RiskFactor, explanation string)
```

Each rule returns a slice of `RiskFactor` structs. Factors are additive and the total is clamped to [0, 100]. This design makes it trivial to add, remove, or reweight rules without touching the aggregation logic.

**Score thresholds:**
| Range  | Level  | Recommendation |
|--------|--------|---------------|
| 0–30   | Low    | Approve        |
| 31–70  | Medium | Manual Review  |
| 71–100 | High   | Decline        |

---

### 3. Fraud indicators chosen and rationale

| # | Signal | Max delta | Rationale |
|---|--------|-----------|-----------|
| 1 | Email velocity (24h / 10min) | +25/+30 | ATO and bot attacks reuse the same account rapidly |
| 2 | IP velocity (1h) | +30 | A single IP making many purchases signals a shared fraud tool |
| 3 | Device velocity (30min) | +30 | Device fingerprints are harder to spoof; bursts = automation |
| 4 | Card cycling per IP | +30 | Fraudsters test stolen card batches from one machine |
| 4b | BIN cross-user velocity | +25 | One compromised card batch exploited by multiple accounts |
| 5 | IP ≠ Card country | +25 | Classic cross-border fraud indicator |
| 5b | IP from high-risk country | +15 | Elevated base rate for known fraud-origin regions |
| 5c | Three-way mismatch | +10 | IP/card/merchant all different is a strong compound signal |
| 6 | Account age <1h / <24h / <7d | +25/+15/+5 | Throwaway accounts are a key fraud ring tactic |
| 7 | Amount anomaly (3x / 5x / 10x avg) | +10/+20/+30 | Draining a compromised account with one large purchase |
| 8 | Known high-risk BIN | +30 | Internal chargeback data identifies specific BIN ranges |
| 8b | Prepaid card BIN | +15 | Prepaid cards lack cardholder identity verification |
| 9 | Off-hours (02:00–06:00 UTC) | +10 | Bots prefer operating when human reviewers are offline |

---

### 4. API design

The API follows REST conventions with a consistent JSON envelope:

```json
{ "data": { ... } }         // success
{ "error": { "code": "...", "message": "..." } }  // failure
```

Chi was chosen for its lightweight, idiomatic middleware chaining and zero-dependency design. The router structure maps 1:1 to the challenge requirements:
- `POST /api/v1/transactions` — core scoring (sync, returns score immediately)
- `GET /api/v1/transactions/{id}` — historical lookup
- `GET /api/v1/entities/{type}/{value}` — entity activity summary
- `POST/DELETE /api/v1/blocklist` — blocklist management (stretch goal 1)
- `GET /api/v1/reports/fraud-patterns` — pattern export (stretch goal 3)
- `POST/DELETE /api/v1/webhooks` — webhook registration (stretch goal 4)

---

### 5. Trade-offs made for the 2-hour scope

| What was simplified | What a production system would do |
|---------------------|----------------------------------|
| In-memory store (lost on restart) | Redis + PostgreSQL for persistence |
| No authentication | API key / JWT middleware |
| Single-node | Distributed store for horizontal scaling |
| No BIN database integration | Real-time BIN lookup API (Mastercard/Visa) |
| Heuristic country risk list | ML-based risk model trained on chargeback data |
| Webhook delivery: fire-and-forget | Persistent job queue with retry + dead-letter |
| No rate limiting on the API itself | Redis-backed sliding-window rate limiter |

---

## Package Structure

```
lumina/fraud-api
├── cmd/
│   ├── server/     Entry point: wires dependencies, loads seed data, starts HTTP server
│   └── seed/       CLI to generate data/seed.json with realistic test patterns
├── internal/
│   ├── domain/     Pure types (no logic, no imports from other internal packages)
│   ├── store/      Thread-safe in-memory store with secondary indexes
│   ├── scoring/    Stateless fraud scoring engine (reads store, never writes)
│   ├── api/        Chi router + HTTP handlers + response helpers
│   └── webhook/    Async webhook notifier (goroutine per delivery)
└── data/
    └── seed.json   ~290 pre-scored transactions covering all fraud patterns
```

The dependency graph flows strictly downward: `api` → `scoring` → `store` → `domain`. No circular imports.
