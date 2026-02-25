// Package domain contains all core types used across the application.
// Keeping domain types in one place makes the fraud scoring rules easy to reason about.
package domain

import "time"

// ─── Constants ───────────────────────────────────────────────────────────────

// Supported currencies for Lumina's markets.
const (
	BRL = "BRL" // Brazilian Real
	MXN = "MXN" // Mexican Peso
	ARS = "ARS" // Argentine Peso
	COP = "COP" // Colombian Peso
)

// Risk level labels that correspond to score bands.
const (
	RiskLow    = "low"    // 0-30
	RiskMedium = "medium" // 31-70
	RiskHigh   = "high"   // 71-100
)

// Recommendation actions for downstream payment processing.
const (
	ActionApprove = "approve" // auto-approve, low risk
	ActionReview  = "review"  // route to manual review queue
	ActionDecline = "decline" // auto-decline, high risk
)

// Entity types used in blocklist and entity-summary lookups.
const (
	EntityEmail  = "email"
	EntityIP     = "ip"
	EntityBIN    = "bin"
	EntityDevice = "device"
)

// List types for the blocklist/allowlist management endpoint.
const (
	ListBlock = "block"
	ListAllow = "allow"
)

// ─── Scoring thresholds ───────────────────────────────────────────────────────

// Score thresholds for recommendation decisions.
// Lumina can override these via API config in a future iteration.
const (
	ThresholdApprove = 30 // <= 30  → approve
	ThresholdReview  = 70 // 31-70  → review
	// > 70 → decline
)

// ─── Core domain types ────────────────────────────────────────────────────────

// TransactionRequest is the payload submitted by Lumina's payment flow.
// All fields are required unless marked optional.
type TransactionRequest struct {
	TransactionID     string    `json:"transaction_id"`
	Timestamp         time.Time `json:"timestamp"`
	Amount            float64   `json:"amount"`
	Currency          string    `json:"currency"`
	UserEmail         string    `json:"user_email"`
	IPAddress         string    `json:"ip_address"`
	IPCountry         string    `json:"ip_country"`          // ISO-3166-1 alpha-2 (e.g. "BR")
	CardBIN           string    `json:"card_bin"`             // first 6 digits of the card number
	CardCountry       string    `json:"card_country"`         // ISO-3166-1 alpha-2 of the issuing bank
	DeviceFingerprint string    `json:"device_fingerprint"`   // opaque client-side hash
	AccountCreatedAt  time.Time `json:"account_created_at"`
	MerchantCountry   string    `json:"merchant_country"`     // Lumina entity country
}

// RiskFactor is a single fraud signal that contributed to the score.
// Exposing factors individually lets human reviewers understand why a
// transaction was flagged and builds trust in the scoring system.
type RiskFactor struct {
	Name        string `json:"name"`        // machine-readable identifier
	Description string `json:"description"` // human-readable explanation
	ScoreDelta  int    `json:"score_delta"` // points added to total score
}

// Transaction is a TransactionRequest enriched with its fraud analysis result.
// This is the canonical record stored and returned by the API.
type Transaction struct {
	TransactionRequest
	RiskScore      int          `json:"risk_score"`      // 0-100
	RiskLevel      string       `json:"risk_level"`      // low / medium / high
	Recommendation string       `json:"recommendation"`  // approve / review / decline
	Factors        []RiskFactor `json:"factors"`
	Explanation    string       `json:"explanation"` // single human-readable summary
	ProcessedAt    time.Time    `json:"processed_at"`
}

// ─── Blocklist / Allowlist ────────────────────────────────────────────────────

// BlocklistEntry represents a manually managed block or allow rule.
// Blocked entries immediately push the risk score to 100.
// Allowed entries short-circuit scoring to 0.
type BlocklistEntry struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`      // email | ip | bin | device
	Value     string     `json:"value"`
	ListType  string     `json:"list_type"` // block | allow
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = permanent
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

// WebhookConfig is a registered callback that Lumina uses to receive
// real-time alerts when a transaction score exceeds the threshold.
type WebhookConfig struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Threshold int       `json:"threshold"` // fire when score >= this value
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
}

// WebhookPayload is the body sent to registered webhook URLs.
type WebhookPayload struct {
	Event       string      `json:"event"`       // always "high_risk_transaction"
	TriggeredAt time.Time   `json:"triggered_at"`
	Transaction Transaction `json:"transaction"`
}

// ─── Reporting ────────────────────────────────────────────────────────────────

// EntitySummary provides aggregated activity for a tracked entity
// (email, IP, card BIN, or device fingerprint) over a time window.
type EntitySummary struct {
	EntityType    string        `json:"entity_type"`
	EntityValue   string        `json:"entity_value"`
	Period        string        `json:"period"`
	TotalCount    int           `json:"total_count"`
	HighRiskCount int           `json:"high_risk_count"`
	AvgRiskScore  float64       `json:"avg_risk_score"`
	TotalAmount   float64       `json:"total_amount"`
	Transactions  []Transaction `json:"transactions"`
}

// FraudReport is the 24-hour pattern export for operations teams.
type FraudReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Period      string         `json:"period"`
	Summary     ReportSummary  `json:"summary"`
	Patterns    []FraudPattern `json:"patterns"`
}

// ReportSummary holds headline metrics for a FraudReport.
type ReportSummary struct {
	TotalTransactions int     `json:"total_transactions"`
	HighRiskCount     int     `json:"high_risk_count"`
	MediumRiskCount   int     `json:"medium_risk_count"`
	LowRiskCount      int     `json:"low_risk_count"`
	AvgRiskScore      float64 `json:"avg_risk_score"`
	TotalFlaggedAmount float64 `json:"total_flagged_amount"`
}

// FraudPattern describes a recurring suspicious behaviour detected in a window.
type FraudPattern struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Count       int      `json:"count"`
	TotalAmount float64  `json:"total_amount"`
	Examples    []string `json:"examples,omitempty"` // up to 3 transaction IDs
}
