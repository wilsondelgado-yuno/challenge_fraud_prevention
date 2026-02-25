// Package scoring implements Lumina's fraud risk scoring engine.
//
// Architecture:
//   The engine is intentionally stateless — it reads historical context from
//   the store but never writes to it. Writes happen in the HTTP handler after
//   scoring, ensuring the current transaction is not counted against itself.
//
// Scoring philosophy:
//   Each rule contributes a non-negative delta to the total score.
//   Deltas are additive; the total is clamped to [0, 100].
//   Blocklist/allowlist entries short-circuit the entire pipeline.
//
// Rules implemented (≥5 required by spec):
//   1. Velocity — email, IP, device, and card-cycling signals
//   2. Geography — IP vs card country, IP vs merchant, high-risk origin
//   3. Account age — newer accounts carry more risk
//   4. Purchase behaviour — anomalous amounts vs the user's historical average
//   5. Card / BIN patterns — known high-risk or prepaid BIN prefixes
//   6. Timing — off-hours transactions (fraud bots prefer 02:00–06:00 UTC)
package scoring

import (
	"fmt"
	"strings"
	"time"

	"lumina/fraud-api/internal/domain"
	"lumina/fraud-api/internal/store"
)

// Engine is the stateless fraud risk scoring engine.
type Engine struct {
	store *store.Store
}

// New creates a scoring engine backed by the given store.
func New(s *store.Store) *Engine {
	return &Engine{store: s}
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Score calculates a risk score for a transaction request.
// It returns the clamped score (0–100), the contributing factors, and a
// human-readable explanation string.
//
// The method does NOT save the transaction to the store; that is the caller's
// responsibility.
func (e *Engine) Score(req *domain.TransactionRequest) (score int, factors []domain.RiskFactor, explanation string) {
	// Blocklist/allowlist takes absolute priority.
	if entry, hit := e.checkLists(req); hit {
		switch entry.ListType {
		case domain.ListBlock:
			f := domain.RiskFactor{
				Name:        "blocklist_match",
				Description: fmt.Sprintf("%s '%s' is on the blocklist: %s", entry.Type, entry.Value, entry.Reason),
				ScoreDelta:  100,
			}
			return 100, []domain.RiskFactor{f}, buildExplanation(100, []domain.RiskFactor{f})
		case domain.ListAllow:
			f := domain.RiskFactor{
				Name:        "allowlist_match",
				Description: fmt.Sprintf("%s '%s' is on the allowlist: %s", entry.Type, entry.Value, entry.Reason),
				ScoreDelta:  0,
			}
			return 0, []domain.RiskFactor{f}, buildExplanation(0, []domain.RiskFactor{f})
		}
	}

	// Fetch all historical context needed by the rules in one pass.
	ctx := e.buildContext(req)

	// Run every rule and aggregate factors.
	rules := []func(*ruleContext) []domain.RiskFactor{
		ruleVelocityEmail,
		ruleVelocityIP,
		ruleVelocityDevice,
		ruleVelocityCardCycling,
		ruleGeography,
		ruleAccountAge,
		rulePurchaseBehaviour,
		ruleCardBIN,
		ruleTiming,
	}

	for _, rule := range rules {
		factors = append(factors, rule(ctx)...)
	}

	// Sum and clamp.
	total := 0
	for _, f := range factors {
		total += f.ScoreDelta
	}
	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	return total, factors, buildExplanation(total, factors)
}

// Recommend returns the recommendation and risk level for a given score.
func Recommend(score int) (recommendation, riskLevel string) {
	switch {
	case score <= domain.ThresholdApprove:
		return domain.ActionApprove, domain.RiskLow
	case score <= domain.ThresholdReview:
		return domain.ActionReview, domain.RiskMedium
	default:
		return domain.ActionDecline, domain.RiskHigh
	}
}

// ─── Rule context ─────────────────────────────────────────────────────────────

// ruleContext bundles the transaction request with pre-fetched historical data,
// so each rule doesn't need to query the store independently.
type ruleContext struct {
	req *domain.TransactionRequest

	emailLast24h  []*domain.Transaction // same email, last 24 h
	emailLast10m  []*domain.Transaction // same email, last 10 min (tight velocity)
	ipLast1h      []*domain.Transaction // same IP, last 1 h
	deviceLast30m []*domain.Transaction // same device, last 30 min
	binLast1h     []*domain.Transaction // same card BIN, last 1 h
	uniqueCardsByIP int                 // distinct BINs ever seen from this IP
}

func (e *Engine) buildContext(req *domain.TransactionRequest) *ruleContext {
	t := req.Timestamp
	return &ruleContext{
		req:             req,
		emailLast24h:    e.store.GetTransactionsByEmail(req.UserEmail, t.Add(-24*time.Hour)),
		emailLast10m:    e.store.GetTransactionsByEmail(req.UserEmail, t.Add(-10*time.Minute)),
		ipLast1h:        e.store.GetTransactionsByIP(req.IPAddress, t.Add(-1*time.Hour)),
		deviceLast30m:   e.store.GetTransactionsByDevice(req.DeviceFingerprint, t.Add(-30*time.Minute)),
		binLast1h:       e.store.GetTransactionsByBIN(req.CardBIN, t.Add(-1*time.Hour)),
		uniqueCardsByIP: e.store.GetUniqueCardsByIP(req.IPAddress),
	}
}

// ─── Blocklist check ──────────────────────────────────────────────────────────

func (e *Engine) checkLists(req *domain.TransactionRequest) (*domain.BlocklistEntry, bool) {
	checks := []struct{ typ, val string }{
		{domain.EntityEmail, req.UserEmail},
		{domain.EntityIP, req.IPAddress},
		{domain.EntityBIN, req.CardBIN},
		{domain.EntityDevice, req.DeviceFingerprint},
	}
	for _, c := range checks {
		if entry, ok := e.store.CheckBlocklist(c.typ, c.val); ok {
			return entry, true
		}
	}
	return nil, false
}

// ─── Rule 1: Email velocity ───────────────────────────────────────────────────

func ruleVelocityEmail(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	// 24-hour window: multiple purchases from the same account signal
	// either account takeover or a compromised account being drained.
	if n := len(ctx.emailLast24h); n >= 2 {
		delta := clamp(5*n, 0, 25)
		factors = append(factors, domain.RiskFactor{
			Name:        "email_velocity_24h",
			Description: fmt.Sprintf("Email used in %d transactions in the last 24 hours", n),
			ScoreDelta:  delta,
		})
	}

	// 10-minute tight window: strong signal for automated bot activity.
	if n := len(ctx.emailLast10m); n >= 2 {
		delta := clamp(10*n, 0, 30)
		factors = append(factors, domain.RiskFactor{
			Name:        "email_velocity_10min",
			Description: fmt.Sprintf("Email used in %d transactions in the last 10 minutes", n),
			ScoreDelta:  delta,
		})
	}

	return factors
}

// ─── Rule 2: IP velocity ──────────────────────────────────────────────────────

func ruleVelocityIP(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	// 3+ transactions from the same IP in an hour is above normal gaming behaviour.
	if n := len(ctx.ipLast1h); n >= 3 {
		delta := clamp(8*n, 0, 30)
		factors = append(factors, domain.RiskFactor{
			Name:        "ip_velocity_1h",
			Description: fmt.Sprintf("IP address used in %d transactions in the last hour", n),
			ScoreDelta:  delta,
		})
	}

	return factors
}

// ─── Rule 3: Device velocity ──────────────────────────────────────────────────

func ruleVelocityDevice(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	// Same device making 2+ purchases in 30 min is highly suspicious.
	if n := len(ctx.deviceLast30m); n >= 2 {
		delta := clamp(12*n, 0, 30)
		factors = append(factors, domain.RiskFactor{
			Name:        "device_velocity_30min",
			Description: fmt.Sprintf("Device fingerprint used in %d transactions in the last 30 minutes", n),
			ScoreDelta:  delta,
		})
	}

	return factors
}

// ─── Rule 4: Card cycling on same IP ─────────────────────────────────────────

func ruleVelocityCardCycling(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	// Fraudsters testing stolen cards often cycle through multiple cards
	// from the same IP or device. 3+ different BINs from one IP is a red flag.
	if ctx.uniqueCardsByIP >= 3 {
		delta := clamp(8*ctx.uniqueCardsByIP, 0, 30)
		factors = append(factors, domain.RiskFactor{
			Name:        "card_cycling_ip",
			Description: fmt.Sprintf("IP address has used %d different card BINs (possible card cycling)", ctx.uniqueCardsByIP),
			ScoreDelta:  delta,
		})
	}

	// Also flag if the same BIN is appearing across multiple different users
	// in the last hour — a sign that a stolen card batch is being exploited.
	if n := len(ctx.binLast1h); n >= 5 {
		emails := make(map[string]bool)
		for _, tx := range ctx.binLast1h {
			emails[tx.UserEmail] = true
		}
		if len(emails) > 1 {
			factors = append(factors, domain.RiskFactor{
				Name:        "bin_velocity_multi_user",
				Description: fmt.Sprintf("Card BIN used by %d different accounts in the last hour", len(emails)),
				ScoreDelta:  clamp(8*len(emails), 0, 25),
			})
		}
	}

	return factors
}

// ─── Rule 5: Geography ────────────────────────────────────────────────────────

func ruleGeography(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	ip := strings.ToUpper(ctx.req.IPCountry)
	card := strings.ToUpper(ctx.req.CardCountry)
	merchant := strings.ToUpper(ctx.req.MerchantCountry)

	// IP country ≠ card issuing country: strong indicator of cross-border fraud.
	if ip != "" && card != "" && ip != card {
		factors = append(factors, domain.RiskFactor{
			Name:        "geo_ip_card_mismatch",
			Description: fmt.Sprintf("IP country (%s) doesn't match card issuing country (%s)", ip, card),
			ScoreDelta:  25,
		})
	}

	// IP country ≠ merchant country (only flag for non-LATAM origins, since
	// cross-country play within LATAM is normal for Lumina's user base).
	if ip != "" && merchant != "" && ip != merchant && !isLATAM(ip) {
		factors = append(factors, domain.RiskFactor{
			Name:        "geo_ip_merchant_mismatch",
			Description: fmt.Sprintf("IP country (%s) doesn't match merchant country (%s)", ip, merchant),
			ScoreDelta:  10,
		})
	}

	// IP from a known high-risk origin country.
	if isHighRiskCountry(ip) {
		factors = append(factors, domain.RiskFactor{
			Name:        "geo_high_risk_country",
			Description: fmt.Sprintf("Transaction originated from high-risk country (%s)", ip),
			ScoreDelta:  15,
		})
	}

	// Three-way mismatch (IP, card, merchant all different) compounds suspicion.
	if ip != "" && card != "" && merchant != "" && ip != card && card != merchant && ip != merchant {
		factors = append(factors, domain.RiskFactor{
			Name:        "geo_three_way_mismatch",
			Description: "IP country, card country, and merchant country are all different",
			ScoreDelta:  10,
		})
	}

	return factors
}

// ─── Rule 6: Account age ──────────────────────────────────────────────────────

func ruleAccountAge(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	age := ctx.req.Timestamp.Sub(ctx.req.AccountCreatedAt)

	switch {
	case age < time.Hour:
		factors = append(factors, domain.RiskFactor{
			Name:        "account_age_critical",
			Description: fmt.Sprintf("Account created %.0f minutes ago (very new)", age.Minutes()),
			ScoreDelta:  25,
		})
	case age < 24*time.Hour:
		factors = append(factors, domain.RiskFactor{
			Name:        "account_age_new",
			Description: fmt.Sprintf("Account created %.0f hours ago", age.Hours()),
			ScoreDelta:  15,
		})
	case age < 7*24*time.Hour:
		factors = append(factors, domain.RiskFactor{
			Name:        "account_age_week",
			Description: fmt.Sprintf("Account created %.0f days ago", age.Hours()/24),
			ScoreDelta:  5,
		})
	}

	return factors
}

// ─── Rule 7: Purchase behaviour ──────────────────────────────────────────────

func rulePurchaseBehaviour(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	history := ctx.emailLast24h // use 24-h window as the baseline

	if len(history) == 0 {
		// No prior history — first transaction carries baseline risk.
		delta := 5
		desc := "First transaction recorded for this email address"
		if ctx.req.Amount > 50 {
			// First purchase that is unusually large warrants more suspicion.
			delta = 15
			desc = fmt.Sprintf("First transaction with a high amount ($%.2f)", ctx.req.Amount)
		}
		factors = append(factors, domain.RiskFactor{
			Name:        "first_transaction",
			Description: desc,
			ScoreDelta:  delta,
		})
		return factors
	}

	// Calculate the user's average transaction amount from history.
	var total float64
	for _, tx := range history {
		total += tx.Amount
	}
	avg := total / float64(len(history))

	if avg > 0 {
		ratio := ctx.req.Amount / avg
		switch {
		case ratio >= 10:
			factors = append(factors, domain.RiskFactor{
				Name:        "amount_anomaly_extreme",
				Description: fmt.Sprintf("Amount is %.1fx the user's 24h average ($%.2f avg)", ratio, avg),
				ScoreDelta:  30,
			})
		case ratio >= 5:
			factors = append(factors, domain.RiskFactor{
				Name:        "amount_anomaly_high",
				Description: fmt.Sprintf("Amount is %.1fx the user's 24h average ($%.2f avg)", ratio, avg),
				ScoreDelta:  20,
			})
		case ratio >= 3:
			factors = append(factors, domain.RiskFactor{
				Name:        "amount_anomaly_medium",
				Description: fmt.Sprintf("Amount is %.1fx the user's 24h average ($%.2f avg)", ratio, avg),
				ScoreDelta:  10,
			})
		}
	}

	return factors
}

// ─── Rule 8: Card BIN patterns ───────────────────────────────────────────────

func ruleCardBIN(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor
	bin := ctx.req.CardBIN

	if isHighRiskBIN(bin) {
		factors = append(factors, domain.RiskFactor{
			Name:        "bin_high_risk",
			Description: fmt.Sprintf("Card BIN %s is flagged for high fraud association", bin),
			ScoreDelta:  30,
		})
	} else if isPrepaidBIN(bin) {
		factors = append(factors, domain.RiskFactor{
			Name:        "bin_prepaid",
			Description: fmt.Sprintf("Card BIN %s is a prepaid card (commonly used in chargebacks)", bin),
			ScoreDelta:  15,
		})
	}

	return factors
}

// ─── Rule 9: Timing ───────────────────────────────────────────────────────────

func ruleTiming(ctx *ruleContext) []domain.RiskFactor {
	var factors []domain.RiskFactor

	// Fraud bots tend to operate in the 02:00–06:00 UTC window when fraud
	// operations teams are offline and approvals are unmonitored.
	hour := ctx.req.Timestamp.UTC().Hour()
	if hour >= 2 && hour < 6 {
		factors = append(factors, domain.RiskFactor{
			Name:        "off_hours",
			Description: fmt.Sprintf("Transaction at %02d:00 UTC (off-hours 02:00–06:00)", hour),
			ScoreDelta:  10,
		})
	}

	return factors
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// buildExplanation formats a score and its factors into a single readable string
// of the form used in the challenge spec example.
func buildExplanation(score int, factors []domain.RiskFactor) string {
	if len(factors) == 0 {
		return fmt.Sprintf("Risk Score: %d. No significant fraud indicators detected.", score)
	}

	parts := make([]string, len(factors))
	for i, f := range factors {
		if f.ScoreDelta > 0 {
			parts[i] = fmt.Sprintf("%s (+%d)", f.Description, f.ScoreDelta)
		} else {
			parts[i] = f.Description
		}
	}
	return fmt.Sprintf("Risk Score: %d. Factors: %s.", score, strings.Join(parts, "; "))
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// isLATAM returns true for the countries that are part of Lumina's core market.
// Cross-border transactions within this region are considered normal.
func isLATAM(country string) bool {
	switch country {
	case "BR", "MX", "AR", "CO", "CL", "PE", "VE", "EC", "BO", "PY", "UY", "CR", "PA":
		return true
	}
	return false
}

// isHighRiskCountry returns true for countries with historically elevated
// card fraud rates in the LATAM payment context.
func isHighRiskCountry(country string) bool {
	switch country {
	case "RU", "NG", "UA", "CN", "VN", "PK", "KP", "RO", "GH", "TZ":
		return true
	}
	return false
}

// isHighRiskBIN returns true for BINs that appear disproportionately in
// Lumina's chargeback records (simulated data for the challenge).
var highRiskBINs = map[string]bool{
	"400000": true,
	"411111": true,
	"420000": true,
	"490000": true,
	"510000": true,
	"520000": true,
	"552000": true,
	"601100": true,
}

func isHighRiskBIN(bin string) bool {
	return highRiskBINs[bin]
}

// isPrepaidBIN returns true for BINs identified as prepaid or gift cards.
// Prepaid cards lack the identity verification of regular bank-issued cards.
var prepaidBINs = map[string]bool{
	"472297": true,
	"483317": true,
	"491528": true,
	"523274": true,
	"535350": true,
	"544107": true,
}

func isPrepaidBIN(bin string) bool {
	return prepaidBINs[bin]
}
