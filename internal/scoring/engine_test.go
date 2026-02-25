package scoring_test

import (
	"fmt"
	"testing"
	"time"

	"lumina/fraud-api/internal/domain"
	"lumina/fraud-api/internal/scoring"
	"lumina/fraud-api/internal/store"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newEngine() (*scoring.Engine, *store.Store) {
	s := store.New()
	return scoring.New(s), s
}

// baseReq returns a clean, low-risk transaction request as a starting point.
func baseReq(id string) *domain.TransactionRequest {
	return &domain.TransactionRequest{
		TransactionID:     id,
		Timestamp:         time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC),
		Amount:            50.0,
		Currency:          domain.BRL,
		UserEmail:         "user@example.com",
		IPAddress:         "177.10.20.30",
		IPCountry:         "BR",
		CardBIN:           "453211",
		CardCountry:       "BR",
		DeviceFingerprint: "device-abc",
		AccountCreatedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		MerchantCountry:   "BR",
	}
}

// save persists a request as a fully scored transaction so it becomes history.
func save(s *store.Store, e *scoring.Engine, req *domain.TransactionRequest) {
	score, factors, explanation := e.Score(req)
	rec, level := scoring.Recommend(score)
	_ = s.SaveTransaction(&domain.Transaction{
		TransactionRequest: *req,
		RiskScore:          score,
		RiskLevel:          level,
		Recommendation:     rec,
		Factors:            factors,
		Explanation:        explanation,
		ProcessedAt:        time.Now().UTC(),
	})
}

// factorNames extracts rule names from a factor slice for easy assertion.
func factorNames(factors []domain.RiskFactor) []string {
	names := make([]string, len(factors))
	for i, f := range factors {
		names[i] = f.Name
	}
	return names
}

func hasFactorName(factors []domain.RiskFactor, name string) bool {
	for _, f := range factors {
		if f.Name == name {
			return true
		}
	}
	return false
}

// ─── Score clamping ───────────────────────────────────────────────────────────

func TestScore_ClampedTo100(t *testing.T) {
	e, s := newEngine()
	req := baseReq("clamp-001")
	// Stack many high-scoring signals.
	req.IPCountry = "RU"
	req.CardCountry = "US"
	req.MerchantCountry = "BR"
	req.CardBIN = "400000" // known high-risk BIN
	req.AccountCreatedAt = req.Timestamp.Add(-5 * time.Minute)
	req.Timestamp = req.Timestamp.Add(-11 * time.Hour) // 03:00 UTC

	// Pre-populate velocity history.
	for i := 0; i < 5; i++ {
		r := baseReq(fmt.Sprintf("clamp-hist-%d", i))
		r.UserEmail = req.UserEmail
		r.Timestamp = req.Timestamp.Add(-time.Duration(i+1) * time.Minute)
		save(s, e, r)
	}

	score, _, _ := e.Score(req)
	if score != 100 {
		t.Errorf("expected score clamped to 100, got %d", score)
	}
}

func TestScore_MinimumIsZero(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("zero-001")
	score, _, _ := e.Score(req)
	if score < 0 {
		t.Errorf("score must not be negative, got %d", score)
	}
}

// ─── Blocklist / Allowlist ────────────────────────────────────────────────────

func TestScore_BlocklistedEmail_Returns100(t *testing.T) {
	e, s := newEngine()
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID:       "bl-1",
		Type:     domain.EntityEmail,
		Value:    "bad@fraud.com",
		ListType: domain.ListBlock,
		Reason:   "test",
	})

	req := baseReq("bl-email-001")
	req.UserEmail = "bad@fraud.com"
	score, factors, _ := e.Score(req)

	if score != 100 {
		t.Errorf("expected 100 for blocklisted email, got %d", score)
	}
	if !hasFactorName(factors, "blocklist_match") {
		t.Errorf("expected factor 'blocklist_match', got %v", factorNames(factors))
	}
}

func TestScore_AllowlistedEmail_Returns0(t *testing.T) {
	e, s := newEngine()
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID:       "al-1",
		Type:     domain.EntityEmail,
		Value:    "vip@lumina.com",
		ListType: domain.ListAllow,
		Reason:   "VIP account",
	})

	req := baseReq("al-email-001")
	req.UserEmail = "vip@lumina.com"
	req.IPCountry = "RU" // would normally add score
	score, factors, _ := e.Score(req)

	if score != 0 {
		t.Errorf("expected 0 for allowlisted email, got %d", score)
	}
	if !hasFactorName(factors, "allowlist_match") {
		t.Errorf("expected factor 'allowlist_match', got %v", factorNames(factors))
	}
}

func TestScore_BlocklistedIP_Returns100(t *testing.T) {
	e, s := newEngine()
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID: "bl-ip-1", Type: domain.EntityIP, Value: "1.2.3.4", ListType: domain.ListBlock,
	})
	req := baseReq("bl-ip-001")
	req.IPAddress = "1.2.3.4"
	score, _, _ := e.Score(req)
	if score != 100 {
		t.Errorf("expected 100 for blocklisted IP, got %d", score)
	}
}

func TestScore_BlocklistedBIN_Returns100(t *testing.T) {
	e, s := newEngine()
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID: "bl-bin-1", Type: domain.EntityBIN, Value: "999999", ListType: domain.ListBlock,
	})
	req := baseReq("bl-bin-001")
	req.CardBIN = "999999"
	score, _, _ := e.Score(req)
	if score != 100 {
		t.Errorf("expected 100 for blocklisted BIN, got %d", score)
	}
}

func TestScore_ExpiredBlocklist_IsIgnored(t *testing.T) {
	e, s := newEngine()
	past := time.Now().Add(-1 * time.Hour)
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID:        "bl-exp-1",
		Type:      domain.EntityEmail,
		Value:     "expired@fraud.com",
		ListType:  domain.ListBlock,
		ExpiresAt: &past,
	})
	req := baseReq("bl-exp-001")
	req.UserEmail = "expired@fraud.com"
	score, _, _ := e.Score(req)
	if score == 100 {
		t.Error("expired blocklist entry should not produce score 100")
	}
}

// ─── Velocity — email ─────────────────────────────────────────────────────────

func TestScore_EmailVelocity_24h_TriggersAt2(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	// Save 2 prior transactions within 24 h.
	for i := 1; i <= 2; i++ {
		r := baseReq(fmt.Sprintf("vel-hist-%d", i))
		r.Timestamp = base.Add(-time.Duration(i) * time.Hour)
		save(s, e, r)
	}

	req := baseReq("vel-email-001")
	req.Timestamp = base
	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "email_velocity_24h") {
		t.Errorf("expected email_velocity_24h, got %v", factorNames(factors))
	}
}

func TestScore_EmailVelocity_10min_TriggersAt2(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	for i := 1; i <= 2; i++ {
		r := baseReq(fmt.Sprintf("fast-hist-%d", i))
		r.Timestamp = base.Add(-time.Duration(i*2) * time.Minute)
		save(s, e, r)
	}

	req := baseReq("fast-email-001")
	req.Timestamp = base
	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "email_velocity_10min") {
		t.Errorf("expected email_velocity_10min, got %v", factorNames(factors))
	}
}

func TestScore_EmailVelocity_NotTriggeredFor1Prior(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	r := baseReq("single-hist-1")
	r.Timestamp = base.Add(-30 * time.Minute)
	save(s, e, r)

	req := baseReq("single-001")
	req.Timestamp = base
	_, factors, _ := e.Score(req)

	if hasFactorName(factors, "email_velocity_10min") {
		t.Error("email_velocity_10min should not trigger with only 1 prior transaction")
	}
}

// ─── Velocity — IP ────────────────────────────────────────────────────────────

func TestScore_IPVelocity_TriggersAt3(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	for i := 1; i <= 3; i++ {
		r := baseReq(fmt.Sprintf("ip-hist-%d", i))
		r.UserEmail = fmt.Sprintf("different%d@user.com", i)
		r.Timestamp = base.Add(-time.Duration(i*10) * time.Minute)
		save(s, e, r)
	}

	req := baseReq("ip-vel-001")
	req.Timestamp = base
	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "ip_velocity_1h") {
		t.Errorf("expected ip_velocity_1h, got %v", factorNames(factors))
	}
}

func TestScore_IPVelocity_OutsideWindow_NotTriggered(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	// 3 transactions but older than 1 hour.
	for i := 1; i <= 3; i++ {
		r := baseReq(fmt.Sprintf("ip-old-%d", i))
		r.UserEmail = fmt.Sprintf("old%d@user.com", i)
		r.Timestamp = base.Add(-time.Duration(i*30+60) * time.Minute)
		save(s, e, r)
	}

	req := baseReq("ip-old-001")
	req.Timestamp = base
	_, factors, _ := e.Score(req)

	if hasFactorName(factors, "ip_velocity_1h") {
		t.Error("ip_velocity_1h should not trigger for transactions outside the 1h window")
	}
}

// ─── Velocity — device ────────────────────────────────────────────────────────

func TestScore_DeviceVelocity_TriggersAt2(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	// The rule fires when there are >= 2 prior transactions on the same device.
	for i := 1; i <= 2; i++ {
		r := baseReq(fmt.Sprintf("dev-hist-%d", i))
		r.UserEmail = fmt.Sprintf("other%d@user.com", i)
		r.Timestamp = base.Add(-time.Duration(i*5) * time.Minute)
		save(s, e, r)
	}

	req := baseReq("dev-vel-001")
	req.Timestamp = base
	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "device_velocity_30min") {
		t.Errorf("expected device_velocity_30min, got %v", factorNames(factors))
	}
}

// ─── Velocity — card cycling ──────────────────────────────────────────────────

func TestScore_CardCycling_TriggersAt3UniqueBINs(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)
	bins := []string{"111111", "222222", "333333"}

	for i, bin := range bins {
		r := baseReq(fmt.Sprintf("cycling-%d", i))
		r.CardBIN = bin
		r.UserEmail = fmt.Sprintf("card%d@user.com", i)
		r.Timestamp = base.Add(-time.Duration(i+1) * time.Hour)
		save(s, e, r)
	}

	req := baseReq("cycling-001")
	req.Timestamp = base
	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "card_cycling_ip") {
		t.Errorf("expected card_cycling_ip, got %v", factorNames(factors))
	}
}

// ─── Geography ────────────────────────────────────────────────────────────────

func TestScore_IPCardMismatch_Adds25(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("geo-001")
	req.IPCountry = "RU"
	req.CardCountry = "BR"

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "geo_ip_card_mismatch" {
			if f.ScoreDelta != 25 {
				t.Errorf("expected +25 for IP/card mismatch, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected geo_ip_card_mismatch factor, got %v", factorNames(factors))
}

func TestScore_NoGeoMismatch_WhenSameCountry(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("geo-same-001")
	req.IPCountry = "BR"
	req.CardCountry = "BR"
	req.MerchantCountry = "BR"

	_, factors, _ := e.Score(req)

	for _, name := range []string{"geo_ip_card_mismatch", "geo_ip_merchant_mismatch", "geo_three_way_mismatch"} {
		if hasFactorName(factors, name) {
			t.Errorf("factor %s should not fire when all countries match", name)
		}
	}
}

func TestScore_HighRiskCountry_Adds15(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("geo-hr-001")
	req.IPCountry = "NG"

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "geo_high_risk_country" {
			if f.ScoreDelta != 15 {
				t.Errorf("expected +15 for high-risk country, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected geo_high_risk_country factor, got %v", factorNames(factors))
}

func TestScore_ThreeWayMismatch_FiresWhenAllDifferent(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("geo-3way-001")
	req.IPCountry = "RU"
	req.CardCountry = "US"
	req.MerchantCountry = "BR"

	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "geo_three_way_mismatch") {
		t.Errorf("expected geo_three_way_mismatch, got %v", factorNames(factors))
	}
}

func TestScore_LATAMCrossCountry_NoMerchantMismatch(t *testing.T) {
	// LATAM users playing on a LATAM merchant from a different LATAM country
	// should NOT trigger the merchant-mismatch penalty (normal Lumina usage).
	e, _ := newEngine()
	req := baseReq("geo-latam-001")
	req.IPCountry = "AR"
	req.CardCountry = "AR"
	req.MerchantCountry = "BR" // different LATAM country

	_, factors, _ := e.Score(req)

	if hasFactorName(factors, "geo_ip_merchant_mismatch") {
		t.Error("LATAM IP playing on a LATAM merchant should not trigger geo_ip_merchant_mismatch")
	}
}

// ─── Account age ──────────────────────────────────────────────────────────────

func TestScore_AccountAgeCritical_Under1Hour(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("age-001")
	req.AccountCreatedAt = req.Timestamp.Add(-30 * time.Minute)

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "account_age_critical" {
			if f.ScoreDelta != 25 {
				t.Errorf("expected +25 for account < 1h, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected account_age_critical, got %v", factorNames(factors))
}

func TestScore_AccountAgeNew_Under24Hours(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("age-002")
	req.AccountCreatedAt = req.Timestamp.Add(-6 * time.Hour)

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "account_age_new" {
			if f.ScoreDelta != 15 {
				t.Errorf("expected +15 for account < 24h, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected account_age_new, got %v", factorNames(factors))
}

func TestScore_AccountAgeWeek_Under7Days(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("age-003")
	req.AccountCreatedAt = req.Timestamp.Add(-3 * 24 * time.Hour)

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "account_age_week" {
			if f.ScoreDelta != 5 {
				t.Errorf("expected +5 for account < 7d, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected account_age_week, got %v", factorNames(factors))
}

func TestScore_AccountAgeOld_NoAgePenalty(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("age-004")
	req.AccountCreatedAt = req.Timestamp.Add(-365 * 24 * time.Hour)

	_, factors, _ := e.Score(req)

	for _, name := range []string{"account_age_critical", "account_age_new", "account_age_week"} {
		if hasFactorName(factors, name) {
			t.Errorf("old account should not trigger %s", name)
		}
	}
}

// ─── Purchase behaviour ───────────────────────────────────────────────────────

func TestScore_FirstTransaction_LowAmount_Gets5(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("behav-first-001")
	req.AccountCreatedAt = req.Timestamp.Add(-365 * 24 * time.Hour)
	req.Amount = 30.0

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "first_transaction" {
			if f.ScoreDelta != 5 {
				t.Errorf("expected +5 for small first transaction, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected first_transaction factor, got %v", factorNames(factors))
}

func TestScore_FirstTransaction_HighAmount_Gets15(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("behav-first-big-001")
	req.AccountCreatedAt = req.Timestamp.Add(-365 * 24 * time.Hour)
	req.Amount = 200.0

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "first_transaction" {
			if f.ScoreDelta != 15 {
				t.Errorf("expected +15 for large first transaction, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected first_transaction factor, got %v", factorNames(factors))
}

func TestScore_AmountAnomaly_3x_Adds10(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	// History: 3 transactions averaging $50
	for i := 1; i <= 3; i++ {
		r := baseReq(fmt.Sprintf("anomaly-hist-%d", i))
		r.Amount = 50.0
		r.Timestamp = base.Add(-time.Duration(i) * time.Hour)
		save(s, e, r)
	}

	req := baseReq("anomaly-001")
	req.Amount = 160.0 // 3.2x average
	req.Timestamp = base

	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "amount_anomaly_medium") {
		t.Errorf("expected amount_anomaly_medium (3x), got %v", factorNames(factors))
	}
}

func TestScore_AmountAnomaly_10x_Adds30(t *testing.T) {
	e, s := newEngine()
	base := time.Date(2026, 2, 25, 14, 0, 0, 0, time.UTC)

	for i := 1; i <= 3; i++ {
		r := baseReq(fmt.Sprintf("extreme-hist-%d", i))
		r.Amount = 50.0
		r.Timestamp = base.Add(-time.Duration(i) * time.Hour)
		save(s, e, r)
	}

	req := baseReq("extreme-001")
	req.Amount = 600.0 // 12x average
	req.Timestamp = base

	_, factors, _ := e.Score(req)

	if !hasFactorName(factors, "amount_anomaly_extreme") {
		t.Errorf("expected amount_anomaly_extreme (10x), got %v", factorNames(factors))
	}
}

// ─── Card BIN patterns ────────────────────────────────────────────────────────

func TestScore_HighRiskBIN_Adds30(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("bin-hr-001")
	req.CardBIN = "400000" // in the high-risk list

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "bin_high_risk" {
			if f.ScoreDelta != 30 {
				t.Errorf("expected +30 for high-risk BIN, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected bin_high_risk factor, got %v", factorNames(factors))
}

func TestScore_PrepaidBIN_Adds15(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("bin-prep-001")
	req.CardBIN = "472297" // in the prepaid list

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "bin_prepaid" {
			if f.ScoreDelta != 15 {
				t.Errorf("expected +15 for prepaid BIN, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected bin_prepaid factor, got %v", factorNames(factors))
}

func TestScore_NormalBIN_NoCardPenalty(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("bin-normal-001")
	req.CardBIN = "453211" // normal LATAM BIN

	_, factors, _ := e.Score(req)

	if hasFactorName(factors, "bin_high_risk") || hasFactorName(factors, "bin_prepaid") {
		t.Errorf("normal BIN should not trigger card penalties, got %v", factorNames(factors))
	}
}

// ─── Timing ───────────────────────────────────────────────────────────────────

func TestScore_OffHours_Adds10(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("timing-001")
	req.Timestamp = time.Date(2026, 2, 25, 3, 30, 0, 0, time.UTC) // 03:30 UTC

	_, factors, _ := e.Score(req)

	for _, f := range factors {
		if f.Name == "off_hours" {
			if f.ScoreDelta != 10 {
				t.Errorf("expected +10 for off-hours, got %d", f.ScoreDelta)
			}
			return
		}
	}
	t.Errorf("expected off_hours factor, got %v", factorNames(factors))
}

func TestScore_BusinessHours_NoTimingPenalty(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("timing-002")
	req.Timestamp = time.Date(2026, 2, 25, 15, 0, 0, 0, time.UTC) // 15:00 UTC

	_, factors, _ := e.Score(req)

	if hasFactorName(factors, "off_hours") {
		t.Error("business-hours transaction should not trigger off_hours")
	}
}

// ─── Recommendation ───────────────────────────────────────────────────────────

func TestRecommend_LowScore_Approve(t *testing.T) {
	rec, level := scoring.Recommend(20)
	if rec != domain.ActionApprove || level != domain.RiskLow {
		t.Errorf("score 20 should approve/low, got %s/%s", rec, level)
	}
}

func TestRecommend_BoundaryApprove_30(t *testing.T) {
	rec, level := scoring.Recommend(30)
	if rec != domain.ActionApprove || level != domain.RiskLow {
		t.Errorf("score 30 should approve/low, got %s/%s", rec, level)
	}
}

func TestRecommend_MediumScore_Review(t *testing.T) {
	rec, level := scoring.Recommend(50)
	if rec != domain.ActionReview || level != domain.RiskMedium {
		t.Errorf("score 50 should review/medium, got %s/%s", rec, level)
	}
}

func TestRecommend_BoundaryReview_31(t *testing.T) {
	rec, level := scoring.Recommend(31)
	if rec != domain.ActionReview || level != domain.RiskMedium {
		t.Errorf("score 31 should review/medium, got %s/%s", rec, level)
	}
}

func TestRecommend_BoundaryDecline_71(t *testing.T) {
	rec, level := scoring.Recommend(71)
	if rec != domain.ActionDecline || level != domain.RiskHigh {
		t.Errorf("score 71 should decline/high, got %s/%s", rec, level)
	}
}

func TestRecommend_HighScore_Decline(t *testing.T) {
	rec, level := scoring.Recommend(100)
	if rec != domain.ActionDecline || level != domain.RiskHigh {
		t.Errorf("score 100 should decline/high, got %s/%s", rec, level)
	}
}

// ─── Explanation string ───────────────────────────────────────────────────────

func TestScore_ExplanationIncludesScore(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("expl-001")
	req.CardBIN = "400000"
	score, _, explanation := e.Score(req)

	expected := fmt.Sprintf("Risk Score: %d.", score)
	if len(explanation) < len(expected) {
		t.Errorf("explanation too short: %q", explanation)
	}
}

func TestScore_ExplanationContainsDelta(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("expl-002")
	req.CardBIN = "400000"
	_, _, explanation := e.Score(req)

	if explanation == "" {
		t.Error("explanation should not be empty")
	}
	// Should contain "(+30)" for the high-risk BIN delta.
	if len(explanation) < 10 {
		t.Errorf("explanation suspiciously short: %q", explanation)
	}
}

// ─── Integration: obvious fraud scenario ─────────────────────────────────────

func TestScore_ObviousFraud_HighScore(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("fraud-int-001")
	req.IPCountry = "RU"
	req.CardCountry = "US"
	req.MerchantCountry = "BR"
	req.CardBIN = "400000"                                        // high-risk BIN
	req.AccountCreatedAt = req.Timestamp.Add(-15 * time.Minute)  // very new account
	req.Timestamp = time.Date(2026, 2, 25, 3, 30, 0, 0, time.UTC) // off-hours

	score, _, _ := e.Score(req)
	if score < 71 {
		t.Errorf("obvious fraud should score > 70, got %d", score)
	}
}

func TestScore_LegitTransaction_LowScore(t *testing.T) {
	e, _ := newEngine()
	req := baseReq("legit-int-001")
	// All fields already set to "normal" Brazilian values by baseReq.
	// Account is 1 year old, first transaction for this email.
	score, _, _ := e.Score(req)
	if score > 30 {
		t.Errorf("clean first transaction should score <= 30, got %d", score)
	}
}
