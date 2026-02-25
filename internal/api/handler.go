package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"lumina/fraud-api/internal/domain"
	"lumina/fraud-api/internal/scoring"
	"lumina/fraud-api/internal/store"
	"lumina/fraud-api/internal/webhook"
)

// Handler holds the dependencies shared across all HTTP handlers.
type Handler struct {
	store    *store.Store
	engine   *scoring.Engine
	notifier *webhook.Notifier
}

// NewHandler creates a Handler wired to the given dependencies.
func NewHandler(s *store.Store, e *scoring.Engine, n *webhook.Notifier) *Handler {
	return &Handler{store: s, engine: e, notifier: n}
}

// ─── POST /api/v1/transactions ────────────────────────────────────────────────

// SubmitTransaction accepts a transaction payload, scores it, saves it, and
// returns the full risk analysis result synchronously.
func (h *Handler) SubmitTransaction(w http.ResponseWriter, r *http.Request) {
	var req domain.TransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "INVALID_JSON", "request body must be valid JSON")
		return
	}

	if err := validateTransactionRequest(&req); err != nil {
		badRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}

	// Score the transaction before saving so historical lookups exclude it.
	score, factors, explanation := h.engine.Score(&req)
	recommendation, riskLevel := scoring.Recommend(score)

	tx := &domain.Transaction{
		TransactionRequest: req,
		RiskScore:          score,
		RiskLevel:          riskLevel,
		Recommendation:     recommendation,
		Factors:            factors,
		Explanation:        explanation,
		ProcessedAt:        time.Now().UTC(),
	}

	if err := h.store.SaveTransaction(tx); err != nil {
		if err == store.ErrDuplicateTransaction {
			conflict(w, fmt.Sprintf("transaction '%s' already exists", req.TransactionID))
			return
		}
		internalError(w)
		return
	}

	// Fire async webhook notifications for high-risk transactions.
	h.notifier.NotifyAsync(tx)

	created(w, tx)
}

// ─── GET /api/v1/transactions/{id} ───────────────────────────────────────────

// GetTransaction retrieves a previously scored transaction by its ID.
func (h *Handler) GetTransaction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tx, exists := h.store.GetTransaction(id)
	if !exists {
		notFound(w, fmt.Sprintf("transaction '%s' not found", id))
		return
	}
	ok(w, tx)
}

// ─── GET /api/v1/entities/{type}/{value} ─────────────────────────────────────

// GetEntitySummary returns aggregated activity for a tracked entity
// (email, ip, bin, or device) over a configurable look-back window.
//
// Query params:
//   days — look-back window in days (default: 7, max: 90)
func (h *Handler) GetEntitySummary(w http.ResponseWriter, r *http.Request) {
	entityType := strings.ToLower(chi.URLParam(r, "type"))
	rawValue := chi.URLParam(r, "value")
	entityValue, _ := url.PathUnescape(rawValue)

	validTypes := map[string]bool{
		domain.EntityEmail:  true,
		domain.EntityIP:     true,
		domain.EntityBIN:    true,
		domain.EntityDevice: true,
	}
	if !validTypes[entityType] {
		badRequest(w, "INVALID_ENTITY_TYPE",
			"entity type must be one of: email, ip, bin, device")
		return
	}

	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		parsed, err := strconv.Atoi(d)
		if err != nil || parsed < 1 || parsed > 90 {
			badRequest(w, "INVALID_PARAM", "days must be an integer between 1 and 90")
			return
		}
		days = parsed
	}

	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	var txns []*domain.Transaction
	switch entityType {
	case domain.EntityEmail:
		txns = h.store.GetTransactionsByEmail(entityValue, since)
	case domain.EntityIP:
		txns = h.store.GetTransactionsByIP(entityValue, since)
	case domain.EntityBIN:
		txns = h.store.GetTransactionsByBIN(entityValue, since)
	case domain.EntityDevice:
		txns = h.store.GetTransactionsByDevice(entityValue, since)
	}

	// Sort newest first for readability.
	sort.Slice(txns, func(i, j int) bool {
		return txns[i].Timestamp.After(txns[j].Timestamp)
	})

	summary := buildEntitySummary(entityType, entityValue, days, txns)
	ok(w, summary)
}

func buildEntitySummary(entityType, entityValue string, days int, txns []*domain.Transaction) domain.EntitySummary {
	var totalScore int
	var totalAmount float64
	var highRisk int
	derefd := make([]domain.Transaction, len(txns))

	for i, tx := range txns {
		derefd[i] = *tx
		totalScore += tx.RiskScore
		totalAmount += tx.Amount
		if tx.RiskScore > domain.ThresholdReview {
			highRisk++
		}
	}

	var avg float64
	if len(txns) > 0 {
		avg = float64(totalScore) / float64(len(txns))
	}

	return domain.EntitySummary{
		EntityType:    entityType,
		EntityValue:   entityValue,
		Period:        fmt.Sprintf("last_%d_days", days),
		TotalCount:    len(txns),
		HighRiskCount: highRisk,
		AvgRiskScore:  avg,
		TotalAmount:   totalAmount,
		Transactions:  derefd,
	}
}

// ─── Blocklist ────────────────────────────────────────────────────────────────

// ListBlocklist returns all active blocklist/allowlist entries.
func (h *Handler) ListBlocklist(w http.ResponseWriter, r *http.Request) {
	entries := h.store.ListBlocklistEntries()
	if entries == nil {
		entries = []*domain.BlocklistEntry{}
	}
	ok(w, entries)
}

// AddBlocklistEntry adds an entity to the block or allow list.
func (h *Handler) AddBlocklistEntry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type      string     `json:"type"`
		Value     string     `json:"value"`
		ListType  string     `json:"list_type"`
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "INVALID_JSON", "request body must be valid JSON")
		return
	}

	validTypes := map[string]bool{
		domain.EntityEmail: true, domain.EntityIP: true,
		domain.EntityBIN: true, domain.EntityDevice: true,
	}
	if !validTypes[req.Type] {
		badRequest(w, "INVALID_TYPE", "type must be one of: email, ip, bin, device")
		return
	}
	if req.Value == "" {
		badRequest(w, "MISSING_VALUE", "value is required")
		return
	}
	if req.ListType != domain.ListBlock && req.ListType != domain.ListAllow {
		badRequest(w, "INVALID_LIST_TYPE", "list_type must be 'block' or 'allow'")
		return
	}

	entry := &domain.BlocklistEntry{
		ID:        uuid.NewString(),
		Type:      req.Type,
		Value:     req.Value,
		ListType:  req.ListType,
		Reason:    req.Reason,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: req.ExpiresAt,
	}

	h.store.SaveBlocklistEntry(entry)
	created(w, entry)
}

// DeleteBlocklistEntry removes an entry from the blocklist/allowlist.
func (h *Handler) DeleteBlocklistEntry(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.store.DeleteBlocklistEntry(id) {
		notFound(w, fmt.Sprintf("blocklist entry '%s' not found", id))
		return
	}
	noContent(w)
}

// ─── Reports ──────────────────────────────────────────────────────────────────

// GetFraudReport generates a summary of detected fraud patterns in the last 24 hours.
func (h *Handler) GetFraudReport(w http.ResponseWriter, r *http.Request) {
	since := time.Now().UTC().Add(-24 * time.Hour)
	allTxns := h.store.GetAllTransactions(since)

	report := buildFraudReport(allTxns)
	ok(w, report)
}

func buildFraudReport(txns []*domain.Transaction) domain.FraudReport {
	var highRisk, medRisk, lowRisk int
	var totalScore int
	var flaggedAmount float64

	// Aggregate by IP, email, BIN for pattern detection.
	ipCounts := make(map[string]int)
	emailCounts := make(map[string]int)
	binCounts := make(map[string]int)
	ipAmounts := make(map[string]float64)

	// Track card cycling: IP → set of BINs
	ipBINs := make(map[string]map[string]bool)

	for _, tx := range txns {
		totalScore += tx.RiskScore

		switch {
		case tx.RiskScore > domain.ThresholdReview:
			highRisk++
			flaggedAmount += tx.Amount
		case tx.RiskScore > domain.ThresholdApprove:
			medRisk++
		default:
			lowRisk++
		}

		ipCounts[tx.IPAddress]++
		emailCounts[tx.UserEmail]++
		binCounts[tx.CardBIN]++
		ipAmounts[tx.IPAddress] += tx.Amount

		if ipBINs[tx.IPAddress] == nil {
			ipBINs[tx.IPAddress] = make(map[string]bool)
		}
		ipBINs[tx.IPAddress][tx.CardBIN] = true
	}

	var patterns []domain.FraudPattern

	// Pattern: IP velocity
	for ip, count := range ipCounts {
		if count >= 5 {
			patterns = append(patterns, domain.FraudPattern{
				Type:        "ip_velocity",
				Description: fmt.Sprintf("IP %s made %d transactions in 24 hours", ip, count),
				Count:       count,
				TotalAmount: ipAmounts[ip],
			})
		}
	}

	// Pattern: email velocity
	for email, count := range emailCounts {
		if count >= 5 {
			patterns = append(patterns, domain.FraudPattern{
				Type:        "email_velocity",
				Description: fmt.Sprintf("Email %s made %d transactions in 24 hours", email, count),
				Count:       count,
			})
		}
	}

	// Pattern: card cycling (many BINs from one IP)
	for ip, bins := range ipBINs {
		if len(bins) >= 3 {
			patterns = append(patterns, domain.FraudPattern{
				Type:        "card_cycling",
				Description: fmt.Sprintf("IP %s used %d distinct card BINs", ip, len(bins)),
				Count:       len(bins),
				TotalAmount: ipAmounts[ip],
			})
		}
	}

	// Pattern: BIN concentration (single card used many times across accounts)
	for bin, count := range binCounts {
		if count >= 5 {
			patterns = append(patterns, domain.FraudPattern{
				Type:        "bin_concentration",
				Description: fmt.Sprintf("Card BIN %s appeared in %d transactions", bin, count),
				Count:       count,
			})
		}
	}

	// Sort patterns by count descending so the most severe appear first.
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Count > patterns[j].Count
	})

	var avg float64
	if len(txns) > 0 {
		avg = float64(totalScore) / float64(len(txns))
	}

	return domain.FraudReport{
		GeneratedAt: time.Now().UTC(),
		Period:      "last_24_hours",
		Summary: domain.ReportSummary{
			TotalTransactions:  len(txns),
			HighRiskCount:      highRisk,
			MediumRiskCount:    medRisk,
			LowRiskCount:       lowRisk,
			AvgRiskScore:       avg,
			TotalFlaggedAmount: flaggedAmount,
		},
		Patterns: patterns,
	}
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

// RegisterWebhook adds a new webhook endpoint.
func (h *Handler) RegisterWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL       string `json:"url"`
		Threshold int    `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "INVALID_JSON", "request body must be valid JSON")
		return
	}
	if req.URL == "" {
		badRequest(w, "MISSING_URL", "url is required")
		return
	}
	if req.Threshold < 0 || req.Threshold > 100 {
		badRequest(w, "INVALID_THRESHOLD", "threshold must be between 0 and 100")
		return
	}
	if req.Threshold == 0 {
		req.Threshold = 80 // sensible default per the spec
	}

	wh := &domain.WebhookConfig{
		ID:        uuid.NewString(),
		URL:       req.URL,
		Threshold: req.Threshold,
		CreatedAt: time.Now().UTC(),
		Active:    true,
	}
	h.store.SaveWebhook(wh)
	created(w, wh)
}

// DeleteWebhook deactivates and removes a webhook.
func (h *Handler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.store.DeleteWebhook(id) {
		notFound(w, fmt.Sprintf("webhook '%s' not found", id))
		return
	}
	noContent(w)
}

// ─── Admin ────────────────────────────────────────────────────────────────────

// SeedData loads an array of TransactionRequests from the request body,
// scores them, and persists them. Useful for populating the store in demo environments.
func (h *Handler) SeedData(w http.ResponseWriter, r *http.Request) {
	var requests []domain.TransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
		badRequest(w, "INVALID_JSON", "body must be a JSON array of transaction requests")
		return
	}

	var loaded, skipped int
	for i := range requests {
		req := &requests[i]
		score, factors, explanation := h.engine.Score(req)
		recommendation, riskLevel := scoring.Recommend(score)

		tx := &domain.Transaction{
			TransactionRequest: *req,
			RiskScore:          score,
			RiskLevel:          riskLevel,
			Recommendation:     recommendation,
			Factors:            factors,
			Explanation:        explanation,
			ProcessedAt:        time.Now().UTC(),
		}

		if err := h.store.SaveTransaction(tx); err != nil {
			skipped++
		} else {
			loaded++
		}
	}

	ok(w, map[string]int{"loaded": loaded, "skipped_duplicates": skipped})
}

// ─── Validation ───────────────────────────────────────────────────────────────

func validateTransactionRequest(req *domain.TransactionRequest) error {
	if req.TransactionID == "" {
		return fmt.Errorf("transaction_id is required")
	}
	if req.Amount <= 0 {
		return fmt.Errorf("amount must be greater than 0")
	}
	if req.Currency == "" {
		return fmt.Errorf("currency is required")
	}
	if req.UserEmail == "" {
		return fmt.Errorf("user_email is required")
	}
	if req.IPAddress == "" {
		return fmt.Errorf("ip_address is required")
	}
	if req.CardBIN == "" {
		return fmt.Errorf("card_bin is required")
	}
	if req.DeviceFingerprint == "" {
		return fmt.Errorf("device_fingerprint is required")
	}
	if req.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if req.AccountCreatedAt.IsZero() {
		return fmt.Errorf("account_created_at is required")
	}
	return nil
}
