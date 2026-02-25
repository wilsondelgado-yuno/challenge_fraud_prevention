// Package webhook handles asynchronous notifications to registered webhook URLs
// when a high-risk transaction is detected.
//
// Notifications are sent in a goroutine so they never block the HTTP response.
// Failed deliveries are logged but not retried (a production system would use
// a persistent queue with exponential backoff).
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"lumina/fraud-api/internal/domain"
	"lumina/fraud-api/internal/store"
)

// Notifier sends webhook payloads to all registered, active endpoints.
type Notifier struct {
	store  *store.Store
	client *http.Client
}

// New creates a Notifier with a sensible default HTTP client timeout.
func New(s *store.Store) *Notifier {
	return &Notifier{
		store: s,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// NotifyAsync fires webhook calls in the background for the given transaction.
// It checks every active webhook and triggers those whose threshold is met.
func (n *Notifier) NotifyAsync(tx *domain.Transaction) {
	hooks := n.store.ListActiveWebhooks()
	for _, wh := range hooks {
		if tx.RiskScore >= wh.Threshold {
			go n.send(wh, tx)
		}
	}
}

// send delivers a single webhook call and logs the outcome.
func (n *Notifier) send(wh *domain.WebhookConfig, tx *domain.Transaction) {
	payload := domain.WebhookPayload{
		Event:       "high_risk_transaction",
		TriggeredAt: time.Now().UTC(),
		Transaction: *tx,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("webhook: failed to marshal payload", "webhook_id", wh.ID, "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		slog.Error("webhook: failed to build request", "webhook_id", wh.ID, "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Lumina-Event", "high_risk_transaction")

	resp, err := n.client.Do(req)
	if err != nil {
		slog.Warn("webhook: delivery failed", "webhook_id", wh.ID, "url", wh.URL, "error", err)
		return
	}
	defer resp.Body.Close()

	slog.Info("webhook: delivered",
		"webhook_id", wh.ID,
		"url", wh.URL,
		"status", resp.StatusCode,
		"transaction_id", tx.TransactionID,
		"risk_score", tx.RiskScore,
	)
}
