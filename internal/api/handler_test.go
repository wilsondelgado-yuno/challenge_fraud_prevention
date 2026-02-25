package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lumina/fraud-api/internal/api"
	"lumina/fraud-api/internal/scoring"
	"lumina/fraud-api/internal/store"
	"lumina/fraud-api/internal/webhook"
)

// ─── Test server setup ────────────────────────────────────────────────────────

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := store.New()
	e := scoring.New(s)
	n := webhook.New(s)
	h := api.NewHandler(s, e, n)
	return httptest.NewServer(api.NewRouter(h))
}

func post(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func get(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func del(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	return resp
}

func decodeData(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	d, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("response has no 'data' key: %v", env)
	}
	return d
}

func decodeError(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	e, ok := env["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no 'error' key: %v", env)
	}
	return e
}

func validTxPayload(id string) map[string]any {
	return map[string]any{
		"transaction_id":     id,
		"timestamp":          "2026-02-25T14:00:00Z",
		"amount":             50.0,
		"currency":           "BRL",
		"user_email":         "test@example.com",
		"ip_address":         "177.10.20.30",
		"ip_country":         "BR",
		"card_bin":           "453211",
		"card_country":       "BR",
		"device_fingerprint": "device-test",
		"account_created_at": "2025-01-01T00:00:00Z",
		"merchant_country":   "BR",
	}
}

// ─── Health ───────────────────────────────────────────────────────────────────

func TestHealth_Returns200(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := get(t, srv, "/health")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ─── POST /api/v1/transactions ────────────────────────────────────────────────

func TestSubmitTransaction_ValidRequest_Returns201(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/transactions", validTxPayload("tx-api-001"))
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
}

func TestSubmitTransaction_ResponseHasRiskScore(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/transactions", validTxPayload("tx-api-002"))
	d := decodeData(t, resp)

	if _, ok := d["risk_score"]; !ok {
		t.Error("response must contain 'risk_score'")
	}
	if _, ok := d["recommendation"]; !ok {
		t.Error("response must contain 'recommendation'")
	}
	if _, ok := d["explanation"]; !ok {
		t.Error("response must contain 'explanation'")
	}
	if _, ok := d["factors"]; !ok {
		t.Error("response must contain 'factors'")
	}
}

func TestSubmitTransaction_DuplicateID_Returns409(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	payload := validTxPayload("dup-tx")
	post(t, srv, "/api/v1/transactions", payload)
	resp := post(t, srv, "/api/v1/transactions", payload)

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409, got %d", resp.StatusCode)
	}
}

func TestSubmitTransaction_MissingField_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	bad := validTxPayload("bad-001")
	delete(bad, "user_email")
	resp := post(t, srv, "/api/v1/transactions", bad)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	e := decodeError(t, resp)
	if e["code"] != "VALIDATION_ERROR" {
		t.Errorf("expected VALIDATION_ERROR, got %v", e["code"])
	}
}

func TestSubmitTransaction_InvalidJSON_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/transactions", "application/json",
		bytes.NewBufferString("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSubmitTransaction_ZeroAmount_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	bad := validTxPayload("zero-amount")
	bad["amount"] = 0.0
	resp := post(t, srv, "/api/v1/transactions", bad)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSubmitTransaction_ObviousFraud_ScoresHigh(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	payload := map[string]any{
		"transaction_id":     "fraud-api-001",
		"timestamp":          "2026-02-25T03:30:00Z",
		"amount":             99.99,
		"currency":           "BRL",
		"user_email":         "fraud@ring.net",
		"ip_address":         "185.100.87.12",
		"ip_country":         "RU",
		"card_bin":           "400000",
		"card_country":       "US",
		"device_fingerprint": "dev-fraud",
		"account_created_at": "2026-02-25T03:15:00Z",
		"merchant_country":   "BR",
	}

	resp := post(t, srv, "/api/v1/transactions", payload)
	d := decodeData(t, resp)

	score := d["risk_score"].(float64)
	if score < 71 {
		t.Errorf("obvious fraud should score > 70, got %.0f", score)
	}
	if d["recommendation"] != "decline" {
		t.Errorf("expected decline, got %v", d["recommendation"])
	}
}

// ─── GET /api/v1/transactions/{id} ───────────────────────────────────────────

func TestGetTransaction_Exists_Returns200(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	post(t, srv, "/api/v1/transactions", validTxPayload("get-001"))
	resp := get(t, srv, "/api/v1/transactions/get-001")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	d := decodeData(t, resp)
	if d["transaction_id"] != "get-001" {
		t.Errorf("expected transaction_id=get-001, got %v", d["transaction_id"])
	}
}

func TestGetTransaction_NotFound_Returns404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := get(t, srv, "/api/v1/transactions/ghost-tx")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── GET /api/v1/entities/{type}/{value} ─────────────────────────────────────

func TestGetEntitySummary_ValidEmail_Returns200(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	post(t, srv, "/api/v1/transactions", validTxPayload("ent-001"))
	resp := get(t, srv, "/api/v1/entities/email/test%40example.com")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	d := decodeData(t, resp)
	if d["total_count"].(float64) < 1 {
		t.Error("expected at least 1 transaction in summary")
	}
}

func TestGetEntitySummary_ValidIP_Returns200(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	post(t, srv, "/api/v1/transactions", validTxPayload("ent-ip-001"))
	resp := get(t, srv, "/api/v1/entities/ip/177.10.20.30")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGetEntitySummary_InvalidType_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := get(t, srv, "/api/v1/entities/foobar/somevalue")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestGetEntitySummary_EmptyHistory_ReturnsZeroCount(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := get(t, srv, "/api/v1/entities/email/nobody%40nowhere.com")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	d := decodeData(t, resp)
	if d["total_count"].(float64) != 0 {
		t.Errorf("expected 0, got %v", d["total_count"])
	}
}

func TestGetEntitySummary_InvalidDaysParam_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := get(t, srv, "/api/v1/entities/ip/1.2.3.4?days=999")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for days>90, got %d", resp.StatusCode)
	}
}

// ─── Blocklist ────────────────────────────────────────────────────────────────

func TestBlocklist_AddAndList(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	post(t, srv, "/api/v1/blocklist", map[string]any{
		"type": "ip", "value": "9.8.7.6", "list_type": "block", "reason": "test",
	})

	resp := get(t, srv, "/api/v1/blocklist")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestBlocklist_Add_Returns201(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/blocklist", map[string]any{
		"type": "email", "value": "bad@evil.com", "list_type": "block", "reason": "test",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
}

func TestBlocklist_Add_InvalidType_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/blocklist", map[string]any{
		"type": "phone", "value": "1234", "list_type": "block",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestBlocklist_Add_InvalidListType_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/blocklist", map[string]any{
		"type": "ip", "value": "1.2.3.4", "list_type": "whitelist",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestBlocklist_Delete_Returns204(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	addResp := post(t, srv, "/api/v1/blocklist", map[string]any{
		"type": "ip", "value": "11.22.33.44", "list_type": "block", "reason": "del test",
	})
	d := decodeData(t, addResp)
	id := d["id"].(string)

	resp := del(t, srv, "/api/v1/blocklist/"+id)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}
}

func TestBlocklist_DeleteMissing_Returns404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := del(t, srv, "/api/v1/blocklist/nonexistent-id")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestBlocklist_BlockedEntity_ScoresMax(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	post(t, srv, "/api/v1/blocklist", map[string]any{
		"type": "ip", "value": "1.1.1.1", "list_type": "block", "reason": "blocked",
	})

	payload := validTxPayload("blocked-tx")
	payload["ip_address"] = "1.1.1.1"
	payload["transaction_id"] = "blocked-ip-tx"
	resp := post(t, srv, "/api/v1/transactions", payload)
	d := decodeData(t, resp)

	if d["risk_score"].(float64) != 100 {
		t.Errorf("blocked IP transaction should score 100, got %v", d["risk_score"])
	}
}

func TestBlocklist_AllowedEntity_ScoresZero(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	post(t, srv, "/api/v1/blocklist", map[string]any{
		"type": "email", "value": "vip@lumina.com", "list_type": "allow", "reason": "VIP",
	})

	payload := validTxPayload("vip-tx")
	payload["user_email"] = "vip@lumina.com"
	payload["ip_country"] = "RU" // would score high otherwise
	resp := post(t, srv, "/api/v1/transactions", payload)
	d := decodeData(t, resp)

	if d["risk_score"].(float64) != 0 {
		t.Errorf("allowlisted transaction should score 0, got %v", d["risk_score"])
	}
}

// ─── Reports ──────────────────────────────────────────────────────────────────

func TestFraudReport_Returns200(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := get(t, srv, "/api/v1/reports/fraud-patterns")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	d := decodeData(t, resp)
	if _, ok := d["summary"]; !ok {
		t.Error("report must contain 'summary'")
	}
	if _, ok := d["patterns"]; !ok {
		t.Error("report must contain 'patterns'")
	}
}

func TestFraudReport_DetectsIPVelocity(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// Submit 6 transactions from the same IP within 24h (above threshold of 5).
	base := time.Now().UTC()
	for i := 0; i < 6; i++ {
		payload := map[string]any{
			"transaction_id":     fmt.Sprintf("rpt-vel-%d", i),
			"timestamp":          base.Add(-time.Duration(i*10) * time.Minute).Format(time.RFC3339),
			"amount":             50.0,
			"currency":           "BRL",
			"user_email":         fmt.Sprintf("u%d@test.com", i),
			"ip_address":         "77.77.77.77",
			"ip_country":         "BR",
			"card_bin":           "453211",
			"card_country":       "BR",
			"device_fingerprint": fmt.Sprintf("dev-%d", i),
			"account_created_at": "2025-01-01T00:00:00Z",
			"merchant_country":   "BR",
		}
		post(t, srv, "/api/v1/transactions", payload)
	}

	resp := get(t, srv, "/api/v1/reports/fraud-patterns")
	d := decodeData(t, resp)
	patterns := d["patterns"].([]any)

	found := false
	for _, p := range patterns {
		pm := p.(map[string]any)
		if pm["type"].(string) == "ip_velocity" {
			found = true
		}
	}
	if !found {
		t.Error("expected ip_velocity pattern in report after 6 transactions from same IP")
	}
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

func TestWebhook_Register_Returns201(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/webhooks", map[string]any{
		"url": "http://example.com/hook", "threshold": 80,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	d := decodeData(t, resp)
	if d["id"] == "" {
		t.Error("response must include webhook id")
	}
}

func TestWebhook_MissingURL_Returns400(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/webhooks", map[string]any{"threshold": 80})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWebhook_DefaultThreshold_Is80(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := post(t, srv, "/api/v1/webhooks", map[string]any{
		"url": "http://example.com/hook", "threshold": 0,
	})
	d := decodeData(t, resp)
	if d["threshold"].(float64) != 80 {
		t.Errorf("expected default threshold 80, got %v", d["threshold"])
	}
}

func TestWebhook_Delete_Returns204(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	addResp := post(t, srv, "/api/v1/webhooks", map[string]any{
		"url": "http://example.com/hook", "threshold": 80,
	})
	d := decodeData(t, addResp)
	id := d["id"].(string)

	resp := del(t, srv, "/api/v1/webhooks/"+id)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}
}

func TestWebhook_DeleteMissing_Returns404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	resp := del(t, srv, "/api/v1/webhooks/ghost-id")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// ─── Admin seed ───────────────────────────────────────────────────────────────

func TestAdminSeed_LoadsTransactions(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	seed := []map[string]any{
		{
			"transaction_id": "seed-1", "timestamp": "2026-02-24T10:00:00Z",
			"amount": 50.0, "currency": "BRL", "user_email": "seed@seed.com",
			"ip_address": "1.2.3.4", "ip_country": "BR", "card_bin": "453211",
			"card_country": "BR", "device_fingerprint": "seed-dev",
			"account_created_at": "2025-01-01T00:00:00Z", "merchant_country": "BR",
		},
		{
			"transaction_id": "seed-2", "timestamp": "2026-02-24T11:00:00Z",
			"amount": 55.0, "currency": "BRL", "user_email": "seed@seed.com",
			"ip_address": "1.2.3.4", "ip_country": "BR", "card_bin": "453211",
			"card_country": "BR", "device_fingerprint": "seed-dev",
			"account_created_at": "2025-01-01T00:00:00Z", "merchant_country": "BR",
		},
	}

	resp := post(t, srv, "/api/v1/admin/seed", seed)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	d := decodeData(t, resp)
	if d["loaded"].(float64) != 2 {
		t.Errorf("expected loaded=2, got %v", d["loaded"])
	}

	// Verify they're now queryable.
	txResp := get(t, srv, "/api/v1/transactions/seed-1")
	if txResp.StatusCode != http.StatusOK {
		t.Error("seeded transaction should be retrievable")
	}
}
