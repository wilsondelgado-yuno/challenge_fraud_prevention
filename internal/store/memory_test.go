package store_test

import (
	"testing"
	"time"

	"lumina/fraud-api/internal/domain"
	"lumina/fraud-api/internal/store"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newTx(id, email, ip, device, bin string, ts time.Time) *domain.Transaction {
	return &domain.Transaction{
		TransactionRequest: domain.TransactionRequest{
			TransactionID:     id,
			Timestamp:         ts,
			Amount:            50.0,
			Currency:          domain.BRL,
			UserEmail:         email,
			IPAddress:         ip,
			DeviceFingerprint: device,
			CardBIN:           bin,
		},
	}
}

var now = time.Now().UTC()

// ─── SaveTransaction ──────────────────────────────────────────────────────────

func TestSave_And_GetByID(t *testing.T) {
	s := store.New()
	tx := newTx("tx-001", "a@a.com", "1.1.1.1", "dev1", "111111", now)
	if err := s.SaveTransaction(tx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := s.GetTransaction("tx-001")
	if !ok {
		t.Fatal("expected to find tx-001")
	}
	if got.TransactionID != "tx-001" {
		t.Errorf("expected tx-001, got %s", got.TransactionID)
	}
}

func TestSave_DuplicateID_ReturnsError(t *testing.T) {
	s := store.New()
	tx := newTx("dup-001", "a@a.com", "1.1.1.1", "dev1", "111111", now)
	_ = s.SaveTransaction(tx)
	err := s.SaveTransaction(tx)
	if err != store.ErrDuplicateTransaction {
		t.Errorf("expected ErrDuplicateTransaction, got %v", err)
	}
}

func TestGet_MissingID_ReturnsFalse(t *testing.T) {
	s := store.New()
	_, ok := s.GetTransaction("nonexistent")
	if ok {
		t.Error("expected ok=false for missing transaction")
	}
}

// ─── Time-windowed lookups ────────────────────────────────────────────────────

func TestGetByEmail_ReturnsOnlyWithinWindow(t *testing.T) {
	s := store.New()

	inside := newTx("e-in-1", "user@x.com", "1.1.1.1", "d1", "111", now.Add(-30*time.Minute))
	outside := newTx("e-out-1", "user@x.com", "1.1.1.1", "d1", "111", now.Add(-2*time.Hour))
	_ = s.SaveTransaction(inside)
	_ = s.SaveTransaction(outside)

	since := now.Add(-1 * time.Hour)
	result := s.GetTransactionsByEmail("user@x.com", since)

	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
	if result[0].TransactionID != "e-in-1" {
		t.Errorf("expected e-in-1, got %s", result[0].TransactionID)
	}
}

func TestGetByIP_ReturnsOnlyWithinWindow(t *testing.T) {
	s := store.New()
	_ = s.SaveTransaction(newTx("ip-in-1", "a@a.com", "5.5.5.5", "d1", "111", now.Add(-20*time.Minute)))
	_ = s.SaveTransaction(newTx("ip-out-1", "b@b.com", "5.5.5.5", "d2", "222", now.Add(-90*time.Minute)))

	result := s.GetTransactionsByIP("5.5.5.5", now.Add(-1*time.Hour))
	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
}

func TestGetByDevice_ReturnsOnlyWithinWindow(t *testing.T) {
	s := store.New()
	_ = s.SaveTransaction(newTx("dv-in-1", "a@a.com", "1.1.1.1", "shared-dev", "111", now.Add(-5*time.Minute)))
	_ = s.SaveTransaction(newTx("dv-out-1", "b@b.com", "2.2.2.2", "shared-dev", "222", now.Add(-40*time.Minute)))

	result := s.GetTransactionsByDevice("shared-dev", now.Add(-30*time.Minute))
	if len(result) != 1 {
		t.Errorf("expected 1, got %d", len(result))
	}
}

func TestGetByBIN_ReturnsOnlyWithinWindow(t *testing.T) {
	s := store.New()
	_ = s.SaveTransaction(newTx("bin-in-1", "a@a.com", "1.1.1.1", "d1", "999999", now.Add(-10*time.Minute)))
	_ = s.SaveTransaction(newTx("bin-out-1", "b@b.com", "2.2.2.2", "d2", "999999", now.Add(-2*time.Hour)))

	result := s.GetTransactionsByBIN("999999", now.Add(-1*time.Hour))
	if len(result) != 1 {
		t.Errorf("expected 1, got %d", len(result))
	}
}

func TestGetByEmail_EmptyResult_WhenNoHistory(t *testing.T) {
	s := store.New()
	result := s.GetTransactionsByEmail("nobody@nowhere.com", now.Add(-24*time.Hour))
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %d", len(result))
	}
}

// ─── GetUniqueCardsByIP ───────────────────────────────────────────────────────

func TestGetUniqueCardsByIP_CountsDistinctBINs(t *testing.T) {
	s := store.New()
	_ = s.SaveTransaction(newTx("c1", "a@a.com", "9.9.9.9", "d1", "111111", now))
	_ = s.SaveTransaction(newTx("c2", "b@b.com", "9.9.9.9", "d2", "222222", now))
	_ = s.SaveTransaction(newTx("c3", "c@c.com", "9.9.9.9", "d3", "111111", now)) // repeat BIN

	count := s.GetUniqueCardsByIP("9.9.9.9")
	if count != 2 {
		t.Errorf("expected 2 unique BINs, got %d", count)
	}
}

func TestGetUniqueCardsByIP_ZeroForUnseenIP(t *testing.T) {
	s := store.New()
	if n := s.GetUniqueCardsByIP("0.0.0.0"); n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

// ─── GetAllTransactions ───────────────────────────────────────────────────────

func TestGetAllTransactions_FiltersCorrectly(t *testing.T) {
	s := store.New()
	_ = s.SaveTransaction(newTx("all-1", "a@a.com", "1.1.1.1", "d1", "111", now.Add(-30*time.Minute)))
	_ = s.SaveTransaction(newTx("all-2", "b@b.com", "2.2.2.2", "d2", "222", now.Add(-90*time.Minute)))
	_ = s.SaveTransaction(newTx("all-3", "c@c.com", "3.3.3.3", "d3", "333", now.Add(-10*time.Minute)))

	since := now.Add(-1 * time.Hour)
	result := s.GetAllTransactions(since)
	if len(result) != 2 {
		t.Errorf("expected 2 transactions within window, got %d", len(result))
	}
}

// ─── Blocklist ────────────────────────────────────────────────────────────────

func TestBlocklist_SaveAndCheck(t *testing.T) {
	s := store.New()
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID:       "bl-1",
		Type:     domain.EntityEmail,
		Value:    "bad@example.com",
		ListType: domain.ListBlock,
	})
	entry, ok := s.CheckBlocklist(domain.EntityEmail, "bad@example.com")
	if !ok {
		t.Fatal("expected to find blocklist entry")
	}
	if entry.ListType != domain.ListBlock {
		t.Errorf("expected block, got %s", entry.ListType)
	}
}

func TestBlocklist_ExpiredEntry_NotFound(t *testing.T) {
	s := store.New()
	past := time.Now().Add(-1 * time.Hour)
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID:        "bl-exp",
		Type:      domain.EntityIP,
		Value:     "1.2.3.4",
		ListType:  domain.ListBlock,
		ExpiresAt: &past,
	})
	_, ok := s.CheckBlocklist(domain.EntityIP, "1.2.3.4")
	if ok {
		t.Error("expired entry should not be found")
	}
}

func TestBlocklist_FutureExpiry_IsFound(t *testing.T) {
	s := store.New()
	future := time.Now().Add(24 * time.Hour)
	s.SaveBlocklistEntry(&domain.BlocklistEntry{
		ID:        "bl-fut",
		Type:      domain.EntityIP,
		Value:     "5.6.7.8",
		ListType:  domain.ListBlock,
		ExpiresAt: &future,
	})
	_, ok := s.CheckBlocklist(domain.EntityIP, "5.6.7.8")
	if !ok {
		t.Error("non-expired entry should be found")
	}
}

func TestBlocklist_Delete_RemovesEntry(t *testing.T) {
	s := store.New()
	s.SaveBlocklistEntry(&domain.BlocklistEntry{ID: "del-1", Type: domain.EntityEmail, Value: "x@x.com", ListType: domain.ListBlock})
	if !s.DeleteBlocklistEntry("del-1") {
		t.Fatal("expected delete to return true")
	}
	_, ok := s.CheckBlocklist(domain.EntityEmail, "x@x.com")
	if ok {
		t.Error("deleted entry should not be found")
	}
}

func TestBlocklist_DeleteMissing_ReturnsFalse(t *testing.T) {
	s := store.New()
	if s.DeleteBlocklistEntry("nonexistent") {
		t.Error("deleting non-existent entry should return false")
	}
}

func TestBlocklist_ListEntries_ExcludesExpired(t *testing.T) {
	s := store.New()
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	s.SaveBlocklistEntry(&domain.BlocklistEntry{ID: "live", Type: domain.EntityIP, Value: "1.1.1.1", ListType: domain.ListBlock, ExpiresAt: &future})
	s.SaveBlocklistEntry(&domain.BlocklistEntry{ID: "dead", Type: domain.EntityIP, Value: "2.2.2.2", ListType: domain.ListBlock, ExpiresAt: &past})
	s.SaveBlocklistEntry(&domain.BlocklistEntry{ID: "perm", Type: domain.EntityIP, Value: "3.3.3.3", ListType: domain.ListBlock})

	entries := s.ListBlocklistEntries()
	if len(entries) != 2 {
		t.Errorf("expected 2 active entries (live + permanent), got %d", len(entries))
	}
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

func TestWebhook_SaveAndList(t *testing.T) {
	s := store.New()
	s.SaveWebhook(&domain.WebhookConfig{ID: "wh-1", URL: "http://a.com", Threshold: 80, Active: true})
	s.SaveWebhook(&domain.WebhookConfig{ID: "wh-2", URL: "http://b.com", Threshold: 90, Active: false})

	hooks := s.ListActiveWebhooks()
	if len(hooks) != 1 {
		t.Errorf("expected 1 active webhook, got %d", len(hooks))
	}
	if hooks[0].ID != "wh-1" {
		t.Errorf("expected wh-1, got %s", hooks[0].ID)
	}
}

func TestWebhook_Delete(t *testing.T) {
	s := store.New()
	s.SaveWebhook(&domain.WebhookConfig{ID: "wh-del", URL: "http://x.com", Active: true})
	if !s.DeleteWebhook("wh-del") {
		t.Fatal("expected delete to return true")
	}
	if len(s.ListActiveWebhooks()) != 0 {
		t.Error("expected no webhooks after delete")
	}
}

func TestWebhook_DeleteMissing_ReturnsFalse(t *testing.T) {
	s := store.New()
	if s.DeleteWebhook("ghost") {
		t.Error("deleting missing webhook should return false")
	}
}

// ─── Concurrency (race detector) ─────────────────────────────────────────────

func TestStore_ConcurrentWrites_NoRace(t *testing.T) {
	s := store.New()
	done := make(chan struct{})

	for i := 0; i < 20; i++ {
		go func(n int) {
			tx := newTx(
				"conc-"+string(rune('A'+n)),
				"user@concurrent.com",
				"10.0.0.1",
				"dev-conc",
				"111111",
				now.Add(-time.Duration(n)*time.Minute),
			)
			_ = s.SaveTransaction(tx)
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}
