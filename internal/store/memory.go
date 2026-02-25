// Package store provides thread-safe, in-memory storage for the fraud API.
//
// Design rationale: For a 90-day rolling fraud-detection window, an in-memory
// store is sufficient for demo and small-scale production loads. The secondary
// indexes (byEmail, byIP, byDevice, byBIN) give O(1) entity lookups while the
// time-range filtering is a linear scan over a typically small slice.
// A production deployment would swap this for Redis or TimescaleDB.
package store

import (
	"errors"
	"sync"
	"time"

	"lumina/fraud-api/internal/domain"
)

// ErrDuplicateTransaction is returned when a transaction ID is submitted twice.
var ErrDuplicateTransaction = errors.New("transaction already exists")

// Store is a thread-safe in-memory data store.
type Store struct {
	mu sync.RWMutex

	transactions map[string]*domain.Transaction
	blocklist    map[string]*domain.BlocklistEntry
	webhooks     map[string]*domain.WebhookConfig

	// Secondary indexes: entity value → slice of transaction IDs.
	// Maintained on every write so reads stay fast.
	txByEmail  map[string][]string
	txByIP     map[string][]string
	txByDevice map[string][]string
	txByBIN    map[string][]string

	// Tracks the set of distinct card BINs seen per IP address.
	// Used to detect the "card cycling on one IP" fraud pattern.
	cardsByIP map[string]map[string]bool
}

// New creates an empty, ready-to-use Store.
func New() *Store {
	return &Store{
		transactions: make(map[string]*domain.Transaction),
		blocklist:    make(map[string]*domain.BlocklistEntry),
		webhooks:     make(map[string]*domain.WebhookConfig),
		txByEmail:    make(map[string][]string),
		txByIP:       make(map[string][]string),
		txByDevice:   make(map[string][]string),
		txByBIN:      make(map[string][]string),
		cardsByIP:    make(map[string]map[string]bool),
	}
}

// ─── Transactions ─────────────────────────────────────────────────────────────

// SaveTransaction persists a transaction and updates all secondary indexes.
// Returns ErrDuplicateTransaction if the ID already exists.
func (s *Store) SaveTransaction(tx *domain.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.transactions[tx.TransactionID]; exists {
		return ErrDuplicateTransaction
	}

	s.transactions[tx.TransactionID] = tx
	s.txByEmail[tx.UserEmail] = append(s.txByEmail[tx.UserEmail], tx.TransactionID)
	s.txByIP[tx.IPAddress] = append(s.txByIP[tx.IPAddress], tx.TransactionID)
	s.txByDevice[tx.DeviceFingerprint] = append(s.txByDevice[tx.DeviceFingerprint], tx.TransactionID)
	s.txByBIN[tx.CardBIN] = append(s.txByBIN[tx.CardBIN], tx.TransactionID)

	if s.cardsByIP[tx.IPAddress] == nil {
		s.cardsByIP[tx.IPAddress] = make(map[string]bool)
	}
	s.cardsByIP[tx.IPAddress][tx.CardBIN] = true

	return nil
}

// GetTransaction retrieves a single transaction by ID.
func (s *Store) GetTransaction(id string) (*domain.Transaction, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, ok := s.transactions[id]
	return tx, ok
}

// GetTransactionsByEmail returns all transactions from the given email that
// occurred at or after `since`. Results are in arbitrary order.
func (s *Store) GetTransactionsByEmail(email string, since time.Time) []*domain.Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filterByTime(s.txByEmail[email], since)
}

// GetTransactionsByIP returns all transactions originating from the given IP
// at or after `since`.
func (s *Store) GetTransactionsByIP(ip string, since time.Time) []*domain.Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filterByTime(s.txByIP[ip], since)
}

// GetTransactionsByDevice returns all transactions from a device fingerprint
// at or after `since`.
func (s *Store) GetTransactionsByDevice(device string, since time.Time) []*domain.Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filterByTime(s.txByDevice[device], since)
}

// GetTransactionsByBIN returns all transactions using a particular card BIN
// at or after `since`.
func (s *Store) GetTransactionsByBIN(bin string, since time.Time) []*domain.Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filterByTime(s.txByBIN[bin], since)
}

// GetUniqueCardsByIP returns how many distinct card BINs have been used from
// the given IP address (all-time, not time-windowed — card cycling is a
// persistent signal even across days).
func (s *Store) GetUniqueCardsByIP(ip string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cardsByIP[ip])
}

// GetAllTransactions returns every transaction stored at or after `since`.
func (s *Store) GetAllTransactions(since time.Time) []*domain.Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*domain.Transaction
	for _, tx := range s.transactions {
		if !tx.Timestamp.Before(since) {
			result = append(result, tx)
		}
	}
	return result
}

// filterByTime resolves a slice of IDs to Transaction pointers,
// keeping only those at or after `since`.
// Must be called with at least a read-lock held.
func (s *Store) filterByTime(ids []string, since time.Time) []*domain.Transaction {
	var result []*domain.Transaction
	for _, id := range ids {
		tx, ok := s.transactions[id]
		if ok && !tx.Timestamp.Before(since) {
			result = append(result, tx)
		}
	}
	return result
}

// ─── Blocklist / Allowlist ────────────────────────────────────────────────────

// SaveBlocklistEntry upserts a blocklist or allowlist rule.
func (s *Store) SaveBlocklistEntry(entry *domain.BlocklistEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocklist[entry.ID] = entry
}

// DeleteBlocklistEntry removes an entry by ID. Returns false if not found.
func (s *Store) DeleteBlocklistEntry(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.blocklist[id]
	if exists {
		delete(s.blocklist, id)
	}
	return exists
}

// CheckBlocklist looks up whether an entity is on the block or allow list.
// Expired entries are silently skipped.
func (s *Store) CheckBlocklist(entityType, value string) (*domain.BlocklistEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	for _, entry := range s.blocklist {
		if entry.Type != entityType || entry.Value != value {
			continue
		}
		if entry.ExpiresAt != nil && entry.ExpiresAt.Before(now) {
			continue // expired
		}
		return entry, true
	}
	return nil, false
}

// ListBlocklistEntries returns all non-expired entries.
func (s *Store) ListBlocklistEntries() []*domain.BlocklistEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var result []*domain.BlocklistEntry
	for _, entry := range s.blocklist {
		if entry.ExpiresAt == nil || entry.ExpiresAt.After(now) {
			result = append(result, entry)
		}
	}
	return result
}

// ─── Webhooks ─────────────────────────────────────────────────────────────────

// SaveWebhook persists a webhook configuration.
func (s *Store) SaveWebhook(wh *domain.WebhookConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks[wh.ID] = wh
}

// DeleteWebhook removes a webhook by ID. Returns false if not found.
func (s *Store) DeleteWebhook(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.webhooks[id]
	if exists {
		delete(s.webhooks, id)
	}
	return exists
}

// ListActiveWebhooks returns all webhooks that are currently active.
func (s *Store) ListActiveWebhooks() []*domain.WebhookConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*domain.WebhookConfig
	for _, wh := range s.webhooks {
		if wh.Active {
			result = append(result, wh)
		}
	}
	return result
}
