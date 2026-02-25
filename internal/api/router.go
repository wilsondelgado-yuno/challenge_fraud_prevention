package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// NewRouter creates and returns a configured Chi router.
func NewRouter(h *Handler) http.Handler {
	r := chi.NewRouter()

	// ── Global middleware ─────────────────────────────────────────────────────
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)

	// ── Health check ──────────────────────────────────────────────────────────
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]string{"status": "ok", "service": "lumina-fraud-api"})
	})

	// ── API v1 ────────────────────────────────────────────────────────────────
	r.Route("/api/v1", func(r chi.Router) {

		// Transactions — core requirement 1 & 2
		r.Route("/transactions", func(r chi.Router) {
			r.Post("/", h.SubmitTransaction)
			r.Get("/{id}", h.GetTransaction)
		})

		// Entity activity summaries — core requirement 3
		r.Get("/entities/{type}/{value}", h.GetEntitySummary)

		// Blocklist / Allowlist management — stretch goal 1
		r.Route("/blocklist", func(r chi.Router) {
			r.Get("/", h.ListBlocklist)
			r.Post("/", h.AddBlocklistEntry)
			r.Delete("/{id}", h.DeleteBlocklistEntry)
		})

		// Fraud pattern report — stretch goal 3
		r.Get("/reports/fraud-patterns", h.GetFraudReport)

		// Webhook registration — stretch goal 4
		r.Route("/webhooks", func(r chi.Router) {
			r.Post("/", h.RegisterWebhook)
			r.Delete("/{id}", h.DeleteWebhook)
		})

		// Admin / demo utilities
		r.Post("/admin/seed", h.SeedData)
	})

	return r
}

// requestLogger is a minimal structured-logging middleware.
// It replaces chi's default Logger to emit slog records.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}
