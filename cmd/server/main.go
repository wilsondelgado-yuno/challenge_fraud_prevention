// Command server starts the Lumina Fraud Detection API.
//
// Usage:
//
//	go run ./cmd/server [flags]
//
// Flags:
//
//	-port  HTTP port to listen on (default: 8080)
//	-seed  Path to a seed data JSON file to load on startup (default: data/seed.json)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"lumina/fraud-api/internal/api"
	"lumina/fraud-api/internal/domain"
	"lumina/fraud-api/internal/scoring"
	"lumina/fraud-api/internal/store"
	"lumina/fraud-api/internal/webhook"
)

func main() {
	port := flag.Int("port", 8080, "HTTP port")
	seedFile := flag.String("seed", "data/seed.json", "path to seed data JSON file")
	flag.Parse()

	// Railway (and most PaaS platforms) inject PORT as an env var.
	// It takes precedence over the -port flag.
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*port = p
		}
	}

	// Structured logging — JSON in production, text-friendly in development.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// ── Wire dependencies ─────────────────────────────────────────────────────
	s := store.New()
	engine := scoring.New(s)
	notifier := webhook.New(s)
	handler := api.NewHandler(s, engine, notifier)
	router := api.NewRouter(handler)

	// ── Load seed data ────────────────────────────────────────────────────────
	if err := loadSeedData(s, engine, *seedFile); err != nil {
		// Non-fatal: the API works fine without seed data.
		slog.Warn("seed data not loaded", "file", *seedFile, "reason", err.Error())
	}

	// ── Start HTTP server ─────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server listening", "port", *port, "seed_file", *seedFile)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	slog.Info("server stopped")
}

// loadSeedData reads a JSON file of TransactionRequests, scores each one,
// and persists them to the store so the API starts with historical context.
func loadSeedData(s *store.Store, e *scoring.Engine, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var requests []domain.TransactionRequest
	if err := json.Unmarshal(data, &requests); err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	// Sort by timestamp before scoring so velocity rules fire in chronological
	// order, matching the pattern that would occur in real-time operation.
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].Timestamp.Before(requests[j].Timestamp)
	})

	var loaded, skipped int
	for i := range requests {
		req := &requests[i]
		score, factors, explanation := e.Score(req)
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
		if err := s.SaveTransaction(tx); err != nil {
			skipped++
		} else {
			loaded++
		}
	}

	slog.Info("seed data loaded", "file", filePath, "loaded", loaded, "skipped", skipped)
	return nil
}
