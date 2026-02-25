// Package api contains the HTTP layer: routing, request binding, and response formatting.
package api

import (
	"encoding/json"
	"net/http"
)

// ─── Response envelope ────────────────────────────────────────────────────────

// envelope is the standard wrapper for all API responses.
// Success responses set `error` to nil; error responses set `data` to nil.
type envelope struct {
	Data  any    `json:"data,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ─── Response helpers ─────────────────────────────────────────────────────────

// writeJSON serialises v into the response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// At this point headers are already sent; all we can do is log.
		// In production this would go to a structured logger.
		_ = err
	}
}

// ok writes a 200 response with the payload wrapped in the standard envelope.
func ok(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, envelope{Data: data})
}

// created writes a 201 response.
func created(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusCreated, envelope{Data: data})
}

// noContent writes a 204 response with no body.
func noContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// badRequest writes a 400 error response.
func badRequest(w http.ResponseWriter, code, message string) {
	writeJSON(w, http.StatusBadRequest, envelope{Error: &apiError{Code: code, Message: message}})
}

// notFound writes a 404 error response.
func notFound(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusNotFound, envelope{Error: &apiError{Code: "NOT_FOUND", Message: message}})
}

// conflict writes a 409 error response.
func conflict(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusConflict, envelope{Error: &apiError{Code: "CONFLICT", Message: message}})
}

// internalError writes a 500 error response.
func internalError(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, envelope{
		Error: &apiError{Code: "INTERNAL_ERROR", Message: "an unexpected error occurred"},
	})
}
