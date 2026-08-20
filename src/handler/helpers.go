// Package handler implements HTTP REST and WebSocket handlers for the E2E message server.
package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"e2e-msg-server/types"
)

// ctxTimeout is the default context timeout for database operations.
const ctxTimeout = 5 * time.Second

// writeJSON writes a JSON response with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ERROR: failed to encode JSON response: %v", err)
	}
}

// writeOK writes a success JSON response.
func writeOK(w http.ResponseWriter, payload interface{}) {
	writeJSON(w, http.StatusOK, types.Response{
		Status:  "ok",
		Payload: payload,
	})
}

// writeError writes an error JSON response.
func writeError(w http.ResponseWriter, code, message string) {
	writeJSON(w, http.StatusOK, types.Response{
		Status: "error",
		Error: &types.APIError{
			Code:    code,
			Message: message,
		},
	})
}

// maxJSONBodySize limits the size of JSON API request bodies to 8 MiB.
const maxJSONBodySize = 8 << 20

// decodeBody reads and JSON-decodes the request body into the given struct.
// The body is limited to maxJSONBodySize to avoid memory exhaustion.
func decodeBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	return json.NewDecoder(r.Body).Decode(v)
}

// bgCtx returns a background context with timeout for database operations.
func bgCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), ctxTimeout)
}
