package handler

import (
	"net/http"
)

// HandleHealth responds to GET / with a plain-text online status.
// Any other path handled by the root mux pattern is intentionally 404.
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("E2E Secure Message Server - Online\n"))
}
