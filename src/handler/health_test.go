package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthRootOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	HandleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != "E2E Secure Message Server - Online\n" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestHealthUnknownPathReturns404(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/unknown-path", nil)
	rec := httptest.NewRecorder()
	HandleHealth(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /unknown-path status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
