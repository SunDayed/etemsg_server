// Package handler — access log helpers and HTTP middleware.
package handler

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	accessFile *os.File
	accessMu   sync.Mutex
)

// InitAccessLog opens (or creates) the access log file at the given path.
// Must be called once before any LogAccess / AccessLogMiddleware usage.
func InitAccessLog(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	accessFile = f
	return nil
}

// CloseAccessLog flushes and closes the access log file.
func CloseAccessLog() {
	if accessFile != nil {
		accessFile.Close()
	}
}

// LogAccess writes a line to the access log.
// Format: "2006/01/02 15:04:05 <message>"
func LogAccess(format string, args ...interface{}) {
	if accessFile == nil {
		return
	}
	accessMu.Lock()
	defer accessMu.Unlock()

	now := time.Now().Format("2006/01/02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(accessFile, "%s %s\n", now, msg)
}

// ── HTTP access-log middleware ──────────────────────────────────────

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	code        int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.code = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	// If WriteHeader wasn't called explicitly, default to 200.
	if !r.wroteHeader {
		r.code = http.StatusOK
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}

// Hijack implements http.Hijacker by delegating to the underlying ResponseWriter.
// gorilla/websocket requires http.Hijacker for WebSocket connection upgrades,
// and embedding http.ResponseWriter does not automatically promote Hijack()
// because it is not part of the http.ResponseWriter interface.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// AccessLogMiddleware returns a handler that logs every HTTP request to access.log.
// Format: "remote_addr method path status_code duration"
func AccessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		sr := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sr, r)

		dur := time.Since(start)
		LogAccess("%s %s %s %d %v",
			r.RemoteAddr,
			r.Method,
			r.URL.RequestURI(),
			sr.code,
			dur,
		)
	})
}
