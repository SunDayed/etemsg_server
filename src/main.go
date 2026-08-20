// E2E Encrypted Message Server (Go rewrite)
// Architecture:
//   - HTTP REST  — register, login (challenge-response), add_contact, get_offline_msg, upload/download file
//   - WebSocket  — real-time message delivery (connect, send_message, heartbeat, new_message)
//   - SQLite     — user data, contacts, offline messages, login challenges, file metadata
// The server never sees plaintext — encryption/decryption happens on the client side.
// Process model (self-contained watchdog, no systemd required):
//	  └─ watcher (E2E_DAEMON=1, E2E_WATCH=1)
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"e2e-msg-server/config"
	"e2e-msg-server/handler"
	"e2e-msg-server/session"
	"e2e-msg-server/store"
)

// workerEnv returns the environment for a worker process.
// It strips the E2E_WATCH marker inherited from the watcher, so the child
// is dispatched to the worker role instead of spawning yet another watcher.
func workerEnv() []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "E2E_WATCH=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "E2E_DAEMON=1")
}

func main() {
	switch {
	case os.Getenv("E2E_DAEMON") != "1":
		startWatcher()

	case os.Getenv("E2E_WATCH") == "1":
		watcherLoop()

	default:
		runServer()
	}
}

// startWatcher spawns the watchdog process in the background and exits.
func startWatcher() {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("FATAL: Cannot determine executable path: %v", err)
	}
	binDir := filepath.Dir(execPath)

	initLogPath := filepath.Join(binDir, "init.log")
	initLog, err := os.OpenFile(initLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("FATAL: Cannot open %s: %v", initLogPath, err)
	}
	defer initLog.Close()

	cmd := exec.Command(execPath)
	cmd.Env = append(os.Environ(), "E2E_DAEMON=1", "E2E_WATCH=1")
	cmd.Dir = binDir
	cmd.Stdout = initLog
	cmd.Stderr = initLog
	cmd.Stdin = nil

	// Detach from controlling terminal (create new session)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		log.Fatalf("FATAL: Failed to start watcher: %v", err)
	}

	fmt.Printf("E2E Message Server started (watcher PID: %d)\n", cmd.Process.Pid)
	fmt.Printf("  Logs: %s\n", initLogPath)
	os.Exit(0)
}

// watcherLoop supervises the worker: restarts it on crash, stops it on signal.
func watcherLoop() {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("FATAL: Cannot determine executable path: %v", err)
	}
	binDir := filepath.Dir(execPath)

	initLogPath := filepath.Join(binDir, "init.log")
	initLog, err := os.OpenFile(initLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("FATAL: Cannot open %s: %v", initLogPath, err)
	}
	defer initLog.Close()
	log.SetOutput(initLog)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	log.Println("Watcher started.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	stopping := false

	const fastCrashThreshold = 10 * time.Second
	fastCrashes := 0

	for {
		cmd := exec.Command(execPath)
		cmd.Env = workerEnv()
		cmd.Dir = binDir
		cmd.Stdout = initLog
		cmd.Stderr = initLog
		cmd.Stdin = nil

		if err := cmd.Start(); err != nil {
			log.Printf("WATCHER: failed to start worker: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}
		workerPid := cmd.Process.Pid
		log.Printf("WATCHER: worker started pid=%d", workerPid)

		started := time.Now()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		select {
		case <-sigCh:
			stopping = true
			log.Printf("WATCHER: signal received — stopping worker pid=%d", workerPid)
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
				// worker exited normally
			case <-time.After(15 * time.Second):
				log.Println("WATCHER: worker did not exit in time, killing it")
				cmd.Process.Kill()
				<-done
			}
			log.Println("WATCHER: stopped.")
			return

		case werr := <-done:
			if stopping {
				return
			}
			elapsed := time.Since(started)
			if elapsed < fastCrashThreshold {
				fastCrashes++
			} else {
				fastCrashes = 0
			}
			delay := 3 * time.Second
			if fastCrashes >= 3 {
				delay = 30 * time.Second
			}
			log.Printf("WATCHER: worker exited (%v) after %v fast_crashes=%d — restarting in %v",
				werr, elapsed.Round(time.Second), fastCrashes, delay)
			time.Sleep(delay)
		}
	}
}

// runServer is the actual service process (worker).
func runServer() {
	// ── Determine binary directory (log files go here) ────────────────
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("FATAL: Cannot determine executable path: %v", err)
	}
	binDir := filepath.Dir(execPath)

	// Set up init.log — all runtime / error / diagnostics logs
	initLogPath := filepath.Join(binDir, "init.log")
	initLog, err := os.OpenFile(initLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("FATAL: Cannot open init.log: %v", err)
	}
	defer initLog.Close()
	log.SetOutput(initLog)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println("Starting E2E Encrypted Message Server (Go)...")

	// Set up access.log — HTTP / WebSocket request-level logs
	accessLogPath := filepath.Join(binDir, "access.log")
	if err := handler.InitAccessLog(accessLogPath); err != nil {
		log.Printf("WARN: Cannot open access.log: %v", err)
	}
	defer handler.CloseAccessLog()

	// ── Runtime config (config.json next to the binary; auto-generated) ──
	if _, err := config.Load(binDir); err != nil {
		log.Fatalf("FATAL: Failed to load config: %v", err)
	}
	log.Printf("Config loaded: %s", filepath.Join(binDir, config.ConfigFileName))

	// ── SQLite (single-instance deployment) ─────────────────────────
	dbPath := filepath.Join(binDir, "etemsg.db")
	st, err := store.New(dbPath)
	if err != nil {
		log.Fatalf("FATAL: Failed to open SQLite database %s: %v", dbPath, err)
	}
	defer st.Close()
	log.Printf("SQLite database ready: %s", dbPath)

	// ── Encrypted file storage directory ───────────────────────────
	fileDir := config.Cfg.FileDirName
	if err := os.MkdirAll(fileDir, 0700); err != nil {
		log.Fatalf("FATAL: Cannot create file directory %s: %v", fileDir, err)
	}
	handler.StartFileCleanup(st, fileDir)

	// ── Session manager ────────────────────────────────────────────
	sm := session.NewManager()

	// ── WebSocket handler ──────────────────────────────────────────
	wsHandler := handler.NewWSHandler(st, sm)

	// ── HTTP routes ────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/", handler.HandleHealth)

	// REST API
	mux.HandleFunc("/register", handler.HandleRegister(st))
	mux.HandleFunc("/login/challenge", handler.HandleLoginChallenge(st))
	mux.HandleFunc("/login", handler.HandleLogin(st))
	mux.HandleFunc("/add_contact", handler.HandleAddContact(st))
	mux.HandleFunc("/get_offline_msg", handler.HandleGetOfflineMsg(st))

	// Encrypted file transfer (ciphertext storage & retrieval)
	mux.HandleFunc("/upload_file", handler.HandleUploadFile(st, fileDir))
	mux.HandleFunc("/download_file/", handler.HandleDownloadFile(st, fileDir))

	// WebSocket
	mux.HandleFunc("/ws", wsHandler.ServeWS)

	// ── Wrap with access-log middleware ────────────────────────────
	accessLoggedMux := handler.AccessLogMiddleware(mux)

	// ── TLS server ─────────────────────────────────────────────────
	// Disable HTTP/2 so that http.ResponseWriter implements http.Hijacker,
	// which is required by gorilla/websocket for connection upgrade.
	// Both TLSNextProto (prevents http2.ConfigureServer) and TLSConfig.NextProtos
	// (prevents ALPN from advertising "h2") are needed to fully disable HTTP/2.
	server := &http.Server{
		Addr:         config.Cfg.ListenAddr,
		Handler:      accessLoggedMux,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig: &tls.Config{
			NextProtos: []string{"http/1.1"},
		},
	}

	// Graceful shutdown on SIGINT / SIGTERM
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("Received signal %v — shutting down...", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("WARN: graceful shutdown timed out: %v", err)
			server.Close()
		}
		wsHandler.CloseAll()
	}()

	log.Printf("HTTPS server listening on %s", config.Cfg.ListenAddr)
	log.Println("Routes:")
	log.Println("  GET  /                  — Health check")
	log.Println("  POST /register          — Register user + public key")
	log.Println("  POST /login/challenge   — Request login challenge")
	log.Println("  POST /login             — Verify challenge signature")
	log.Println("  POST /add_contact       — Add contact relationship")
	log.Println("  POST /get_offline_msg   — Fetch + clear offline messages")
	log.Println("  POST /upload_file       — Upload encrypted file (streamed)")
	log.Println("  GET  /download_file/    — Download encrypted file (recipient only)")
	log.Println("  GET  /ws                — WebSocket (real-time messaging)")

	if err := server.ListenAndServeTLS(config.Cfg.CertFile, config.Cfg.KeyFile); err != nil {
		if err == http.ErrServerClosed {
			log.Println("Server shut down gracefully.")
		} else {
			log.Fatalf("FATAL: Server error: %v", err)
		}
	}
}
