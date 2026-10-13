// Package config provides runtime configuration for the E2E message server: config.json next to the binary
// wins once it exists (defaults are written on first start); relative paths resolve against that directory.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ConfigFileName is the runtime configuration file (same dir as the binary).
const ConfigFileName = "config.json"

// Config holds all tunable server settings; durations are expressed in seconds in JSON.
type Config struct {
	ListenAddr string `json:"listen_addr"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`

	WSReadTimeout  int   `json:"ws_read_timeout_seconds"`
	WSPingInterval int   `json:"ws_ping_interval_seconds"`
	WSWriteTimeout int   `json:"ws_write_timeout_seconds"`
	WSMaxPayload   int64 `json:"ws_max_payload_bytes"`

	MaxFileSize    int64  `json:"max_file_size_bytes"`
	FileTTLSeconds int    `json:"file_ttl_seconds"`
	FileNameMax    int    `json:"file_name_max"`
	FileDirName    string `json:"file_dir_name"`

	TokenTTLSeconds int `json:"token_ttl_seconds"`
}

// Cfg is the process-wide configuration, initialized by Load.
var Cfg *Config

// Duration helpers for the JSON seconds fields.
func (c *Config) WSReadTimeoutD() time.Duration {
	return time.Duration(c.WSReadTimeout) * time.Second
}
func (c *Config) WSPingIntervalD() time.Duration {
	return time.Duration(c.WSPingInterval) * time.Second
}
func (c *Config) WSWriteTimeoutD() time.Duration {
	return time.Duration(c.WSWriteTimeout) * time.Second
}
func (c *Config) FileTTL() time.Duration {
	return time.Duration(c.FileTTLSeconds) * time.Second
}
func (c *Config) TokenTTL() time.Duration {
	return time.Duration(c.TokenTTLSeconds) * time.Second
}

// defaultConfig returns the built-in defaults.
func defaultConfig() *Config {
	return &Config{
		ListenAddr: ":60345",
		CertFile:   "certs/server.crt",
		KeyFile:    "certs/server.key",

		WSReadTimeout:  300,
		WSPingInterval: 30,
		WSWriteTimeout: 10,
		WSMaxPayload:   20 * 1024 * 1024,

		MaxFileSize:    500 * 1024 * 1024,
		FileTTLSeconds: int((7 * 24 * time.Hour).Seconds()),
		FileNameMax: 1024,
		FileDirName: "files",

		TokenTTLSeconds: int((7 * 24 * time.Hour).Seconds()),
	}
}

// Load reads config.json from binDir; if the file is absent it writes one with the defaults, and it
// also checks that the TLS cert/key exist (relative paths resolve against binDir).
func Load(binDir string) (*Config, error) {
	cfg := defaultConfig()
	path := filepath.Join(binDir, ConfigFileName)

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := cfg.write(path); err != nil {
			return nil, fmt.Errorf("generate default config %s: %w", path, err)
		}
		fmt.Printf("Generated default config: %s\n", path)
	} else {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	// Relative paths resolve against the binary directory, so runtime file access does not depend on the process working directory.
	resolve := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(binDir, p)
	}
	cfg.CertFile = resolve(cfg.CertFile)
	cfg.KeyFile = resolve(cfg.KeyFile)
	cfg.FileDirName = resolve(cfg.FileDirName)

	for _, f := range []string{cfg.CertFile, cfg.KeyFile} {
		if _, err := os.Stat(f); err != nil {
			return nil, fmt.Errorf("TLS file missing: %s (config %s)", f, path)
		}
	}

	Cfg = cfg
	return cfg, nil
}

func (c *Config) write(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
