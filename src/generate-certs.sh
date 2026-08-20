#!/bin/bash
# =============================================================================
# SSL Certificate Generator for E2E Chat Server
# =============================================================================
# Generates a self-signed certificate for development/testing.
# For production, replace with real certificates from Let's Encrypt or your CA.
#
# Usage:
#   ./generate-certs.sh [output_dir]
#
# If output_dir is omitted, certificates are written to:
#   <script directory>/certs
#
# Output:
#   <output_dir>/server.crt  - Certificate (public)
#   <output_dir>/server.key  - Private key
#   <output_dir>/dhparam.pem - DH parameters (for DHE ciphers)
# =============================================================================

set -e

CERT_DIR="${1:-$(dirname "$0")/certs}"
mkdir -p "$CERT_DIR"

echo "=== E2E Chat Server — SSL Certificate Generator ==="
echo "Output directory: $CERT_DIR"
echo ""

# ---------------------------------------------------------------------------
# Private Key (RSA 2048-bit)
# ---------------------------------------------------------------------------
echo "[1/3] Generating private key..."
openssl genrsa -out "$CERT_DIR/server.key" 2048
chmod 600 "$CERT_DIR/server.key"
echo "  -> $CERT_DIR/server.key"

# ---------------------------------------------------------------------------
# Certificate Signing Request & Self-Signed Certificate
# ---------------------------------------------------------------------------
echo "[2/3] Generating self-signed certificate (valid 365 days)..."
openssl req -new -x509 -days 365 -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=California/L=San Francisco/O=E2E Chat/OU=Development/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:0.0.0.0"

chmod 644 "$CERT_DIR/server.crt"
echo "  -> $CERT_DIR/server.crt"

# ---------------------------------------------------------------------------
# DH Parameters (for Perfect Forward Secrecy with DHE ciphers)
# ---------------------------------------------------------------------------
echo "[3/3] Generating DH parameters (this may take a moment)..."
openssl dhparam -out "$CERT_DIR/dhparam.pem" 2048
chmod 644 "$CERT_DIR/dhparam.pem"
echo "  -> $CERT_DIR/dhparam.pem"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Done ==="
echo "Certificate details:"
openssl x509 -in "$CERT_DIR/server.crt" -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:|IP Address:"
echo ""
echo "To use with nginx, uncomment the SSL lines in nginx.conf or set env:"
echo "  LISTEN_SSL=true"
