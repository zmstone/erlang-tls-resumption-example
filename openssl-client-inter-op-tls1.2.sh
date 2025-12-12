#!/bin/bash

# Test TLS 1.2 session resumption using OpenSSL s_client
# This script:
# 1. Connects and sends a ping message with a client ID
# 2. Saves the TLS session
# 3. Reconnects using the saved session and sends another ping with the same client ID
# 4. Verifies that the session was resumed (Session ID matches or "Reused" indicator)
#
# The server will verify session resumption based on the client ID and log the result.

set -euo pipefail

SERVER_HOST="${TLSER_SERVER_HOST:-localhost}"
SERVER_PORT="${TLSER_SERVER_PORT:-9999}"
CERT_DIR="${TLSER_CERTS:-certs}"
CA_CERT="${CERT_DIR}/ca.pem"
CLIENT_CERT="${CERT_DIR}/client-cert.pem"
CLIENT_KEY="${CERT_DIR}/client-key.pem"

if [ ! -f "$CA_CERT" ]; then
    echo "Error: CA certificate not found at $CA_CERT"
    exit 1
fi

# client-cert.pem contains the full certificate chain (client cert + intermediate CA)
# OpenSSL will automatically send all certificates in the file
if [ ! -f "$CLIENT_CERT" ] || [ ! -f "$CLIENT_KEY" ]; then
    echo "Error: Client certificate/key required but not found"
    exit 1
fi

CLIENT_OPTS="-cert $CLIENT_CERT -key $CLIENT_KEY"

echo "=========================================="
echo "TLS 1.2 Session Resumption Test"
echo "=========================================="
echo "Server: ${SERVER_HOST}:${SERVER_PORT}"
echo ""
echo ""

# Generate a client ID for this test session
CLIENT_ID=$(openssl rand -hex 8 | tr -d '\n')
SESSION_FILE=$(mktemp)

# First connection - establish session and send ping
echo "--- First Connection (Establish Session) ---"
(printf "ping-%s" "$CLIENT_ID"; sleep 2) | timeout 10 openssl s_client \
    -connect "${SERVER_HOST}:${SERVER_PORT}" \
    -tls1_2 \
    -CAfile "$CA_CERT" \
    $CLIENT_OPTS \
    -sess_out "$SESSION_FILE" \
    > /tmp/openssl_tls12_first.log 2>&1
# Show only essential output
grep -E "(Session-ID|Reused|pong)" /tmp/openssl_tls12_first.log 2>/dev/null || true

# Extract session ID from first connection (ignore "unknown_ca" alerts)
FIRST_SESSION_ID=$(grep -i "Session-ID:" /tmp/openssl_tls12_first.log | head -1 | sed 's/.*Session-ID: *//' | tr -d ' ' | cut -d',' -f1 | tr -d ':')

if [ -z "$FIRST_SESSION_ID" ]; then
    echo "Error: Failed to extract Session-ID from first connection"
    echo "Last 20 lines of output:"
    tail -20 /tmp/openssl_tls12_first.log
    rm -f "$SESSION_FILE" /tmp/openssl_tls12_first.log /tmp/openssl_tls12_second.log
    exit 1
fi

echo "First Session ID: $FIRST_SESSION_ID"
echo ""

# Wait a moment for server to process first connection
sleep 1

# Second connection - resume session using saved session and send ping with same client ID
echo "--- Second Connection (Resume Session) ---"
if [ -s "$SESSION_FILE" ]; then
    (printf "ping-%s" "$CLIENT_ID"; sleep 2) | timeout 10 openssl s_client \
        -connect "${SERVER_HOST}:${SERVER_PORT}" \
        -tls1_2 \
        -CAfile "$CA_CERT" \
        $CLIENT_OPTS \
        -sess_in "$SESSION_FILE" \
        > /tmp/openssl_tls12_second.log 2>&1
else
    echo "Warning: Session file not saved, making new connection"
    (printf "ping-%s" "$CLIENT_ID"; sleep 2) | timeout 10 openssl s_client \
        -connect "${SERVER_HOST}:${SERVER_PORT}" \
        -tls1_2 \
        -CAfile "$CA_CERT" \
        $CLIENT_OPTS \
        > /tmp/openssl_tls12_second.log 2>&1
fi
# Show only essential output
grep -E "(Session-ID|Reused|pong)" /tmp/openssl_tls12_second.log 2>/dev/null || true

# Extract session ID from second connection
SECOND_SESSION_ID=$(grep -i "Session-ID:" /tmp/openssl_tls12_second.log | head -1 | sed 's/.*Session-ID: *//' | tr -d ' ' | cut -d',' -f1 | tr -d ':')

# Check for resumption indicators
RESUMED=$(grep -i "Reused" /tmp/openssl_tls12_second.log || true)
VERIFY_RESULT=$(grep -i "Verify return code" /tmp/openssl_tls12_second.log | tail -1 || true)

echo "--- Verification ---"
if [ -n "$RESUMED" ]; then
    echo "✓ Session resumption detected: $RESUMED"
    RESUMPTION_SUCCESS=true
elif [ -n "$FIRST_SESSION_ID" ] && [ -n "$SECOND_SESSION_ID" ] && [ "$FIRST_SESSION_ID" = "$SECOND_SESSION_ID" ]; then
    echo "✓ Session IDs match - session was resumed"
    RESUMPTION_SUCCESS=true
else
    echo "✗ Session resumption NOT detected"
    echo "  First Session ID:  ${FIRST_SESSION_ID:-<none>}"
    echo "  Second Session ID: ${SECOND_SESSION_ID:-<none>}"
    RESUMPTION_SUCCESS=false
fi

if [ -n "$VERIFY_RESULT" ]; then
    echo "Certificate verification: $VERIFY_RESULT"
fi

# Cleanup
rm -f "$SESSION_FILE" /tmp/openssl_tls12_first.log /tmp/openssl_tls12_second.log

if [ "$RESUMPTION_SUCCESS" = "true" ]; then
    echo ""
    echo "=========================================="
    echo "✓ TLS 1.2 Session Resumption: SUCCESS"
    echo "=========================================="
    exit 0
else
    echo ""
    echo "=========================================="
    echo "✗ TLS 1.2 Session Resumption: FAILED"
    echo "=========================================="
    exit 1
fi
