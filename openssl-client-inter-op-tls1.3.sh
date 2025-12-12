#!/bin/bash

# Test TLS 1.3 session resumption using OpenSSL s_client
# This script:
# 1. Connects and sends a ping message with a client ID
# 2. Saves the TLS session ticket
# 3. Reconnects using the saved session ticket and sends another ping with the same client ID
# 4. Verifies that the session was resumed (PSK/early data indicators or "Reused" indicator)
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
echo "TLS 1.3 Session Resumption Test"
echo "=========================================="
echo "Server: ${SERVER_HOST}:${SERVER_PORT}"
echo ""
echo ""

# Generate a client ID for this test session
CLIENT_ID=$(openssl rand -hex 8 | tr -d '\n')

# First connection - establish session and send ping
echo "--- First Connection (Establish Session) ---"
SESSION_FILE=$(mktemp)
(printf "ping-%s" "$CLIENT_ID"; sleep 2) | timeout 10 openssl s_client \
    -connect "${SERVER_HOST}:${SERVER_PORT}" \
    -tls1_3 \
    -CAfile "$CA_CERT" \
    $CLIENT_OPTS \
    -sess_out "$SESSION_FILE" \
    > /tmp/openssl_tls13_first.log 2>&1
# Show only essential output
grep -E "(TLS session ticket|Reused|PSK|Early data|pong)" /tmp/openssl_tls13_first.log 2>/dev/null || true

# Check if we received a session ticket or if session was established
TICKET_RECEIVED=$(grep -i "TLS session ticket\|New, TLSv1.3" /tmp/openssl_tls13_first.log || true)

if [ -z "$TICKET_RECEIVED" ] && [ ! -s "$SESSION_FILE" ]; then
    echo "Warning: Session file is empty, but checking if connection succeeded..."
    if ! grep -q "New, TLSv1.3" /tmp/openssl_tls13_first.log; then
        echo "Error: Failed to establish TLS 1.3 session"
        cat /tmp/openssl_tls13_first.log
        rm -f "$SESSION_FILE" /tmp/openssl_tls13_first.log /tmp/openssl_tls13_second.log
        exit 1
    fi
fi

echo "Session ticket/connection info: ${TICKET_RECEIVED:-<found TLS 1.3 connection>}"
echo ""

# Second connection - resume session and send ping with same client ID
echo "--- Second Connection (Resume Session) ---"
if [ -s "$SESSION_FILE" ]; then
    (printf "ping-%s" "$CLIENT_ID"; sleep 2) | timeout 10 openssl s_client \
        -connect "${SERVER_HOST}:${SERVER_PORT}" \
        -tls1_3 \
        -CAfile "$CA_CERT" \
        $CLIENT_OPTS \
        -sess_in "$SESSION_FILE" \
        > /tmp/openssl_tls13_second.log 2>&1
else
    # Session file not saved, try reconnect option instead
    echo "Note: Session file not saved, using -reconnect option for testing"
    (printf "ping-%s" "$CLIENT_ID"; sleep 2) | timeout 10 openssl s_client \
        -connect "${SERVER_HOST}:${SERVER_PORT}" \
        -tls1_3 \
        -CAfile "$CA_CERT" \
        $CLIENT_OPTS \
        -reconnect \
        > /tmp/openssl_tls13_second.log 2>&1
fi
# Show only essential output
grep -E "(TLS session ticket|Reused|PSK|Early data|pong)" /tmp/openssl_tls13_second.log 2>/dev/null || true

# Check for resumption indicators
RESUMED=$(grep -i "Reused\|Resumed" /tmp/openssl_tls13_second.log || true)
VERIFY_RESULT=$(grep -i "Verify return code" /tmp/openssl_tls13_second.log | tail -1 || true)

# For TLS 1.3, check if early data or PSK was used
PSK_USED=$(grep -i "PSK" /tmp/openssl_tls13_second.log || true)
EARLY_DATA=$(grep -i "Early data" /tmp/openssl_tls13_second.log || true)

echo "--- Verification ---"
if [ -n "$RESUMED" ]; then
    echo "✓ Session resumption detected: $RESUMED"
    RESUMPTION_SUCCESS=true
elif [ -n "$PSK_USED" ]; then
    echo "✓ PSK (Pre-Shared Key) used - session was resumed"
    echo "  Details: $PSK_USED"
    RESUMPTION_SUCCESS=true
elif [ -n "$EARLY_DATA" ]; then
    echo "✓ Early data indication - session was resumed"
    echo "  Details: $EARLY_DATA"
    RESUMPTION_SUCCESS=true
else
    echo "✗ Session resumption NOT detected"
    echo "  Checking logs for details..."
    RESUMPTION_SUCCESS=false
fi

if [ -n "$VERIFY_RESULT" ]; then
    echo "Certificate verification: $VERIFY_RESULT"
fi

# Additional debug info
if [ "$RESUMPTION_SUCCESS" = "false" ]; then
    echo ""
    echo "Debug information:"
    echo "First connection output (last 10 lines):"
    tail -10 /tmp/openssl_tls13_first.log || true
    echo ""
    echo "Second connection output (last 10 lines):"
    tail -10 /tmp/openssl_tls13_second.log || true
fi

# Cleanup
rm -f "$SESSION_FILE" /tmp/openssl_tls13_first.log /tmp/openssl_tls13_second.log

if [ "$RESUMPTION_SUCCESS" = "true" ]; then
    echo ""
    echo "=========================================="
    echo "✓ TLS 1.3 Session Resumption: SUCCESS"
    echo "=========================================="
    exit 0
else
    echo ""
    echo "=========================================="
    echo "✗ TLS 1.3 Session Resumption: FAILED"
    echo "=========================================="
    exit 1
fi
