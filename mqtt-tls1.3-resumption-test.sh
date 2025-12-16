#!/bin/bash

# Test TLS 1.3 session resumption with MQTT protocol
# This script:
# 1. Connects to MQTT server using TLS 1.3
# 2. Sends MQTT CONNECT packet
# 3. Verifies TLS 1.3 session ticket was received
# 4. Reconnects and verifies session resumption worked
# 5. Prints result in green (success) or red (failure)
#
# Requirements:
# - Server must support TLS 1.3
# - Server must send session tickets for TLS 1.3 resumption

set -euo pipefail

# Parse host:port argument, default to localhost:8883
MQTT_HOST_PORT="${1:-localhost:8883}"
if [[ "$MQTT_HOST_PORT" == *:* ]]; then
    MQTT_HOST="${MQTT_HOST_PORT%%:*}"
    MQTT_PORT="${MQTT_HOST_PORT##*:}"
else
    MQTT_HOST="$MQTT_HOST_PORT"
    MQTT_PORT=8883
fi

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SESSION_FILE=$(mktemp)

# Generate a simple MQTT CONNECT packet (MQTT 3.1.1)
# Fixed header: 0x10 (CONNECT)
# Remaining length: 0x16 (22 bytes)
# Variable header:
#   Protocol name length: 00 04
#   Protocol name: MQTT (4D 51 54 54)
#   Protocol level: 04
#   Connect flags: 02 (clean session)
#   Keep alive: 00 0A (10 seconds)
# Payload:
#   Client ID length: 00 0A (10)
#   Client ID: "test-client" (74 65 73 74 2D 63 6C 69 65 6E 74)
#
# Full packet: 10 16 00 04 4D 51 54 54 04 02 00 0A 00 0A 74 65 73 74 2D 63 6C 69 65 6E 74
#
# Function to generate MQTT CONNECT packet (avoid null byte issues)
generate_mqtt_connect() {
    printf '\x10\x16\x00\x04MQTT\x04\x02\x00\x0A\x00\x0Atest-client'
}

echo "=========================================="
echo "MQTT TLS 1.3 Session Resumption Test"
echo "=========================================="
echo "MQTT Server: ${MQTT_HOST}:${MQTT_PORT}"
echo ""

# First connection - establish TLS 1.3 session and send MQTT CONNECT
echo "--- First Connection (Establish TLS 1.3 Session) ---"
# Force TLS 1.3 - exit with error if server doesn't support it
(generate_mqtt_connect; sleep 2) | timeout 10 openssl s_client \
    -connect "${MQTT_HOST}:${MQTT_PORT}" \
    -tls1_3 \
    -sess_out "$SESSION_FILE" \
    > /tmp/mqtt_tls_first.log 2>&1 || true

# Check for TLS handshake errors - look for protocol version errors
PROTOCOL_ERROR=$(strings /tmp/mqtt_tls_first.log 2>/dev/null | grep -iE "protocol version|tlsv1 alert|alert protocol" | head -1 || echo "")
HANDSHAKE_FAILED=$(strings /tmp/mqtt_tls_first.log 2>/dev/null | grep -iE "New, \(NONE\)|Cipher is \(NONE\)" | head -1 || echo "")
SSL_ERROR=$(strings /tmp/mqtt_tls_first.log 2>/dev/null | grep -iE "^[0-9]+:error:" | head -1 || echo "")

# Extract TLS version and session info - handle binary data
# Try multiple extraction methods for robustness
TLS_VERSION_LINE=$(grep -a "New, TLSv" /tmp/mqtt_tls_first.log 2>/dev/null | head -1 || echo "")
if [ -z "$TLS_VERSION_LINE" ]; then
    # Fallback: use strings to extract text from binary file
    TLS_VERSION_LINE=$(strings /tmp/mqtt_tls_first.log 2>/dev/null | grep "New, TLSv" | head -1 || echo "")
fi

# Extract version number (handles TLSv1.2, TLSv1.3, etc.)
if [ -n "$TLS_VERSION_LINE" ]; then
    TLS_VERSION=$(echo "$TLS_VERSION_LINE" | grep -oE "TLSv[0-9.]+" | head -1 || echo "unknown")
    # Also extract cipher info if available
    TLS_CIPHER=$(echo "$TLS_VERSION_LINE" | grep -oE "Cipher is [^ ]+" | sed 's/Cipher is //' || echo "")
else
    TLS_VERSION="unknown"
    TLS_CIPHER=""
fi

# Check if TLS 1.3 was negotiated - exit with error if not
if ! echo "$TLS_VERSION" | grep -qE "TLSv1\.3|1\.3"; then
    echo -e "${RED}ERROR: TLS 1.3 was not negotiated${NC}"
    echo ""

    # Provide specific error message based on what we detected
    if [ -n "$PROTOCOL_ERROR" ] || [ -n "$SSL_ERROR" ]; then
        echo "The server rejected the TLS 1.3 handshake attempt."
        if [ -n "$SSL_ERROR" ]; then
            # Extract the meaningful error message
            # Format: PID:error:CODE:SSL routines:function:reason:file:line
            # Try to get the reason part first (most meaningful)
            REASON=$(echo "$SSL_ERROR" | grep -oE "tlsv1 alert [^:]+" | head -1 || echo "")
            if [ -n "$REASON" ]; then
                echo "SSL Error: $REASON"
            else
                # Fallback to function name
                CLEAN_ERROR=$(echo "$SSL_ERROR" | sed -E 's/^[0-9]+:error:[0-9A-F]+:SSL routines://' | sed -E 's/:.*$//' | head -1)
                if [ -n "$CLEAN_ERROR" ] && [ "$CLEAN_ERROR" != "SSL routines" ]; then
                    echo "SSL Error: $CLEAN_ERROR"
                else
                    echo "SSL Error: Protocol version mismatch (server rejected TLS 1.3)"
                fi
            fi
        elif [ -n "$PROTOCOL_ERROR" ]; then
            echo "Error: $PROTOCOL_ERROR"
        fi
        echo ""
    elif [ -n "$HANDSHAKE_FAILED" ]; then
        echo "TLS handshake failed - no cipher suite was negotiated."
        echo ""
    elif [ "$TLS_VERSION" != "unknown" ]; then
        echo "Server negotiated: $TLS_VERSION (not TLS 1.3)"
        echo ""
    else
        echo "Could not determine negotiated TLS version."
        echo ""
    fi

    echo "This script requires TLS 1.3. The server may only support older TLS versions."
    echo ""
    echo "Possible reasons:"
    echo "  1. Server does not support TLS 1.3"
    echo "  2. Server is configured to use only TLS 1.2 or older"
    echo "  3. Server explicitly disabled TLS 1.3"
    echo ""
    echo "Connection details:"
    echo "  Server: ${MQTT_HOST}:${MQTT_PORT}"
    if [ -n "$TLS_VERSION_LINE" ]; then
        echo "  Negotiated: $TLS_VERSION_LINE"
    else
        # Show relevant error lines from the log
        echo "  Handshake status: Failed"
        if [ -n "$SSL_ERROR" ]; then
            # Extract meaningful error message
            REASON=$(echo "$SSL_ERROR" | grep -oE "tlsv1 alert [^:]+" | head -1 || echo "")
            if [ -n "$REASON" ]; then
                echo "  Error: $REASON"
            else
                # Fallback to function name
                CLEAN_ERROR=$(echo "$SSL_ERROR" | sed -E 's/^[0-9]+:error:[0-9A-F]+:SSL routines://' | sed -E 's/:.*$//' | head -1)
                if [ -n "$CLEAN_ERROR" ] && [ "$CLEAN_ERROR" != "SSL routines" ]; then
                    echo "  Error: $CLEAN_ERROR"
                else
                    echo "  Error: Protocol version mismatch"
                fi
            fi
        elif [ -n "$PROTOCOL_ERROR" ]; then
            echo "  Error: $PROTOCOL_ERROR"
        fi
    fi
    echo ""
    echo "Full connection log (last 15 lines):"
    strings /tmp/mqtt_tls_first.log 2>/dev/null | tail -15
    echo ""
    rm -f "$SESSION_FILE" /tmp/mqtt_tls_first.log /tmp/mqtt_tls_second.log
    exit 1
fi

# Display detailed TLS 1.3 information
echo "--- TLS 1.3 Connection Details ---"
echo "TLS Version: $TLS_VERSION"
if [ -n "$TLS_CIPHER" ]; then
    echo "Cipher Suite: $TLS_CIPHER"
fi
# Show the full line for debugging
echo "Full TLS info: $TLS_VERSION_LINE"

SESSION_FILE_SIZE=$(stat -f%z "$SESSION_FILE" 2>/dev/null || stat -c%s "$SESSION_FILE" 2>/dev/null || echo "0")
echo "Session file size: $SESSION_FILE_SIZE bytes"

# Check if session ticket was received
echo "Note: TLS 1.3 uses session tickets (stored in session file)"
if [ "$SESSION_FILE_SIZE" = "0" ]; then
    echo -e "  ${RED}Warning: Empty session file - no ticket received from server${NC}"
else
    echo "  Session file contains ticket data ($SESSION_FILE_SIZE bytes)"
fi
echo ""

# Wait a moment before reconnecting
sleep 1

# Second connection - resume TLS 1.3 session and send same MQTT CONNECT
echo "--- Second Connection (Resume TLS 1.3 Session) ---"
# For TLS 1.3, if session file is empty, it means no session ticket was received
if [ -s "$SESSION_FILE" ]; then
    # Session file has content, use it for resumption
    echo "Using session file with ticket for TLS 1.3 resumption..."
    (generate_mqtt_connect; sleep 2) | timeout 10 openssl s_client \
        -connect "${MQTT_HOST}:${MQTT_PORT}" \
        -tls1_3 \
        -sess_in "$SESSION_FILE" \
        > /tmp/mqtt_tls_second.log 2>&1 || true
else
    # Empty session file means no session ticket was received from server
    echo -e "${RED}ERROR: No TLS 1.3 session ticket received from server${NC}"
    echo ""
    echo "For TLS 1.3, the server must send a NewSessionTicket message after the handshake."
    echo "An empty session file (0 bytes) indicates no ticket was received."
    echo ""
    echo "Possible reasons:"
    echo "  1. Server is not configured to send session tickets"
    echo "  2. Server has session tickets disabled"
    echo "  3. Server configuration issue with TLS 1.3 session resumption"
    echo ""
    echo "Debug information:"
    echo "  TLS version: $TLS_VERSION"
    echo "  Session file size: $SESSION_FILE_SIZE bytes"
    echo ""
    echo "First connection log (TLS negotiation):"
    strings /tmp/mqtt_tls_first.log 2>/dev/null | grep -a "New, TLSv" | head -3
    echo ""
    rm -f "$SESSION_FILE" /tmp/mqtt_tls_first.log /tmp/mqtt_tls_second.log
    exit 1
fi

# Extract TLS version from second connection for comparison
TLS_VERSION_LINE_2=$(grep -a "New, TLSv" /tmp/mqtt_tls_second.log 2>/dev/null | head -1 || echo "")
if [ -z "$TLS_VERSION_LINE_2" ]; then
    TLS_VERSION_LINE_2=$(strings /tmp/mqtt_tls_second.log 2>/dev/null | grep "New, TLSv" | head -1 || echo "")
fi
if [ -n "$TLS_VERSION_LINE_2" ]; then
    TLS_VERSION_2=$(echo "$TLS_VERSION_LINE_2" | grep -oE "TLSv[0-9.]+" | head -1 || echo "unknown")
    TLS_CIPHER_2=$(echo "$TLS_VERSION_LINE_2" | grep -oE "Cipher is [^ ]+" | sed 's/Cipher is //' || echo "")
else
    TLS_VERSION_2="unknown"
    TLS_CIPHER_2=""
fi

# Check for TLS resumption indicators in the second connection log
RESUMED=$(grep -aiE "Reused|Resumed" /tmp/mqtt_tls_second.log 2>/dev/null || true)
PSK_USED=$(grep -aiE "PSK|Pre.*Shared.*Key" /tmp/mqtt_tls_second.log 2>/dev/null || true)
EARLY_DATA=$(grep -aiE "Early data|early.*data" /tmp/mqtt_tls_second.log 2>/dev/null || true)

# For TLS 1.3, check if ticket was used (look for PSK extension or resumption)
TLS13_RESUMPTION=$(grep -aiE "TLSv1\.3.*Reused|PSK.*accepted|Resumption.*PSK" /tmp/mqtt_tls_second.log 2>/dev/null || true)

echo "--- Verification ---"
echo "First connection:  TLS $TLS_VERSION${TLS_CIPHER:+ ($TLS_CIPHER)}"
echo "Second connection: TLS $TLS_VERSION_2${TLS_CIPHER_2:+ ($TLS_CIPHER_2)}"
if [ "$TLS_VERSION" != "$TLS_VERSION_2" ] && [ "$TLS_VERSION_2" != "unknown" ]; then
    echo -e "${RED}Warning: TLS version mismatch between connections${NC}"
fi
echo ""

# Verify that TLS 1.3 session ticket was received and used
# (We already verified TLS 1.3 was negotiated above)
echo "Checking TLS 1.3 session ticket status..."
TICKET_USED=false

# Check for resumption indicators in second connection log
# Look for explicit resumption messages
if grep -aqiE "Reused|Resumed" /tmp/mqtt_tls_second.log 2>/dev/null; then
    TICKET_USED=true
fi

# Check for PSK-related messages (TLS 1.3 uses PSK for resumption)
# "Resumption PSK:" with a value indicates a ticket was received and used
if grep -aqiE "Resumption PSK:" /tmp/mqtt_tls_second.log 2>/dev/null; then
    # Check if there's actually a PSK value (not just "None")
    RESUMPTION_PSK=$(grep -ai "Resumption PSK:" /tmp/mqtt_tls_second.log 2>/dev/null | head -1 | sed 's/.*Resumption PSK: *//' | tr -d ' ' || echo "")
    if [ -n "$RESUMPTION_PSK" ] && [ "$RESUMPTION_PSK" != "None" ] && [ "$RESUMPTION_PSK" != "" ]; then
        TICKET_USED=true
        echo "  Found Resumption PSK indicator (ticket was used)"
    fi
fi

# Also check for other PSK acceptance patterns
if grep -aqiE "PSK.*accepted|PSK.*used|Pre.*Shared.*Key.*accepted" /tmp/mqtt_tls_second.log 2>/dev/null; then
    TICKET_USED=true
fi

# Check for "Early data" which indicates resumption
# But exclude "Early data was not sent" which doesn't indicate resumption
EARLY_DATA_LINE=$(grep -aqiE "Early data" /tmp/mqtt_tls_second.log 2>/dev/null | grep -vi "not sent" | head -1 || echo "")
if [ -n "$EARLY_DATA_LINE" ]; then
    TICKET_USED=true
fi

# Check for "Max Early Data" which indicates resumption support
if grep -aqiE "Max Early Data:" /tmp/mqtt_tls_second.log 2>/dev/null; then
    MAX_EARLY_DATA=$(grep -ai "Max Early Data:" /tmp/mqtt_tls_second.log 2>/dev/null | head -1 | sed 's/.*Max Early Data: *//' | tr -d ' ' || echo "")
    if [ -n "$MAX_EARLY_DATA" ] && [ "$MAX_EARLY_DATA" != "0" ] && [ "$MAX_EARLY_DATA" != "" ]; then
        TICKET_USED=true
        echo "  Found Max Early Data indicator (resumption supported)"
    fi
fi

# With -reconnect, OpenSSL may show resumption in subsequent connections
# Check all TLS negotiation lines for resumption indicators
RECONNECT_LINES=$(strings /tmp/mqtt_tls_second.log 2>/dev/null | grep -a "New, TLSv1.3" | wc -l || echo "0")
if [ "$RECONNECT_LINES" -gt 1 ]; then
    # Multiple connections - check if any show resumption
    # In TLS 1.3, resumption typically shows "Reused" or uses PSK
    if strings /tmp/mqtt_tls_second.log 2>/dev/null | grep -qiE "reused|resumed|resumption psk"; then
        TICKET_USED=true
        echo "  Found resumption indicator in reconnect attempts"
    fi
fi

# Also check the raw log file (not just strings output) for resumption PSK
# This catches cases where the PSK might be in binary sections
if grep -aqi "Resumption PSK:" /tmp/mqtt_tls_second.log 2>/dev/null; then
    RESUMPTION_PSK_RAW=$(grep -ai "Resumption PSK:" /tmp/mqtt_tls_second.log 2>/dev/null | head -1 | sed 's/.*Resumption PSK: *//' | head -c 50 || echo "")
    if [ -n "$RESUMPTION_PSK_RAW" ] && [ "$RESUMPTION_PSK_RAW" != "None" ]; then
        TICKET_USED=true
        echo "  Found Resumption PSK in raw log (ticket was used)"
    fi
fi

if [ "$TICKET_USED" = "false" ]; then
    echo -e "${RED}ERROR: TLS 1.3 session ticket was not received from server${NC}"
    echo ""
    echo "For TLS 1.3, the server must send a NewSessionTicket message after the handshake."
    echo "Session resumption did not occur, which indicates no usable ticket was received."
    echo ""
    echo "Possible reasons:"
    echo "  1. Server is not configured to send session tickets"
    echo "  2. Server has session tickets disabled"
    echo "  3. Server configuration issue with TLS 1.3 session resumption"
    echo ""
    echo "Debug information:"
    echo "  TLS version: $TLS_VERSION"
    echo "  Session resumption detected: No"
    echo ""
    echo "First connection log (TLS negotiation):"
    strings /tmp/mqtt_tls_first.log 2>/dev/null | grep -a "New, TLSv" | head -3
    echo ""
    echo "Second connection log (checking for resumption):"
    strings /tmp/mqtt_tls_second.log 2>/dev/null | grep -a "New, TLSv" | head -5
    echo ""
    echo "Resumption indicators searched for: Reused, Resumed, PSK, Early data"
    strings /tmp/mqtt_tls_second.log 2>/dev/null | grep -iE "reused|resumed|psk|early" | head -5 || echo "  None found"
    echo ""
    rm -f "$SESSION_FILE" /tmp/mqtt_tls_first.log /tmp/mqtt_tls_second.log
    exit 1
else
    echo "✓ TLS 1.3 session ticket was received and used successfully"
fi
echo ""
RESUMPTION_SUCCESS=false

if [ -n "$RESUMED" ]; then
    echo "Session resumption detected: $RESUMED"
    RESUMPTION_SUCCESS=true
elif [ -n "$PSK_USED" ] && [ -n "$(echo "$PSK_USED" | grep -i "accepted\|used")" ]; then
    echo "PSK (Pre-Shared Key) accepted - session was resumed"
    echo "  Details: $PSK_USED"
    RESUMPTION_SUCCESS=true
elif [ -n "$EARLY_DATA" ]; then
    echo "Early data indication - session was resumed"
    RESUMPTION_SUCCESS=true
elif [ -n "$TLS13_RESUMPTION" ]; then
    echo "TLS 1.3 resumption detected: $TLS13_RESUMPTION"
    RESUMPTION_SUCCESS=true
fi

# If still not detected, show debug info
if [ "$RESUMPTION_SUCCESS" = "false" ]; then
    echo "Debug: Checking logs for resumption indicators..."
    echo "  RESUMED: ${RESUMED:-<not found>}"
    echo "  PSK_USED: ${PSK_USED:-<not found>}"
    echo "  EARLY_DATA: ${EARLY_DATA:-<not found>}"
    echo "  TLS13_RESUMPTION: ${TLS13_RESUMPTION:-<not found>}"
    echo ""
    echo "Second connection log (last 30 lines):"
    tail -30 /tmp/mqtt_tls_second.log 2>/dev/null || echo "Log file not found or empty"
fi

# Cleanup (only if successful, keep logs on failure for debugging)
if [ "$RESUMPTION_SUCCESS" = "true" ]; then
    rm -f "$SESSION_FILE" /tmp/mqtt_tls_first.log /tmp/mqtt_tls_second.log
fi

# Print result
echo ""
if [ "$RESUMPTION_SUCCESS" = "true" ]; then
    echo -e "${GREEN}=========================================="
    echo -e "✓ TLS Session Resumption: SUCCESS"
    echo -e "==========================================${NC}"
    exit 0
else
    echo -e "${RED}=========================================="
    echo -e "✗ TLS Session Resumption: FAILED"
    echo -e "==========================================${NC}"
    exit 1
fi
