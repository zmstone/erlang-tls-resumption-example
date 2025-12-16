# Erlang TLS Resumption

A demo application to test TLS session resumption for both TLS 1.2 and TLS 1.3 protocols.

## Overview

This application demonstrates and verifies TLS session resumption functionality:
- **TLS 1.2**: Uses session ID-based resumption with external session cache
- **TLS 1.3**: Uses session ticket-based resumption

The application tracks session resumption by:
- Using random printable client IDs (16-character base62 strings) to identify connections
- Tracking ping message counts per client to determine expected resumption state
- Comparing session IDs (TLS 1.2) or checking `session_resumption` flag (TLS 1.3)
- Verifying that resumption works correctly on reconnection

## Quick Start

### Start Server

```bash
./run.sh server
```

The server listens on port 9999 (default) and accepts TLS connections with client certificate authentication.

### Start Client

```bash
# Test TLS 1.2 session resumption
env TLSER_TLS_VERSION=1.2 ./run.sh client

# Test TLS 1.3 session resumption
env TLSER_TLS_VERSION=1.3 ./run.sh client
```

## How It Works

### Client Behavior

1. **First Connection**:
   - Generates a unique random client ID (16-character printable string)
   - Performs full TLS handshake
   - Sends `ping-<clientid>` message
   - Stores session ID (TLS 1.2) or receives session ticket (TLS 1.3)

2. **Second Connection**:
   - Reconnects using stored session ID (TLS 1.2) or session ticket (TLS 1.3)
   - Sends `ping-<clientid>` message with same client ID
   - Verifies session resumption by comparing session IDs or checking resumption flag

3. **TLS 1.3 Additional Test**:
   - Tests corrupted ticket rejection (ensures server properly validates tickets)

### Server Behavior

1. **First Connection**:
   - Receives `ping-<clientid>` message
   - Extracts client ID from ping message
   - Gets current session ID from socket
   - Stores session ID associated with client ID (ping count = 1)
   - Logs "First connection" message

2. **Second Connection**:
   - Receives `ping-<clientid>` message with same client ID
   - Gets current session ID from socket
   - Checks ping count (ping count = 2, so resumption is expected)
   - For TLS 1.2: Compares current session ID with stored session ID
   - For TLS 1.3: Uses `check_session_resumption/2` to check `session_resumption` flag
   - Logs verification result (success or failure)

## Configuration

### Environment Variables

#### Client Configuration

- `TLSER_TLS_VERSION`: TLS version to use
  - `"1.2"` - TLS 1.2 only
  - `"1.3"` - TLS 1.3 only
  - Not set - Both 1.3 (default)

- `TLSER_SERVER_HOST`: Server hostname (default: `localhost`)

- `TLSER_CLIENT_NO_HOST_CHECK`: Disable hostname verification
  - Set to `"1"`, `"true"`, or `"yes"` to disable hostname checking
  - Useful when connecting to IP addresses (e.g., `127.0.0.1`) instead of hostname
  - Certificate verification is still performed, only hostname check is disabled

- `TLSER_CLIENT_CIPHERS`: Comma-separated cipher suite names (optional)

#### Server Configuration

- `TLSER_SERVER_PORT`: Server port number (default: `9999`)

#### Shared Configuration

- `TLSER_LOG_LEVEL`: SSL debug logging level
  - `"debug"` - Enable SSL debug logging
  - Not set - Standard logging (default)

- `TLSER_CERTS`: Path to certificates directory (default: `certs`)
  - Must contain:
    - `ca.pem` - CA certificate (used by both client and server)
    - `cert.pem` - Server certificate
    - `key.pem` - Server private key
    - `client-cert.pem` - Client certificate
    - `client-key.pem` - Client private key

## Example Usage

### Test TLS 1.2 Session Resumption

```bash
# Terminal 1: Start server
env TLSER_LOG_LEVEL=debug ./run.sh server > server.log 2>&1

# Terminal 2: Start client
env TLSER_TLS_VERSION=1.2 TLSER_LOG_LEVEL=debug ./run.sh client > client.log 2>&1

# Connect to IP address instead of hostname (disable hostname check)
env TLSER_TLS_VERSION=1.2 TLSER_SERVER_HOST=127.0.0.1 TLSER_CLIENT_NO_HOST_CHECK=1 ./run.sh client
```

### Test TLS 1.3 Session Resumption

```bash
# Terminal 1: Start server
env TLSER_LOG_LEVEL=debug ./run.sh server > server.log 2>&1

# Terminal 2: Start client
env TLSER_TLS_VERSION=1.3 TLSER_LOG_LEVEL=debug ./run.sh client > client.log 2>&1
```

### OpenSSL Client Interoperability Tests

The project includes scripts to test session resumption using OpenSSL's `s_client` tool, which helps verify interoperability with standard TLS clients:

```bash
# Test TLS 1.2 session resumption with OpenSSL client
./openssl-client-inter-op-tls1.2.sh

# Test TLS 1.3 session resumption with OpenSSL client
./openssl-client-inter-op-tls1.3.sh

# With custom server host/port
TLSER_SERVER_HOST=127.0.0.1 TLSER_SERVER_PORT=9999 ./openssl-client-inter-op-tls1.2.sh
```

These scripts:
- Connect to the server using OpenSSL `s_client`
- Send ping messages with client IDs (same format as Erlang client)
- Save and reuse TLS sessions/tickets
- Verify session resumption at the TLS level
- Display minimal output (only Session IDs, resumption indicators, and pong responses)

The server will verify session resumption based on the client ID and log the result, just like with the Erlang client.

### External Server Testing Scripts

The project includes scripts to test TLS 1.3 session resumption against external servers (e.g., MQTT brokers):

#### Pure TLS 1.3 Resumption Test

```bash
# Test TLS 1.3 session resumption (no application data)
./tls1.3-resumption-test.sh [host:port]

# Examples
./tls1.3-resumption-test.sh localhost:8883
./tls1.3-resumption-test.sh tls.example.com:443
```

**Features:**
- Pure TLS handshake test (no application protocol)
- Forces TLS 1.3 negotiation
- Verifies TLS 1.3 session ticket was received
- Disconnects and reconnects using the saved ticket
- Verifies session resumption occurred
- Useful for testing any TLS 1.3 server, not just MQTT

**Requirements:**
- Server must support TLS 1.3
- Server must send session tickets for TLS 1.3 resumption

**Exit Codes:**
- `0` - Success (TLS 1.3 negotiated and resumption verified)
- `1` - Failure (TLS 1.3 not supported, no ticket received, or resumption failed)

Both scripts provide detailed error messages and debug information when tests fail, making it easy to diagnose TLS configuration issues.

#### MQTT TLS 1.3 Resumption Test

```bash
# Test TLS 1.3 session resumption with MQTT server
./mqtt-tls1.3-resumption-test.sh [host:port]

# Examples
./mqtt-tls1.3-resumption-test.sh localhost:8883
./mqtt-tls1.3-resumption-test.sh mqtt.example.com:8883
```

**Features:**
- Forces TLS 1.3 negotiation (exits with error if server doesn't support TLS 1.3)
- Sends MQTT CONNECT packet over TLS
- Verifies TLS 1.3 session ticket was received
- Reconnects and verifies session resumption worked
- Provides clear error messages if TLS 1.3 is not supported or tickets are not sent

**Requirements:**
- Server must support TLS 1.3
- Server must send session tickets for TLS 1.3 resumption
- Server must accept MQTT connections

## Session Resumption Verification

The application uses ping message counts to determine expected resumption state:
- **First ping** (ping count = 1): Full handshake expected
- **Second ping** (ping count = 2): Session resumption expected

### TLS 1.2

- **Client**: Compares current session ID with stored session ID using `check_session_resumption/2`
- **Server**: Compares current session ID with stored session ID for the client using `check_session_resumption/2`
- Both verify resumption by session ID comparison
- If session IDs match → resumption verified
- If session IDs don't match → test fails

### TLS 1.3

- **Client**: Uses `check_session_resumption/2` which checks `session_resumption` flag from `ssl:connection_information/2`
- **Server**: Uses `check_session_resumption/2` which checks `session_resumption` flag from `ssl:connection_information/2`
- Both verify resumption using the flag
- Session IDs are tracked for all clients but not used for TLS 1.3 verification

## Requirements

- Erlang/OTP 28 or later
- rebar3

## License

Apache 2.0
