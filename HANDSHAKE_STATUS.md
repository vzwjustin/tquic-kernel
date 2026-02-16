# TQUIC Handshake & Data Exchange Status

## Current State: Clean End-to-End Data Exchange with Connection Teardown

Full bidirectional data flow with clean shutdown verified: 10KB file download
completes in 11ms (7.45 Mbps) with proper CONNECTION_CLOSE exchange.
Client exits cleanly (exit code 0). ACK generation and MAX_DATA flow control
updates are in place for larger transfers.

### What's Working

1. **TLS 1.3 Handshake** (cert_verify bypass mode)
   - ClientHello parsing with all 7 extensions
   - ServerHello generation with x25519 key share
   - Server flight: EncryptedExtensions + Certificate + CertificateVerify + Finished
   - PKCS#8-to-PKCS#1 unwrapper for RSA-PSS signing
   - Handshake and Application key derivation and installation
   - Per-level AEAD/HP context selection

2. **Packet Processing**
   - DCID-based connection lookup via rhashtable
   - Initial, Handshake, and 1-RTT packet decryption
   - Header protection removal/application for all packet types
   - CRYPTO frame extraction and handshake state machine
   - Immediate ACK generation for 1-RTT ack-eliciting packets

3. **Application Data Exchange**
   - Stream creation for peer-initiated (incoming) streams
   - Stream-level and connection-level flow control
   - MAX_DATA flow control window updates (sent when half window consumed)
   - Data enqueue to stream receive buffers
   - Blocking and non-blocking recv() with wait_event_interruptible
   - Lazy default_stream initialization on server-side accepted sockets
   - Server HTTP GET request parsing and file serving

4. **Connection Lifecycle**
   - CONNECTION_CLOSE frame transmission via dedicated tquic_xmit_close()
   - Clean connection teardown for server connections (with or without state machine)
   - Stream waiters woken on CLOSING/DRAINING state transitions
   - Bidirectional CONNECTION_CLOSE exchange verified

### Infrastructure
- Module loads/unloads cleanly
- Rate limiting, ratelimit cookie, and stateless reset paths work
- Path MTU: 65507 (loopback), no EMSGSIZE issues

## Bugs Found and Fixed

### Critical: Spinlock Deadlock in Stream Creation
**File**: `tquic_main.c` `tquic_stream_create_locked()`

`tquic_stream_create_locked()` re-acquired `conn->lock` despite its
comment stating "Caller must hold conn->lock". When called from
`tquic_stream_open_incoming()` (which already holds the lock), this
caused recursive spinlock acquisition in softirq context, deadlocking
the CPU and freezing the entire VPS.

**Fix**: Removed redundant `spin_lock_bh/spin_unlock_bh` pairs.

### Critical: Wrong MAX_STREAMS Limit for Incoming Streams
**File**: `tquic_main.c` `tquic_stream_create_locked()`

Incoming stream validation checked `conn->max_streams_bidi` (the peer's
outgoing limit, 0 for our test client) instead of
`conn->local_params.initial_max_streams_bidi` (what we advertised, 100).
All peer-initiated streams were rejected.

**Fix**: Use `conn->local_params.initial_max_streams_{bidi,uni}` for
incoming stream validation per RFC 9000 Section 4.6.

### Critical: Connection-Level Receive Flow Control Uninitialized
**File**: `tquic_handshake.c` cert_verify bypass path

The bypass handshake path set `conn->max_data_remote` (outgoing limit)
but never set `conn->max_data_local` (incoming limit), leaving it at 0.
All received STREAM data was rejected with EDQUOT.

**Fix**: Added `WRITE_ONCE(conn->max_data_local, bypass_max_data)` in
the bypass path, and initialized `local_params` from socket config in
the inline handshake path.

### HP Short Header pn_offset Corruption
**File**: `crypto/header_protection.c`

Short header HP protect/unprotect used incorrect `pn_offset`, corrupting
packet number decoding for 1-RTT packets.

**Fix**: Corrected pn_offset calculation for short headers.

### Secret Swap in Key Installation
**File**: `tquic_handshake.c` `tquic_inline_hs_install_keys()`

Server and client passed client/server secrets in the same order.
TLS 1.3 requires the server to read with client_secret and write with
server_secret (opposite of client).

**Fix**: Conditional secret ordering based on `conn->is_server`.

## Test Procedure

```bash
# On VPS (165.245.136.125):
modprobe udp_tunnel && modprobe ip6_udp_tunnel && \
  modprobe inet_diag && modprobe libcurve25519
insmod /root/tquic-kernel/net/tquic/tquic.ko
echo 0 > /proc/sys/net/tquic/debug_level

T=/root/tquic-kernel/net/tquic/test/interop
dd if=/dev/urandom of=/tmp/test.txt bs=1024 count=10

$T/tools/tquic_test_server -a 127.0.0.1 -p 4433 \
    -c $T/certs/server.crt -k $T/certs/server.key -d /tmp &
sleep 1
timeout 10 $T/tools/tquic_test_client -a 127.0.0.1 -p 4433 \
    --download /test.txt
```

**Expected**: `Downloaded 10240 bytes` with server showing `GET request for: /test.txt`

**Note**: Module refcount prevents `rmmod` after socket use. Reboot VPS
between test iterations that need module reload.

## Next Steps

1. ~~**Stream FIN handling**~~: Done - FIN sent on close via tquic_close()
2. ~~**MAX_STREAM_DATA frames**~~: Done - Per-stream flow control send + receive
3. ~~**All RFC 9000 frame types**~~: Done - Handlers for 0x04-0x17 (RESET_STREAM, STOP_SENDING, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED)
4. **Large file transfer debugging**: 100KB transfer caps at 38400 bytes; send-side is NOT blocked (cwnd/FC diagnostics don't fire); bottleneck appears to be on receive side
5. **Delayed ACK timer**: RFC 9000 Section 13.2.1 (currently sending immediate ACKs)
6. **Retransmission / loss recovery**: RFC 9002 loss detection and retransmission
7. **Module refcount cleanup**: Fix orphaned socket handling preventing rmmod
8. **Client-initiated streams**: Outgoing stream creation from kernel side
