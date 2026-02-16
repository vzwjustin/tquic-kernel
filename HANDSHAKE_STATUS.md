# TQUIC Handshake & Data Exchange Status

## Current State: Bidirectional Data Exchange Working

Full end-to-end data flow verified: 10KB file download completes successfully
with the userspace test client/server over the kernel QUIC transport.
100KB partial transfer also works (38KB received before flow control window
exhaustion — MAX_DATA updates not yet generated).

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

3. **Application Data Exchange**
   - Stream creation for peer-initiated (incoming) streams
   - Stream-level and connection-level flow control
   - Data enqueue to stream receive buffers
   - Blocking and non-blocking recv() with wait_event_interruptible
   - Lazy default_stream initialization on server-side accepted sockets
   - Server HTTP GET request parsing and file serving

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

1. **Flow control window updates**: Generate MAX_DATA/MAX_STREAM_DATA frames
   as application reads data — needed for transfers larger than initial window
2. **FIN handling**: Stream FIN for clean data transfer completion
3. **ACK generation**: Send ACKs for received packets to advance loss detection
4. **Connection close wakeup**: Wake blocked stream waiters on connection close
5. **Larger file transfers**: Test with multi-MB files after flow control updates
6. **Module refcount cleanup**: Fix orphaned socket handling preventing rmmod
