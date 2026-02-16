# TQUIC Handshake Status

## What's Working

### Server-Side TLS 1.3
- **ClientHello parsing**: All 7 extensions parsed (supported_versions, supported_groups,
  signature_algorithms, key_share, psk_key_exchange_modes, alpn, quic_transport_params)
- **ServerHello generation**: 122-byte SH with x25519 key share, TLS_AES_128_GCM_SHA256
- **Server flight generation**: EncryptedExtensions + Certificate + CertificateVerify + Finished
  - PKCS#8 unwrapper working: `key_len=1218 rsa_key_len=1192`
  - RSA-PSS signing succeeds
- **Server output**: Both Initial (SH, 1182 bytes) and Handshake (flight, 1245 bytes) packets
  transmitted successfully via `tquic_output_flush_crypto` (ret=2)
- **Server handshake and app key installation**: Keys derived and installed at both levels

### Client-Side Packet Reception
- **DCID-based connection lookup**: Client's SCID correctly registered in `cid_lookup_table`;
  server response packets matched via DCID lookup in `tquic_udp_recv`
- **Initial packet decryption**: ServerHello decrypted with Initial keys (ret=0, 1136 bytes)
- **CRYPTO frame extraction**: SH extracted at enc_level=0, data[0..3]=02000076
- **ServerHello processing**: `inline_hs_recv_crypto ret=0`; state transition
  `WAIT_SH -> WAIT_EE` detected
- **Handshake key installation**: `tquic_inline_hs_install_keys(HANDSHAKE)` called after SH

### Infrastructure
- Module loads/unloads cleanly
- Rate limiting, ratelimit cookie, and stateless reset paths work
- Path MTU: 65507 (loopback), no EMSGSIZE issues

## Bugs Found and Fixed

### 1. Missing `tquic_crypto_set_level()` after key installation
**Symptom**: HP removal used Initial-level keys for Handshake packets, producing garbage PN
(e.g., 9733027 instead of 0) and AEAD decrypt failure (-74 EBADMSG).

**Root cause**: `tquic_inline_hs_recv_crypto()` installed Handshake keys via
`tquic_inline_hs_install_keys()` but never called `tquic_crypto_set_level()` to activate
them. The single `aead_rx`/`hp_ctx` stayed at Initial level.

**Fix**: Added `tquic_crypto_set_level(HANDSHAKE, HANDSHAKE)` calls in both client and
server paths of `tquic_inline_hs_recv_crypto()`.

### 2. Secret swap bug in `tquic_inline_hs_install_keys()`
**Symptom**: Even after fixing level activation, Handshake decrypt still failed (-74).
HP removal produced wrong packet numbers.

**Root cause**: `tquic_crypto_install_keys(crypto, level, server_secret, client_secret)`
was called unconditionally. This is correct for the CLIENT (read=server, write=client)
but BACKWARDS for the SERVER (should be read=client, write=server).

In TLS 1.3 QUIC:
- `client_secret` = client TX / server RX
- `server_secret` = server TX / client RX

**Fix** (in tquic_handshake.c ~1174-1197):
```c
if (conn->is_server)
    ret = tquic_crypto_install_keys(crypto, level,
                                    client_secret, cs_len,
                                    server_secret, ss_len);
else
    ret = tquic_crypto_install_keys(crypto, level,
                                    server_secret, ss_len,
                                    client_secret, cs_len);
```

## What's NOT Working

### Single-AEAD Architecture: Level Switch Destroys Previous Keys

**Symptom**: After the secret swap fix, the client's Initial packet decryption now fails
(-74 EBADMSG), and Handshake HP removal returns -126 (ENOKEY).

**Root cause**: `tquic_crypto_state` has only a SINGLE `aead_tx`, `aead_rx`, and `hp_ctx`.
When the server calls `tquic_crypto_set_level(HANDSHAKE)`, the single `aead_tx` is
overwritten with the Handshake TX key. Then `tquic_output_flush_crypto()` iterates over
BOTH Initial and Handshake PN spaces, encrypting ALL packets with the current `aead_tx`
(now Handshake). The Initial-level ServerHello gets encrypted with the wrong key.

**Call sequence on server**:
1. `tquic_inline_hs_recv_crypto()` processes ClientHello
2. Installs Handshake keys via `tquic_inline_hs_install_keys(HANDSHAKE)`
3. Calls `tquic_crypto_set_level(HANDSHAKE, HANDSHAKE)` -- overwrites `aead_tx`
4. Generates server flight (SH in Initial space, EE+Cert+CV+Fin in Handshake space)
5. Calls `tquic_output_flush_crypto()` which encrypts BOTH spaces
6. Initial space ServerHello encrypted with Handshake key (WRONG!)

**Architecture issue**:
```
struct tquic_crypto_state {
    struct tquic_crypto_keys read_keys[LEVEL_COUNT];   // per-level storage OK
    struct tquic_crypto_keys write_keys[LEVEL_COUNT];  // per-level storage OK
    struct crypto_aead *aead_tx;   // SINGLE - overwritten on level change
    struct crypto_aead *aead_rx;   // SINGLE - overwritten on level change
    struct tquic_hp_ctx *hp_ctx;   // SINGLE - only tracks current level
};
```

**Possible fixes** (in order of preference):
1. **Flush Initial before level switch**: In the server handshake path, call
   `tquic_output_flush_crypto()` for the Initial space BEFORE calling
   `tquic_crypto_set_level(HANDSHAKE)`. Then flush Handshake space after.
2. **Per-level AEAD selection in encrypt/decrypt**: Make `tquic_encrypt_payload()`
   and `tquic_decrypt_payload()` select keys from `write_keys[level]`/`read_keys[level]`
   based on the `pkt_type` parameter, rather than using the single `aead_tx`/`aead_rx`.
3. **Per-level AEAD contexts**: Add `aead_tx[LEVEL_COUNT]` and `aead_rx[LEVEL_COUNT]`
   arrays to `tquic_crypto_state` so level switching doesn't destroy previous keys.

## Key Files and Functions

| File | Function | Purpose |
|------|----------|---------|
| `tquic_input.c:3703` | `tquic_udp_recv` | Main packet receive entry |
| `tquic_input.c:3076` | `tquic_process_packet` | Packet decrypt + frame dispatch |
| `tquic_input.c:407` | `tquic_remove_header_protection` | HP removal (uses `crypto->hp_ctx`) |
| `tquic_input.c:463` | `tquic_decrypt_payload` | AEAD decryption (uses `crypto->aead_rx`) |
| `tquic_handshake.c:1226` | `tquic_inline_hs_recv_crypto` | Client/server handshake state machine |
| `tquic_handshake.c:1106` | `tquic_inline_hs_install_keys` | Key derivation and installation |
| `tquic_output.c:1052` | `tquic_encrypt_payload` | AEAD encryption for outgoing packets |
| `tquic_output.c:2544` | `tquic_output_flush_crypto` | Iterates PN spaces, sends crypto packets |
| `tquic_output.c:1086` | `tquic_assemble_packet` | Builds and encrypts a single packet |
| `crypto/tls.c:182` | `struct tquic_crypto_state` | Single AEAD/HP + per-level key storage |
| `crypto/tls.c:1140` | `tquic_crypto_install_keys` | Stores keys, derives AEAD/HP/IV |
| `crypto/tls.c:1087` | `tquic_crypto_set_level` | Activates AEAD keys, syncs HP level |
| `crypto/tls.c:341` | `tquic_derive_keys_versioned` | HKDF-Expand-Label for key/IV/HP |
| `crypto/tls.c:397` | `tquic_setup_hp_keys` | Installs HP keys in HP context |
| `crypto/header_protection.c:956` | `tquic_hp_set_level` | Switches active HP read/write level |
| `crypto/handshake.c` | `tquic_hs_get_handshake_secrets` | Returns client/server HS secrets |

## Test Procedure

```bash
# On VPS (165.245.136.125):
T=/root/tquic-kernel/net/tquic/test/interop
dmesg -C
$T/tools/tquic_test_server -a 127.0.0.1 -p 4433 \
    -c $T/certs/server.crt -k $T/certs/server.key -v &
sleep 2
timeout 10 $T/tools/tquic_test_client -a 127.0.0.1 -p 4433 -v
dmesg | grep -E 'process_pkt|install_keys|derive_keys|crypto_set_level|hp_unprotect|aead_decrypt|flush_crypto|encrypt_payload'
```

**Note**: Orphaned sockets from test connections hold module references, preventing
`rmmod`. A VPS reboot is required between test iterations that need module reload.

## Next Steps

1. **Fix the single-AEAD level switch issue** (preferred: flush Initial before level switch)
   - In server handshake path, split the output flush to encrypt Initial packets before
     switching to Handshake level
   - Alternatively, make `tquic_encrypt_payload` select per-level keys from the stored arrays
2. **Verify full handshake completion**: After fixing encryption, confirm client processes
   ServerHello -> derives Handshake keys -> decrypts Handshake packet -> processes
   EE + Certificate + CertificateVerify + Finished -> sends client Finished
3. **Handle client Finished generation and transmission**
4. **Clean up orphaned socket handling** to avoid requiring VPS reboots
5. **Remove debug pr_warn traces** and reduce to pr_debug once handshake works
