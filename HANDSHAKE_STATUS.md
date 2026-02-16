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

## What's NOT Working

### Handshake Packet Decryption (pkt_type=2)
**Symptom**: `decrypt ret=-74` (EBADMSG) on the server's Handshake packet at the client.

**Root cause investigation**:

1. **HP removal runs** but produces suspicious results:
   - `data[0]`: 0xef -> 0xe4 (pn_len=1 from low bits)
   - `pkt_num` decoded as 58 instead of expected 0

2. **Bug found and partially fixed**: `tquic_crypto_set_level()` was never called after
   installing Handshake keys. Without it:
   - `crypto->read_level` stayed at `TQUIC_ENC_INITIAL`
   - AEAD key was not activated for `aead_rx`
   - HP context `current_read_level` stayed at `TQUIC_HP_LEVEL_INITIAL`

   **Fix applied**: Added `tquic_crypto_set_level()` calls in both client and server
   paths of `tquic_inline_hs_recv_crypto()`. But decrypt still fails.

3. **Current theory**: The AEAD key and HP key are now being set to Handshake level,
   but the derived keys may be incorrect. Possibilities:
   - The handshake traffic secrets from `tquic_hs_get_handshake_secrets()` don't match
     what the server used
   - The HKDF-Expand-Label derivation produces wrong key/IV/HP material
   - The nonce construction (IV XOR pkt_num) is wrong due to incorrect IV
   - There's a read/write secret swap (client vs server perspective)

## Key Files and Functions

| File | Function | Purpose |
|------|----------|---------|
| `tquic_input.c:3703` | `tquic_udp_recv` | Main packet receive entry |
| `tquic_input.c:3076` | `tquic_process_packet` | Packet decrypt + frame dispatch |
| `tquic_input.c:407` | `tquic_remove_header_protection` | HP removal (uses `crypto->hp_ctx`) |
| `tquic_input.c:463` | `tquic_decrypt_payload` | AEAD decryption (uses `crypto->aead_rx`) |
| `tquic_handshake.c:1226` | `tquic_inline_hs_recv_crypto` | Client/server handshake state machine |
| `tquic_handshake.c:1106` | `tquic_inline_hs_install_keys` | Key derivation and installation |
| `crypto/tls.c:1140` | `tquic_crypto_install_keys` | Stores keys, derives AEAD/HP/IV |
| `crypto/tls.c:1087` | `tquic_crypto_set_level` | Activates AEAD keys, syncs HP level |
| `crypto/tls.c:341` | `tquic_derive_keys_versioned` | HKDF-Expand-Label for key/IV/HP |
| `crypto/tls.c:397` | `tquic_setup_hp_keys` | Installs HP keys in HP context |
| `crypto/header_protection.c:956` | `tquic_hp_set_level` | Switches active HP read/write level |
| `crypto/handshake.c` | `tquic_hs_get_handshake_secrets` | Returns client/server HS secrets |

## Where to Add Debugging Traces

### Priority 1: Key Material Verification
These traces would directly identify whether the derived keys match between client and server.

1. **`tquic_inline_hs_install_keys()` (tquic_handshake.c ~1191)**
   ```c
   // After tquic_crypto_install_keys returns:
   pr_warn("install_keys: level=%d ret=%d conn=%p is_server=%d\n",
           level, ret, conn, conn->is_server);
   // Print first 8 bytes of secrets for comparison:
   pr_warn("install_keys: read_secret=%*phN write_secret=%*phN\n",
           8, server_secret, 8, client_secret);
   ```

2. **`tquic_derive_keys_versioned()` (crypto/tls.c ~381)**
   ```c
   // After keys->valid = true:
   pr_warn("derive_keys: key=%*phN iv=%*phN hp=%*phN\n",
           min_t(int, keys->key_len, 8), keys->key,
           min_t(int, keys->iv_len, 8), keys->iv,
           min_t(int, keys->key_len, 8), keys->hp_key);
   ```

3. **`tquic_crypto_set_level()` (crypto/tls.c ~1094)**
   ```c
   pr_warn("crypto_set_level: read=%d write=%d "
           "read_key_valid=%d write_key_valid=%d\n",
           read_level, write_level,
           crypto->read_keys[read_level].valid,
           crypto->write_keys[write_level].valid);
   ```

### Priority 2: HP Unprotect Internals
4. **`tquic_hp_unprotect()` (crypto/header_protection.c)**
   ```c
   // At entry:
   pr_warn("hp_unprotect: read_level=%d has_key=%d\n",
           ctx->current_read_level,
           tquic_hp_has_key(ctx, ctx->current_read_level, 0));
   ```

### Priority 3: AEAD Decrypt Internals
5. **`tquic_decrypt_packet()` (crypto/tls.c)**
   ```c
   // Before crypto_aead_decrypt:
   pr_warn("aead_decrypt: read_level=%d key_valid=%d "
           "iv=%*phN pkt_num=%llu\n",
           crypto->read_level,
           crypto->read_keys[crypto->read_level].valid,
           8, crypto->read_keys[crypto->read_level].iv,
           pkt_num);
   ```

### Priority 4: Server-Side Key Comparison
6. **Server `tquic_output_flush_crypto()` (tquic_output.c ~2522)**
   ```c
   // Before encrypting Handshake packet:
   pr_warn("flush_crypto: encrypting space=%d write_level=%d\n",
           space, crypto->write_level);
   ```

## Test Procedure

```bash
# On VPS (165.245.136.125):
dmesg -C
cd /root/tquic-kernel/net/tquic/test/interop/tools
./tquic_test_server -a 127.0.0.1 -p 5555 \
    --cert /root/tquic-certs/server.crt \
    --key /root/tquic-certs/server.key -v &
sleep 2
./tquic_test_client -a 127.0.0.1 -p 5555 --test-mode handshake -v
dmesg | grep -E 'process_pkt|install_keys|derive_keys|crypto_set_level|hp_unprotect|aead_decrypt'
```

## Next Steps

1. Add Priority 1 traces to verify key material matches between client and server
2. If secrets match, add Priority 2-3 traces to check HP mask and AEAD nonce
3. Compare server's encrypt key/IV with client's decrypt key/IV byte-for-byte
4. Verify `tquic_hs_get_handshake_secrets()` returns correct TLS 1.3 handshake secrets
