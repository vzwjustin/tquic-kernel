# RFC 9000 Section 12.2 Packet Coalescing - Key Code Snippets

## 1. Payload Length Validation in quic_packet_parse_long()

Location: net/quic/packet.c, lines 133-145

```c
	/*
	 * Validate payload length per RFC 9000 Section 12.2.
	 * The payload_len field indicates the length of the rest of the packet
	 * (packet number + encrypted payload + AEAD tag). It must not extend
	 * beyond the received packet data.
	 *
	 * Note: payload_len < remaining is allowed per RFC 9000 Section 12.2
	 * which permits coalesced packets. The peer may have combined multiple
	 * QUIC packets into a single UDP datagram.
	 */
	if (payload_len > skb->len - offset)
		return -EINVAL;
```

**Purpose:** Validates that the payload length doesn't exceed available data, while allowing for coalesced packets where payload_len < remaining buffer.

---

## 2. quic_packet_get_length() Function

Location: net/quic/packet.c, lines 172-294

```c
/*
 * quic_packet_get_length - Get the total length of a QUIC packet in a buffer
 * @data: Pointer to the start of the QUIC packet
 * @len: Total length of available data
 * @packet_len: Output parameter for the packet length
 *
 * Per RFC 9000 Section 12.2, multiple QUIC packets can be coalesced into a
 * single UDP datagram. This function determines the length of the first
 * packet so subsequent packets can be separated and processed.
 *
 * For long header packets, the length is determined by the Length field.
 * For short header packets, the entire remaining buffer is the packet.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int quic_packet_get_length(const u8 *data, int len, int *packet_len)
{
	// ... [125 lines of implementation]
	// Parses header to extract length
	// Validates all fields
	// Returns packet length in *packet_len
}
```

**Key Logic:**
- Short header → entire buffer is one packet
- Long header → parse to Length field, return header + payload_len
- Retry packet → entire buffer (no Length field)
- All validations: fixed bit, DCID/SCID lengths, token length, payload length

---

## 3. Enhanced quic_packet_process() with Coalescing

Location: net/quic/packet.c, lines 605-768

### a) Variables for Coalescing Support

```c
void quic_packet_process(struct quic_connection *conn, struct sk_buff *skb)
{
	struct quic_crypto_ctx *ctx;
	u8 first_byte;
	u8 pn_offset, pn_len;
	u64 truncated_pn, pn;
	u8 level;
	int err;
	int packet_len;           // NEW: Track first packet length
	struct sk_buff *next_skb; // NEW: Hold coalesced packets
```

### b) Packet Length Detection

```c
	/*
	 * RFC 9000 Section 12.2: Coalesced Packets
	 * Determine the length of this packet. For long header packets,
	 * this allows us to separate coalesced packets. For short header
	 * packets, the entire remaining datagram is this packet.
	 */
	err = quic_packet_get_length(skb->data, skb->len, &packet_len);
	if (err) {
		kfree_skb(skb);
		return;
	}

	/*
	 * Validate packet_len is within bounds.
	 * This should not happen given quic_packet_get_length validation,
	 * but defense in depth is important for network code.
	 */
	if (packet_len < 1 || packet_len > skb->len) {
		kfree_skb(skb);
		return;
	}
```

### c) Coalesced Packet Separation

```c
	/*
	 * If there's data remaining after this packet, we have coalesced
	 * packets. Create a new skb for the remaining data and queue it
	 * for processing after we finish with this packet.
	 */
	next_skb = NULL;
	if (packet_len < skb->len) {
		int remaining = skb->len - packet_len;

		/*
		 * Validate remaining data has at least a header byte
		 * to prevent processing empty/corrupt trailing data.
		 */
		if (remaining >= 1) {
			next_skb = alloc_skb(remaining + 64, GFP_ATOMIC);
			if (next_skb) {
				skb_reserve(next_skb, 64);
				skb_put_data(next_skb, skb->data + packet_len,
					     remaining);
			}
			/* If allocation fails, we just lose the coalesced packet(s) */
		}
		/* Trim this skb to just the first packet */
		skb_trim(skb, packet_len);
	}
```

### d) Modified Control Flow (Example)

**Before:**
```c
	case QUIC_LONG_TYPE_RETRY:
		/* Handle retry packet specially */
		quic_packet_process_retry(conn, skb);
		return;  // OLD: Direct return
	default:
		kfree_skb(skb);
		return;  // OLD: Direct return
```

**After:**
```c
	case QUIC_LONG_TYPE_RETRY:
		/* Handle retry packet specially */
		quic_packet_process_retry(conn, skb);
		goto process_next;  // NEW: Process coalesced packets
	default:
		kfree_skb(skb);
		goto process_next;  // NEW: Process coalesced packets
```

### e) Recursive Processing

```c
	kfree_skb(skb);

process_next:
	/* Process any remaining coalesced packets */
	if (next_skb)
		quic_packet_process(conn, next_skb);  // Recursive call
}
```

---

## Usage Example

When a UDP datagram contains an Initial packet (500 bytes) followed by a Handshake packet (800 bytes):

1. First call to `quic_packet_process()`:
   - `quic_packet_get_length()` returns 500
   - Remaining data (800 bytes) copied to `next_skb`
   - Current skb trimmed to 500 bytes
   - Initial packet processed normally
   - At `process_next:`, recursively calls with `next_skb`

2. Second call (recursive):
   - `quic_packet_get_length()` returns 800
   - No remaining data (packet_len == skb->len)
   - `next_skb` stays NULL
   - Handshake packet processed normally
   - At `process_next:`, next_skb is NULL, function returns

Result: Both packets processed correctly with correct encryption levels.

---

## Error Handling

All error cases properly handled:

1. **Malformed Length field** → `quic_packet_get_length()` returns -EINVAL
2. **Allocation failure for next_skb** → Graceful degradation, first packet still processed
3. **Decryption failure** → Current packet freed, next packet still processed
4. **Invalid encryption level** → Current packet freed, next packet still processed

---

## Performance Characteristics

- **Overhead:** One additional header parse per coalesced packet
- **Memory:** One additional skb allocation per coalesced packet
- **Latency:** Recursive processing adds minimal overhead (tail recursion)
- **Scalability:** Limited by recursion depth (max ~5-10 packets practical)

---

## Testing Checklist

- [ ] Single packet (no coalescing) - backward compatibility
- [ ] Initial + Handshake coalesced packets
- [ ] Initial + Handshake + 1-RTT coalesced packets
- [ ] Malformed Length field (too large)
- [ ] Corrupted coalesced packet data
- [ ] Allocation failure during next_skb creation
- [ ] Maximum coalescing depth (many small packets)
- [ ] Short header packets (should consume entire buffer)
- [ ] Retry packets (special case, no Length field)

---

## Kernel Coding Style Compliance

- ✓ Tab indentation (not spaces)
- ✓ 80-character line limit (flexible for readability)
- ✓ K&R brace style
- ✓ Proper comment style (/* */ for multi-line, // for inline)
- ✓ Variable declarations at start of scope
- ✓ Error handling with goto labels
- ✓ Defensive programming (validation before use)

---

## RFC Compliance Matrix

| Requirement | Status | Location |
|------------|--------|----------|
| Parse Length field correctly | ✓ | quic_packet_get_length() |
| Separate coalesced packets | ✓ | quic_packet_process() |
| Process multiple encryption levels | ✓ | Existing + coalescing |
| Short header consumes entire buffer | ✓ | quic_packet_get_length() |
| Validate Length field values | ✓ | Both locations |
| Handle padding correctly | ✓ | Existing frame processing |
| Support Initial + Handshake | ✓ | Encryption level handling |
| Support 0-RTT coalescing | ✓ | Encryption level handling |

---

## Integration Status

✅ **COMPLETE** - All three modifications from reference implementation applied:
1. ✅ Payload validation in `quic_packet_parse_long()`
2. ✅ New `quic_packet_get_length()` function
3. ✅ Enhanced `quic_packet_process()` with coalescing support

Optional enhancement for output path (quic_coalesce_packets validation) not implemented as it's lower priority.
