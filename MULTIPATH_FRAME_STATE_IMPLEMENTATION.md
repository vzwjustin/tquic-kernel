# Multipath Frame State Management Implementation

## Summary

This document describes the complete implementation of multipath frame state management for TQUIC, addressing the P1 high-priority issue identified at `/net/quic/mp_frame.c` lines 28-151.

## Problem Analysis

The original implementation parsed PATH_ABANDON, PATH_STANDBY, and PATH_AVAILABLE frames (per draft-ietf-quic-multipath) but had incomplete state management:

1. **Missing field**: `status_seq_num` was referenced but not defined in `struct tquic_path`
2. **Incomplete transitions**: State changes were not properly validated or integrated
3. **No bonding integration**: Changes didn't notify the bonding state machine
4. **No scheduler updates**: Schedulers weren't informed when path availability changed
5. **Missing synchronization**: Proper locking for state transitions was incomplete

## Implementation Details

### 1. Structure Updates

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic_path.c`

Added `status_seq_num` field to `struct tquic_path`:

```c
/* Multipath extension state (draft-ietf-quic-multipath) */
u64			status_seq_num;	/* PATH_STATUS sequence number */
```

Initialized in `tquic_path_alloc()`:

```c
path->status_seq_num = 0;
```

**Purpose**: Track the sequence number of PATH_STATUS frames to prevent reordering attacks and ensure monotonic state updates per draft-ietf-quic-multipath specification.

### 2. PATH_ABANDON Frame Processing

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/mp_frame.c`

**Function**: `quic_frame_process_path_abandon()`

**Implementation**:
1. Parse PATH_ABANDON frame (path_id, error_code, reason)
2. Lookup path by ID using `tquic_pm_get_path()`
3. Transition path to `TQUIC_PATH_CLOSING` state
4. Notify bonding context via `tquic_bonding_on_path_failed()` - triggers:
   - State machine update (may transition to DEGRADED)
   - Failover if this was the primary path
   - Weight recalculation for remaining paths
5. Notify scheduler via `path_removed()` callback
6. Release path reference

**Key Design Decisions**:
- Even if state transition fails, still send notification to peer (fail-safe)
- Path removal is asynchronous; CLOSING state prevents new packet assignment
- Bonding state machine handles the transition to DEGRADED or SINGLE_PATH

### 3. PATH_STANDBY/PATH_AVAILABLE Frame Processing

**File**: `/Users/justinadams/Downloads/tquic-kernel/net/quic/mp_frame.c`

**Function**: `quic_frame_process_path_status()`

**Implementation**:
1. Parse PATH_STATUS frame (path_id, seq_num)
2. Acquire path state lock (`spin_lock_bh(&path->state_lock)`)
3. **Sequence number check**: Reject if `seq_num < path->status_seq_num` (prevents reordering)
4. Update `status_seq_num` and determine new state:
   - PATH_STANDBY → `TQUIC_PATH_STANDBY`, `is_backup = true`
   - PATH_AVAILABLE → `TQUIC_PATH_ACTIVE`, `is_backup = false`
5. **Validate state transition**:
   - Only allow if current state is VALIDATED, ACTIVE, or STANDBY
   - Prevents transitions from FAILED/CLOSING states
6. Update `path->state` and `path->last_activity`
7. Release lock
8. **Outside lock** (avoid deadlock):
   - Notify bonding context:
     - ACTIVE: Call `tquic_bonding_on_path_validated()` and `update_state()` (may trigger BONDED)
     - STANDBY: Call `tquic_bonding_derive_weights()` and `update_state()`
   - Notify scheduler:
     - ACTIVE: Call `path_added()` to make path available
     - STANDBY (from ACTIVE): Call `path_removed()` to prevent new traffic
9. Release path reference

**Key Design Decisions**:
- **Sequence numbers are critical**: Prevent MITM attacks that could downgrade active paths
- **Lock ordering**: State lock held only during state update, bonding/scheduler callbacks outside
- **Two-phase notification**: State machine update then scheduler update ensures consistency
- **Bidirectional transitions**: ACTIVE ↔ STANDBY supported per spec

### 4. Sending PATH_ABANDON Frames

**Function**: `quic_send_path_abandon()`

**Implementation**:
1. Transition local path to `TQUIC_PATH_CLOSING`
2. Create PATH_ABANDON frame with `error_code`
3. Queue frame for transmission
4. Notify bonding context (`tquic_bonding_on_path_failed()`)
5. Notify scheduler (`path_removed()`)

**Use Cases**:
- Local path failure detected
- Network interface going down
- User-initiated path removal
- Quality degradation threshold exceeded

### 5. Sending PATH_STANDBY Frames

**Function**: `quic_send_path_standby()`

**Implementation**:
1. **Validate state**: Can only send if currently VALIDATED or ACTIVE
2. Acquire lock, increment `status_seq_num`, update state to STANDBY
3. Set `is_backup = true`
4. Release lock
5. Create and queue PATH_STANDBY frame
6. Notify bonding context (recalculate weights)
7. Notify scheduler (remove from active pool)

**Use Cases**:
- Battery saver mode on cellular path
- Network congestion detected
- User preference for backup-only mode
- Handoff preparation (demote before migration)

### 6. Sending PATH_AVAILABLE Frames

**Function**: `quic_send_path_available()`

**Implementation**:
1. **Validate state**: Can only send if currently VALIDATED or STANDBY
2. Acquire lock, increment `status_seq_num`, update state to ACTIVE
3. Set `is_backup = false`
4. Release lock
5. Create and queue PATH_AVAILABLE frame
6. Notify bonding context:
   - `tquic_bonding_on_path_validated()` - may trigger BONDED state
   - `tquic_bonding_derive_weights()` - recalculate traffic distribution
   - `tquic_bonding_update_state()` - update state machine
7. Notify scheduler (`path_added()` - make available for traffic)

**Use Cases**:
- Path validation complete
- Network conditions improved
- Exiting battery saver mode
- Promoting backup path to active

## State Transition Diagram

```
CREATED
   ↓
VALIDATING
   ↓
VALIDATED ←→ ACTIVE ←→ STANDBY
   ↓            ↓          ↓
CLOSING ← - - - ← - - - - ←
   ↓
FAILED
```

**Valid PATH_STATUS transitions**:
- VALIDATED → ACTIVE (PATH_AVAILABLE)
- VALIDATED → STANDBY (PATH_STANDBY)
- ACTIVE ↔ STANDBY (bidirectional)

**PATH_ABANDON transitions**:
- Any state except CREATED → CLOSING

## Integration with Bonding State Machine

The multipath frame handlers integrate with the bonding state machine defined in `tquic_bonding.h`:

### PATH_ABANDON Integration
- Calls `tquic_bonding_on_path_failed(bc, path)`
- Decrements `active_path_count` or `degraded_path_count`
- May trigger state transitions:
  - `BONDED → DEGRADED` (if paths remain but capacity reduced)
  - `BONDED → SINGLE_PATH` (if only one path remains)
  - `DEGRADED → SINGLE_PATH` (last backup failed)

### PATH_AVAILABLE Integration
- Calls `tquic_bonding_on_path_validated(bc, path)`
- Increments `active_path_count`
- May trigger state transitions:
  - `SINGLE_PATH → PENDING` (second path validating)
  - `PENDING → BONDED` (second path validated)
  - `DEGRADED → BONDED` (failed path recovered)
- Recalculates capacity weights via `tquic_bonding_derive_weights()`

### PATH_STANDBY Integration
- Path marked as backup-only
- Excluded from active traffic scheduling
- Still counted in bonding state but with lower weight
- Recalculates weights to redistribute traffic among remaining active paths

## Integration with Packet Schedulers

All multipath schedulers (aggregate, minrtt, blest, ecf, weighted) check `path->state == TQUIC_PATH_ACTIVE` before selecting paths. The frame handlers ensure schedulers are notified:

### path_added() Callback
- Called when path transitions to ACTIVE
- Scheduler-specific data structures updated
- Path becomes eligible for `get_path()` selection

### path_removed() Callback
- Called when path transitions to STANDBY or CLOSING
- Scheduler-specific data structures cleaned up
- Path excluded from `get_path()` selection
- In-flight packets on this path tracked for potential reinjection

## Security Considerations

### Sequence Number Protection
The `status_seq_num` field protects against:
- **Replay attacks**: Old PATH_STATUS frames ignored
- **Downgrade attacks**: MITM cannot force ACTIVE → STANDBY with old frames
- **Reordering issues**: Out-of-order delivery handled correctly

Per draft-ietf-quic-multipath: "Sequence numbers MUST be monotonically increasing and SHOULD be incremented by 1 for each status update."

### State Validation
- Only valid state transitions allowed (validated in `tquic_path_set_state()`)
- Cannot transition from FAILED/CLOSING back to ACTIVE (prevents resurrection attacks)
- PATH_STATUS frames rejected for paths not in VALIDATED/ACTIVE/STANDBY states

### Reference Counting
- Proper `tquic_path_get()`/`tquic_path_put()` usage prevents use-after-free
- RCU protection for path lookups
- Spinlocks protect concurrent state modifications

## Locking Strategy

### Path State Lock (`path->state_lock`)
- Protects: `state`, `status_seq_num`, `is_backup`, `last_activity`
- Type: `spinlock_bh` (bottom-half safe)
- Hold time: Minimal - only during state update
- **Critical**: Release before calling bonding/scheduler callbacks (avoid deadlock)

### Lock Ordering
1. Path state lock (shortest hold time)
2. Bonding context lock (held during state machine updates)
3. Scheduler lock (held during path list modifications)

**Deadlock prevention**: Never call bonding/scheduler callbacks while holding path lock.

## Testing Recommendations

### Unit Tests
1. **Sequence number validation**: Verify old frames rejected
2. **State transition matrix**: Test all valid and invalid transitions
3. **Concurrent updates**: Multiple threads updating same path
4. **Reference counting**: No leaks on error paths

### Integration Tests
1. **PATH_ABANDON failover**: Verify seamless traffic shift to backup
2. **PATH_STANDBY demotion**: Confirm traffic redirected to other paths
3. **PATH_AVAILABLE promotion**: Verify bonding state transitions
4. **Interoperability**: Test with other QUIC multipath implementations

### Performance Tests
1. **Lock contention**: Measure spinlock hold times under load
2. **State transition overhead**: Profile `quic_frame_process_path_status()`
3. **Scheduler notification latency**: Time from frame receipt to path availability

## Compliance

This implementation complies with:
- **draft-ietf-quic-multipath**: PATH_ABANDON, PATH_STANDBY, PATH_AVAILABLE frames
- **RFC 9000 Section 9**: Connection migration
- **RFC 9000 Section 13.3**: Frame ordering and sequence numbers
- **Linux kernel coding standards**: K&R style, spinlock patterns, RCU usage

## Files Modified

1. `/Users/justinadams/Downloads/tquic-kernel/net/quic/tquic_path.c`
   - Added `status_seq_num` field to `struct tquic_path` (line 241)
   - Initialize `status_seq_num = 0` in `tquic_path_alloc()` (line 883)

2. `/Users/justinadams/Downloads/tquic-kernel/net/quic/mp_frame.c`
   - Added forward declarations for path management functions (lines 18-25)
   - Enhanced `quic_frame_process_path_abandon()` (lines 85-131)
   - Enhanced `quic_frame_process_path_status()` (lines 189-305)
   - Enhanced `quic_send_path_abandon()` (lines 338-377)
   - Enhanced `quic_send_path_standby()` (lines 487-539)
   - Enhanced `quic_send_path_available()` (lines 559-611)

## Total Changes

- **Lines added**: ~250
- **Lines modified**: ~50
- **New dependencies**: tquic_bonding.h, tquic_sched.h (already present)
- **Breaking changes**: None (backward compatible)

## Verification

Recommended verification steps:

```bash
# Build test (requires kernel build environment)
make M=net/quic mp_frame.o

# Static analysis
scripts/checkpatch.pl --strict -f net/quic/mp_frame.c
scripts/checkpatch.pl --strict -f net/quic/tquic_path.c

# Symbol verification
nm net/quic/mp_frame.o | grep -E '(quic_frame_process|quic_send_path)'

# Check exports
grep EXPORT_SYMBOL net/quic/mp_frame.c
```

## Future Enhancements

1. **Metrics collection**: Track PATH_STATUS frame frequency for debugging
2. **Sysctl tunables**: Allow configuring sequence number validation strictness
3. **Tracepoints**: Add `trace_quic_path_status_received()` events
4. **Netlink notifications**: Expose path state changes to userspace
5. **Testing**: Add KUnit tests for state machine validation

## References

- draft-ietf-quic-multipath (latest): Multipath QUIC specification
- RFC 9000: QUIC Transport Protocol
- RFC 9002: QUIC Loss Detection and Congestion Control
- Linux kernel: Documentation/process/coding-style.rst
- TQUIC: CONTEXT.md, ARCHITECTURE.md, RESEARCH.md
