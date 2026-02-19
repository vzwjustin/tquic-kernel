# PRD: TQUIC Multipath Loss Timer Attribution Fixes

## Objective
Fix the remaining medium-priority multipath loss attribution issues identified in the codebase audit. Currently, several timer and congestion calculations inaccurately use the global active path rather than the specific path associated with the packet or event.

## Scope
Modify `net/tquic/core/quic_loss.c` to ensure the following functions use per-path attributes:
1. `tquic_loss_get_pto_time_space`
2. `tquic_set_loss_detection_timer`
3. `tquic_loss_discard_pn_space_keys`
4. `tquic_loss_persistent_congestion`

## Constraints
- Safe concurrent access when reading path state.
- Fallback safely to the active path if a specific path context is unavailable or invalid.
- Maintain compatibility with single-path environments.
- Verify changes using existing tests in the `net/tquic` directory.
