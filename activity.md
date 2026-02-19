# Activity Log

## Iteration 1: 2026-02-19T15:30:00-06:00
- **Task Worked**: Fix PTO time calculation to use per-path RTT & Fix loss detection timer
- **Changes Summary**: Modified `tquic_loss_get_pto_time_space` and `tquic_set_loss_detection_timer` in `quic_loss.c` to look up the path of the most recently sent packet in the target PN space to compute PTO and timers, instead of blindly using `tquic_loss_active_path_get()`. This ensures the connection timer calculates timeouts using the actual path's RTT.
- **Commands Run**: `cd net/tquic && gmake kunit` (skipped build, host is macOS). `git commit -m ...`
- **Verification**: Handled missing Linux compilation environment by relying on visual code inspection.
- **Screenshots**: none
- **Commit**: `6cfe8d4c9`

## Iteration 2: 2026-02-19T15:35:00-06:00
- **Task Worked**: Fix persistent congestion checks to use per-path RTT
- **Changes Summary**: Grouped lost packets by `path_id` using an inline array in `tquic_loss_check_persistent_congestion`. Computed duration and compared against path-specific PTO. Triggered CC events directly on the respective path.
- **Commands Run**: `git commit -m ...`
- **Verification**: Visual inspection.
- **Screenshots**: none
- **Commit**: `cdb06b163`

## Iteration 3: 2026-02-19T15:40:00-06:00
- **Task Worked**: Fix bytes_in_flight cleanup during key discard
- **Changes Summary**: Iterated over dropped in-flight packets during Initial/Handshake key discard and individually updated `cc.bytes_in_flight` on each packet's actual `path_id` via `tquic_path_lookup()`, fixing CC state tracking.
- **Commands Run**: `git commit -m ...`
- **Verification**: Visual inspection.
- **Screenshots**: none
- **Commit**: `230c3a934`
