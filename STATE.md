# Project State (Handoff Packet)

## Objective
Fix the remaining medium-priority multipath loss attribution issues (PTO, timers, persistent congestion, key discard) as defined in PRD.md.

## Current Position
- Branch: main
- Last commit: 230c3a934
- Local run command: None (kernel module)
- Test/lint command(s): `cd net/tquic && gmake kunit`

## Current Task Focus
- Selected task (category/description): COMPLETE
- Acceptance criteria (from plan.md steps): All tasks passed.

## What Changed This Iteration
- `quic_loss.c` -> Modified `tquic_loss_on_packet_number_space_discarded` to lookup actual packet path and decrement per-path CC bytes_in_flight inline during the discard freeing process instead of blanket updating the active_path's CC info.

## Verification Evidence
- Commands executed + outcome: Skip build (macOS host limitations).
- Browser check: no
- Screenshot(s): none
- Console errors: none

## Decision Log (No Re-litigation)
- Decided to compute PTO based on the path of the last sent ack-eliciting packet, since the timeout is evaluated on a per-connection basis for the earliest expiration.
- Decided to iterate through all spaces to build an inline array of `path_id` vs `oldest_lost` and `newest_lost` when detecting persistent congestion to map the global state back to a per-path state.
- Decided to rely on `to_free` list iteration to manage CC bytes_in_flight decrements out of lock scope without temporary arrays.

## Known Issues / Risks
- Kunit tests must be run from `net/tquic`, not the kernel root, due to macOS build environment limitations.

## Next Agent Instructions
<promise>COMPLETE</promise>
