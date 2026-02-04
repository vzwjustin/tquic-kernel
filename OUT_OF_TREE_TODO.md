# Out-of-Tree Build: Remaining Fixes

This branch builds much further, but the out-of-tree module still fails at
`modpost` with undefined symbols. Below is the current known gap list and the
preferred fixes (either re-enable objects or add minimal stubs).

## Current modpost undefined symbols

- `tquic_udp_encap_init`
- `tquic_udp_send`
- `tquic_scheduler_init`
- `tquic_scheduler_exit`
- `tquic_mp_sched_find`
- `tquic_pm_get_path`
- `tquic_pm_get_active_paths`
- `tquic_crypto_derive_initial_secrets`
- `tquic_path_state_names`

## Likely sources and recommended resolution

1. UDP offload helpers
   - Symbols: `tquic_udp_encap_init`, `tquic_udp_send`
   - Source: `net/tquic/quic_offload.c`
   - Fix: Either compile `quic_offload.c` in out-of-tree or add lightweight
     stubs in `net/tquic/out_of_tree_stubs.c` (return `-EOPNOTSUPP` and drop skb).

2. Multipath scheduler core
   - Symbols: `tquic_scheduler_init`, `tquic_scheduler_exit`, `tquic_mp_sched_find`
   - Source: `net/tquic/multipath/tquic_scheduler.c`
   - Fix: Re-enable `tquic_scheduler.c` in the out-of-tree `tquic-y` list
     or stub these three symbols (init returns 0, exit no-op, find returns NULL).

3. PM APIs expected by bonding/mp_frame
   - Symbols: `tquic_pm_get_path`, `tquic_pm_get_active_paths`
   - Expected by:
     - `net/tquic/core/mp_frame.c`
     - `net/tquic/bond/tquic_bonding.c`
   - Fix options:
     - Implement simple helpers that walk `conn->paths` via `tquic_conn_get_path`
       or iterate the list under RCU and return ACTIVE/VALIDATED paths.
     - Or refactor bonding to use `tquic_conn_get_path` directly.

4. Initial secrets derive API mismatch
   - Symbol: `tquic_crypto_derive_initial_secrets`
   - Current implementation is named `tquic_crypto_derive_init_secrets`
     in `net/tquic/core/quic_crypto.c`.
   - Fix: add a small wrapper with the correct name that calls
     `tquic_crypto_derive_init_secrets()` and export it.

5. Path state name table
   - Symbol: `tquic_path_state_names`
   - A static array exists in `net/tquic/diag/path_metrics.c`, but is not exported.
   - Fix: add a global `const char *tquic_path_state_names[]` (aligned with
     `enum tquic_path_state` in `include/net/tquic.h`) and export it.

## Notes

- `net/tquic/out_of_tree_stubs.c` already provides stubs for a few other
  missing symbols and is compiled when `TQUIC_OUT_OF_TREE` is defined.
- This branch currently consolidates many objects into `tquic.ko` to avoid
  circular module dependencies; any new object added should be placed in both
  `net/tquic/Kbuild` and `net/tquic/Makefile` `tquic-y` lists.

