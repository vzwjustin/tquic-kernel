# Out-of-Tree Build: Remaining Fixes

## Status: RESOLVED

All previously undefined symbols have been fixed as of this commit.

## Previously undefined symbols (now fixed)

- `tquic_udp_encap_init` - **FIXED**: Added `quic_offload.o` to build
- `tquic_udp_send` - **FIXED**: Added `quic_offload.o` to build
- `tquic_scheduler_init` - **FIXED**: Added `multipath/tquic_scheduler.o` to build
- `tquic_scheduler_exit` - **FIXED**: Added `multipath/tquic_scheduler.o` to build
- `tquic_mp_sched_find` - **FIXED**: Added `multipath/tquic_scheduler.o` to build
- `tquic_pm_get_path` - **FIXED**: Added stub in `out_of_tree_stubs.c`
- `tquic_pm_get_active_paths` - **FIXED**: Added stub in `out_of_tree_stubs.c`
- `tquic_crypto_derive_initial_secrets` - **FIXED**: Added wrapper in `out_of_tree_stubs.c`
- `tquic_path_state_names` - **FIXED**: Added definition in `out_of_tree_stubs.c`

## Resolution details

### 1. UDP offload helpers
- Added `quic_offload.o` to both `net/tquic/Kbuild` and `net/tquic/Makefile`
- The file provides `tquic_udp_encap_init` and `tquic_udp_send` implementations

### 2. Multipath scheduler core
- Added `multipath/tquic_scheduler.o` to both `net/tquic/Kbuild` and `net/tquic/Makefile`
- Provides `tquic_scheduler_init`, `tquic_scheduler_exit`, and `tquic_mp_sched_find`

### 3. PM APIs for bonding/mp_frame
- Added stubs in `out_of_tree_stubs.c`:
  - `tquic_pm_get_path()` returns NULL
  - `tquic_pm_get_active_paths()` returns 0
- These are minimal stubs; full implementation requires real path manager integration

### 4. Crypto API name mismatch
- Added wrapper `tquic_crypto_derive_initial_secrets()` that calls
  `tquic_crypto_derive_init_secrets()` (the actual implementation)

### 5. Path state name table
- Added global `tquic_path_state_names[]` array in `out_of_tree_stubs.c`
- Matches the `enum tquic_path_state` in `include/net/tquic.h`

## Notes

- `net/tquic/out_of_tree_stubs.c` is compiled when `TQUIC_OUT_OF_TREE` is defined
- All objects are consolidated into single `tquic.ko` to avoid circular dependencies
- New objects should be added to both `net/tquic/Kbuild` and `net/tquic/Makefile`

## Build instructions

```bash
cd net/tquic
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```
