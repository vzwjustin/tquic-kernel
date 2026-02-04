# Out-of-Tree Build: Remaining Fixes

## Status: RESOLVED

All previously undefined symbols have been fixed with real implementations.

## Previously undefined symbols (now fixed)

- `tquic_udp_encap_init` - **FIXED**: Added `quic_offload.o` to build
- `tquic_udp_send` - **FIXED**: Added `quic_offload.o` to build
- `tquic_scheduler_init` - **FIXED**: Added `multipath/tquic_scheduler.o` to build
- `tquic_scheduler_exit` - **FIXED**: Added `multipath/tquic_scheduler.o` to build
- `tquic_mp_sched_find` - **FIXED**: Added `multipath/tquic_scheduler.o` to build
- `tquic_pm_get_path` - **FIXED**: Real implementation in `pm/path_manager.c`
- `tquic_pm_get_active_paths` - **FIXED**: Real implementation in `pm/path_manager.c`
- `tquic_crypto_derive_initial_secrets` - **FIXED**: Renamed function in `core/quic_crypto.c`
- `tquic_path_state_names` - **FIXED**: Exported from `pm/path_manager.c`

## Resolution details

### 1. UDP offload helpers
- Added `quic_offload.o` to both `net/tquic/Kbuild` and `net/tquic/Makefile`
- The file provides `tquic_udp_encap_init` and `tquic_udp_send` implementations

### 2. Multipath scheduler core
- Added `multipath/tquic_scheduler.o` to both `net/tquic/Kbuild` and `net/tquic/Makefile`
- Provides `tquic_scheduler_init`, `tquic_scheduler_exit`, and `tquic_mp_sched_find`

### 3. PM APIs for bonding/mp_frame
- Implemented real functions in `pm/path_manager.c`:
  - `tquic_pm_get_path()` - looks up path by ID via connection's path list
  - `tquic_pm_get_active_paths()` - returns array of ACTIVE/VALIDATED paths
- Declarations added to `include/net/tquic_pm.h`

### 4. Crypto API name fix
- Renamed `tquic_crypto_derive_init_secrets()` to `tquic_crypto_derive_initial_secrets()`
  in `core/quic_crypto.c` to match the declared API
- Updated declaration in `core/tquic_crypto.h`

### 5. Path state name table
- Added global `tquic_path_state_names[]` array in `pm/path_manager.c`
- Matches the `enum tquic_path_state` in `include/net/tquic.h`
- Declaration added to `include/net/tquic_pm.h`

## Notes

- `net/tquic/out_of_tree_stubs.c` provides minimal stubs only for symbols from
  subsystems not included in out-of-tree builds (tracing, module lifecycle)
- All objects are consolidated into single `tquic.ko` to avoid circular dependencies
- New objects should be added to both `net/tquic/Kbuild` and `net/tquic/Makefile`

## Build instructions

```bash
cd net/tquic
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```
