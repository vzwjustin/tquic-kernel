# TQUIC Security Findings Summary

| ID | Application / Component | Severity | Location | Description |
| :--- | :--- | :--- | :--- | :--- |
| **APP-1** | tquic-manager | **CRITICAL** | `backend/app.py:120` | **Command Injection**: `sysctl` command constructed with unsanitized user input allows root RCE. |
| **NL-1** | net/tquic | **CRITICAL** | `net/tquic/tquic_netlink.c:746` | **Use-After-Free**: Path object freed via `tquic_nl_path_put` but remains in `conn->paths` list. |
| **C-1** | net/tquic | **CRITICAL** | `net/tquic/core/connection.c:1283` | **Time-Side-Channel**: Non-constant time comparison of Retry Token HMACs. |
| **C-2** | net/tquic | **CRITICAL** | `net/tquic/tquic_input.c:398` | **Race Condition**: `tquic_handle_stateless_reset` bypasses state machine, risking UAF. |
| **C-3** | net/tquic | **CRITICAL** | `net/tquic/tquic_input.c:757` | **DoS Vector**: ECN Validation treats all CE marks as new, allowing amplification attacks. |
| **C-5** | net/tquic | **CRITICAL** | `net/tquic/tquic_input.c:715` | **RFC Violation**: Hardcoded ACK Delay Exponent (should be negotiated). |
| **H-1** | net/tquic | **HIGH** | `net/tquic/tquic_input.c:737` | **Congestion Control**: `bytes_acked` calculation oversimplified (assumes 1200 MTU), allowing window inflation. |
| **H-2** | net/tquic | **HIGH** | `net/tquic/tquic_input.c:1116` | **RFC Violation**: Missing validation for `retire_prior_to` in NEW_CONNECTION_ID frames. |
| **H-5** | net/tquic | **HIGH** | `net/tquic/core/connection.c:956` | **Ossification Risk**: Hardcoded Version Negotiation packet format (greasing missing). |
| **H-7** | net/tquic | **HIGH** | `net/tquic/core/connection.c:1356` | **Interoperability**: Hardcoded Retry Integrity Keys (only valid for v1, breaks v2). |
| **H-9** | net/tquic | **HIGH** | `net/tquic/core/stream.c:177` | **Integer Overflow**: Stream `final_size` initialized to `-1` (U64_MAX), exceeding flow control limits. |
| **M-6** | net/tquic | **MEDIUM** | `net/tquic/tquic_input.c:986` | **Consistency Check**: `FIN` flag not checked against previously declared `final_size`. |
