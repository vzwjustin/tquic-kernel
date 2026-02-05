# Configuration Guide

TQUIC exposes runtime configuration via sysctls under:

```
/proc/sys/net/tquic/
```

## Common Tunables

Examples (non‑exhaustive):

- `enabled` — master enable switch
- `cc_algorithm` — congestion control selection
- `default_bond_mode` — default WAN bonding mode
- `default_ack_delay_us` — default ACK delay
- `attack_threshold` — QUIC‑LEAK defense threshold
- `cert_verify_mode` — TLS cert verification mode
- `cert_verify_hostname` — hostname verification
- `ratelimit` — rate limiting parameters

## Example: Set Congestion Control

```bash
echo cubic > /proc/sys/net/tquic/cc_algorithm
```

## Example: Enable/Disable TQUIC

```bash
echo 1 > /proc/sys/net/tquic/enabled
echo 0 > /proc/sys/net/tquic/enabled
```

## Persistence

For persistent settings, add to `/etc/sysctl.conf` or a file in
`/etc/sysctl.d/`, e.g.:

```
net.tquic.enabled = 1
net.tquic.cc_algorithm = cubic
```

Then reload:

```bash
sysctl -p /etc/sysctl.conf
```

## Discover All Tunables

```bash
ls /proc/sys/net/tquic
```
