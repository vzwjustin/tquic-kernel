# Troubleshooting

## Module Fails to Load: Unknown Symbol

Symptoms:
- `modprobe tquic` fails
- `dmesg` shows `Unknown symbol ...`

Fix:
- Ensure the running kernel matches the built modules.
- Rebuild and reinstall modules for the current kernel:

```bash
cd /usr/src/linux-6.12.63
make -j"$(nproc)" modules
make modules_install
depmod -a 6.12.63
```

## `Attempt to override permanent protocol 253`

This happens if you unload/reload the module in a running kernel.
It should not appear after a clean reboot with auto‑load enabled.

## Sysctl Directory Missing

If `/proc/sys/net/tquic` is missing:

```bash
modprobe tquic
```

If still missing, check build config for `CONFIG_TQUIC=y`.

## Handshake Symbols Missing

If `tls_client_hello_x509` or `tls_server_hello_x509` are missing:

- Ensure `CONFIG_NET_HANDSHAKE=y`
- Ensure `CONFIG_SUNRPC=y` (often enabled by `CONFIG_NFS_FS=y`)

## UDP Tunnel Symbols Missing

If `udp_sock_create4/6` or `udp_tunnel_xmit_skb` are missing:

- Ensure `CONFIG_NET_UDP_TUNNEL=y`
- Ensure `CONFIG_IP6_UDP_TUNNEL=y`

## NAPI / IO_URING Build Errors

These features are currently disabled on Debian 6.12 until API ports
are completed. See `TQUIC_PORTING_GAPS.md` for details.
