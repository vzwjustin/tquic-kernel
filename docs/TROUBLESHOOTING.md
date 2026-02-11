# Troubleshooting

## Module Fails to Load: Unknown Symbol

Symptoms:
- `modprobe tquic` fails
- `dmesg` shows `Unknown symbol ...`

Fix:
- Ensure the running kernel matches the built modules.
- Rebuild and reinstall modules for the current kernel:

```bash
cd /path/to/kernel-source
make -j"$(nproc)" modules
make modules_install
depmod -a $(uname -r)
```

## `Attempt to override permanent protocol 253`

This happens if you unload/reload the module in a running kernel.
It should not appear after a clean reboot with auto-load enabled.

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

## NAPI / IO_URING / AF_XDP Build Errors

These features are conditionally compiled behind Kconfig options:
- `CONFIG_TQUIC_IO_URING` - io_uring integration
- `CONFIG_TQUIC_NAPI` - NAPI polling
- `CONFIG_TQUIC_AF_XDP` - AF_XDP fast path

If build errors occur, disable the feature in your `.config` or ensure your kernel headers support the required APIs. See [PORTING_GUIDE.md](PORTING_GUIDE.md) for kernel version compatibility details.
