# tquic-kernel

Minimal Linux kernel for routers, VPS, and server deployments with **TQUIC WAN bonding**.

This is a stripped-down Linux kernel (~690MB vs ~1.6GB full source) focused on networking and routing. Desktop components have been removed.

## What's Included

### Core
- x86_64 and arm64 architectures
- Full kernel core (scheduler, memory, IPC, namespaces, cgroups)
- BPF/eBPF subsystem

### Networking (Complete)
- IPv4/IPv6 advanced routing, multipath, policy routing, VRF
- Netfilter (nftables + iptables), NAT, connection tracking, IPVS
- QoS/tc schedulers (HTB, FQ, CAKE, fq_codel, etc.)
- MPTCP, WireGuard, L2TP, PPP, MPLS
- Tunnels: GRE, IPIP, VXLAN, GENEVE, SIT
- eBPF/XDP packet processing
- **TQUIC WAN bonding over QUIC**

### TQUIC Features
- Multipath QUIC for WAN bonding
- Path manager with intelligent selection
- Schedulers: round-robin, min-RTT, weighted, BLEST, ECF
- Congestion control: CUBIC, BBR, COPA, Westwood, coupled (OLIA/BALIA)
- BPF struct_ops for custom schedulers
- Netfilter integration
- sock_diag support (`ss` command)

### Drivers
- Virtio (VPS/cloud)
- Server NICs: Intel, Mellanox, Broadcom, Realtek
- Cloud: AWS ENA, Google GVE, Azure MANA
- WiFi: Intel, Atheros, Realtek, MediaTek
- LTE/5G: USB modems (QMI, MBIM), WWAN
- Storage: NVMe, SATA, SCSI, virtio-blk
- Filesystems: ext4, XFS, btrfs, NFS

## What's Removed

- Graphics/DRM/GPU drivers
- Sound/ALSA
- Bluetooth
- Media/V4L
- HID (joysticks, touchscreens, tablets)
- Desktop platform drivers (Dell, HP, Lenovo, Surface, Chrome)
- Legacy: ISDN, Firewire, Parport, PCMCIA
- Infiniband (add back if needed)
- Most non-x86/arm64 architectures
- Documentation, samples, rust

## Build

```bash
# Use provided router config
cp configs/router_minimal.config .config
make olddefconfig

# Or start fresh
make defconfig
make menuconfig  # Enable TQUIC under Networking

# Build
make -j$(nproc)

# Install
sudo make modules_install
sudo make install
```

## Size

| Version | Size |
|---------|------|
| Full Linux source | ~1.6 GB |
| tquic-kernel | ~690 MB |
| Reduction | ~57% |

## License

GPL-2.0 (Linux kernel)
