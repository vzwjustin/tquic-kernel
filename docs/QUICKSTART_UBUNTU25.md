# Quick Start (Ubuntu Server 25)

This guide covers a minimal path to build, load, and smoke-test TQUIC on an
Ubuntu Server 25 system.

## Pick A Build Mode

- **Out-of-tree module build (fastest)**: build `tquic.ko` against the running
  kernel’s headers. Works best when the running kernel exports the symbols TQUIC
  needs.
- **Full kernel build (most reliable)**: build and boot a kernel from this tree,
  then load the module.

If you are not sure, try the out-of-tree path first.

## Prereqs (Both Paths)

```bash
sudo apt update
sudo apt install -y \
  build-essential bc bison flex libssl-dev libelf-dev \
  dwarves pahole pkg-config python3 rsync git
```

Check your running kernel and headers:

```bash
uname -r
dpkg -l "linux-headers-$(uname -r)" | cat
```

If headers are missing:

```bash
sudo apt install -y "linux-headers-$(uname -r)"
```

Note: if Secure Boot is enabled, unsigned modules may fail to load until you
disable Secure Boot or sign the modules.

## Option A: Out-of-Tree Module Build (Against Running Kernel)

From this repo on the Ubuntu box:

```bash
cd /path/to/tquic-kernel/net/tquic
make -f Makefile.oot -j"$(nproc)"
```

Load the module directly (no install step):

```bash
sudo insmod ./tquic.ko
```

If that succeeds, run the smoke test:

```bash
sudo /path/to/tquic-kernel/tools/tquic/smoke/tquic-smoke.sh
```

To uninstall (for the current boot):

```bash
sudo rmmod tquic || true
```

If `insmod` fails with missing symbols, you likely need the full-kernel path.

## Option B: Full Kernel Build (Recommended For Deep Testing)

Start from the Ubuntu kernel config you are currently running:

```bash
cd /path/to/tquic-kernel
cp -v /boot/config-$(uname -r) .config
yes "" | make olddefconfig
```

Enable TQUIC:

```bash
make menuconfig
```

Then ensure these are enabled (names may appear under Networking):

- `CONFIG_IP_QUIC`
- `CONFIG_TQUIC`

Build Debian packages (easiest install path on Ubuntu):

```bash
make -j"$(nproc)" bindeb-pkg LOCALVERSION=-tquic
```

Install the resulting packages (one directory above the repo):

```bash
cd ..
sudo dpkg -i ./*.deb
sudo update-grub
sudo reboot
```

After rebooting into the new kernel:

```bash
sudo modprobe tquic
sudo /path/to/tquic-kernel/tools/tquic/smoke/tquic-smoke.sh
```

## Notes

- `IPPROTO_TQUIC` is `253` in this tree.
- See `docs/TROUBLESHOOTING.md` for common failure modes.
