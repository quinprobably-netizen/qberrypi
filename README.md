# qberrypi

A single-purpose operating system for the Raspberry Pi 3 B+ that turns the
board into a network-wide DNS ad blocker. The Linux kernel is stock;
everything above it is one static Rust executable: init, Wi-Fi supplicant,
network setup, DNS server and status page. No shell, no other programs.

**Status: design.** Nothing boots yet. The design is in
[`docs/superpowers/specs/2026-11-10-qberrypi-design.md`](docs/superpowers/specs/2026-11-10-qberrypi-design.md).

## Licence

MIT. See `LICENSE`.
