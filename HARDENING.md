# v0.4 Alpha hardening boundary

Chromaplex Coding Agent and ChromaLinux are separate products. This repository ships an optional ChromaLinux/ISO hardening pack, but does not make ICP a dependency and does not claim that a generic Linux host is immutable.

## Implemented in Coding Agent

- strict memory-safety gate for native C and managed-language FFI escapes;
- hardened Safe-C compiler flags and GCC analyzer gate;
- WebAssembly/WAT secure build target;
- structural ELF, PE and Wasm validation after compilation;
- executable packer signatures (including UPX) blocked;
- executable entropy measured and high entropy requires explicit policy review;
- mandatory `chromaplex-capabilities.json` in workspaces;
- network-off and host-home-hidden bubblewrap runtime by default;
- capability mismatch blocks execution before start;
- source/binary ClamAV gates, SHA-256 sealing and security manifest remain mandatory.

## ChromaLinux/ISO hardening assets

`python -m chromaplex_agent.hardening install-assets <rootfs>` installs:

- `/etc/apparmor.d/chromaplex-generated`
- `/etc/default/grub.d/60-chromaplex-lockdown.cfg`

The GRUB fragment requests `lockdown=integrity`. Linux documents this mode as disabling kernel features that permit user space to modify the running kernel. Actual enforcement must be verified on the built target kernel/boot path.

`python -m chromaplex_agent.hardening format-verity rootfs.img rootfs.hash` uses `veritysetup` to create a SHA-256 dm-verity hash tree and emits a `.verity.json` root-hash manifest. dm-verity is read-only integrity verification; boot-time mapping still has to be wired to the concrete ChromaLinux image layout by the ISO builder and tested in a real VM/device.

Internet Computer integration is deliberately not part of this hardening core. ChromaLinux may later use ICP for selected persistent data, but generic ChromaPress and Coding Agent remain independent.

## Raspberry Pi deployment profiles

`chromaplex-hardening generate-rpi-apparmor <binary> <workspace> <chromaplex-capabilities.json> <output-profile>` generates a conservative AppArmor profile from an approved Raspberry Pi capability manifest. Network and process execution are only emitted when explicitly declared; arbitrary home/system write access is not added.
