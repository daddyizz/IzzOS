# Qualcomm SM8475 evidence boundary for IzzOS

This directory is the source-backed staging area for the OnePlus 10T / `ovaltine` standalone EDK2 bring-up.

## Platform identity

- Qualcomm platform family: SM8475 / Cape
- OnePlus target: OnePlus 10T 5G (`ovaltine`)
- Exact physical test device: CPH2413
- Fastboot product observation: `taro` (platform-level only; never use it as the sole device identity)

## Source-backed hardware observations

The OnePlus/Qualcomm device-tree sources used by the project support the following observations for Cape-class SM8475 bring-up:

- SoC compatible family: `qcom,cape`
- Qualcomm MSM ID observed for Cape: `530` / `0x10000`
- debug UART path references the QUP UART at `0x0099c000`
- UFS PHY block: `0x01d80000`, size `0x2000`
- UFS host block: `0x01d84000`, size `0x3000`
- UFS ICE block: `0x01d88000`, size `0x8000`
- UFS ICE HWKM block: `0x01d90000`, size `0x9000`
- UFS reference clock: 19.2 MHz
- a small SRAM observation exists at `0x17d09400`, size `0x400`

These addresses are recorded as research observations only. They do **not** authorize programming those blocks from firmware.

## Deliberately unresolved before standalone firmware layout

The following must not be guessed or copied from another Qualcomm target:

1. DDR base and usable size for the exact OnePlus 10T boot environment.
2. Reserved-memory exclusions that the standalone firmware must never overwrite.
3. Firmware load address / FD placement that is proven not to overlap the bootloader, DTB, framebuffer, carve-outs, modem/DSP regions, or other secure/reserved ranges.
4. Runtime framebuffer base/size. The M1 diagnostic design must discover GOP/framebuffer state at runtime rather than hard-code an address.
5. GIC/timer/platform-init assumptions required for a truly standalone EDK2 image.
6. Any UFS/ICE/HWKM initialization sequence. Internal-storage writes remain forbidden during M1.

## Build policy

`Ovaltine.dsc` and `Ovaltine.fdf` must not be promoted as launchable standalone firmware merely because they compile. A launch candidate requires independent evidence for the memory placement and entry assumptions above, plus the existing recovery, exact-firmware, temporary-route, and host-toolchain gates.

No source file under this directory may introduce guessed MMIO writes or a guessed DDR/FD base as if it were validated hardware data.
