# M1 Host-Build Checkpoint

Status: **verified host build complete**

This document records the first reproducible, CI-verified AARCH64 EFI application produced for the IzzOS M1 non-destructive diagnostic milestone.

## First verified build

- IzzOS branch: `izzos-woa-foundation`
- Source head: `99847bd3d87c1405facc0ccab917c8b8d87366fe`
- GitHub PR test merge revision: `f7e0e9723e9e8d2272519b28047ce5b062152dea`
- Pinned EDK2 revision: `d98a39d4ceeb7204b33fc330fdfee8cdb5ddbb43`
- GitHub Actions run: `32594624635` (`UEFI Ovaltine Diagnostic`, run #31)
- Artifact ID: `9481273713`
- Artifact name: `OvaltineDiag-AARCH64`
- Artifact archive digest: `sha256:c2e4919792e7e8f8f53023583e2a5d171866de3d82c792d1801981bd47a59ea2`

GitHub Actions checks out the PR test merge revision for the pull-request run, while the artifact metadata records the source branch head separately. Both are recorded above to make the build provenance explicit.

## EFI artifact

- File: `OvaltineDiag.efi`
- Size: `20480` bytes
- SHA256: `894e008d99464b6c3f88e2ee6debe6edce75dea49fea62a10645f3bf466b2363`
- File classification: `PE32+ executable for EFI (application), ARM64, 3 sections`

The SHA256 stored in `BUILD_INFO.txt`, the generated `SHA256SUMS`, and an independent checksum of the downloaded CI artifact all matched exactly.

## Reproducibility confirmation

The build script was subsequently optimized to initialize only the third-party submodules required by this minimal target: BaseTools Brotli and MdePkg MipiSysT.

The optimized pipeline passed all gates again:

- source head: `5567fb2ed0011b3c781bb153b843bc282d0e8f32`
- GitHub Actions run: `32595051840` (run #36)
- artifact ID: `9481336770`
- artifact archive digest: `sha256:c77b1632d17a1fd79f00a7ba89e74f6cc1aefa891ecc9c00f857b6c35d43e292`
- EFI size: `20480` bytes
- EFI SHA256: `894e008d99464b6c3f88e2ee6debe6edce75dea49fea62a10645f3bf466b2363`
- file classification: `PE32+ executable for EFI (application), ARM64, 3 sections`

The `.efi` hash is byte-for-byte identical to the first verified build. The ZIP artifact digest differs as expected because `BUILD_INFO.txt` records a different CI checkout revision, but the executable itself is reproducible.

## CI gates passed

1. Checkout IzzOS — PASS
2. M1 read-only safety gate — PASS
3. AArch64 EDK2 dependency installation — PASS
4. OvaltineDiag build — PASS
5. OvaltineDiag artifact verification — PASS
6. Artifact upload — PASS

The final AARCH64 link required EDK2's official `CompilerIntrinsicsLib` NULL library instance. Current EDK2 explicitly uses this on AARCH64 because compilers may emit freestanding intrinsic symbols such as `memcpy` and `memset`.

## What this proves

This checkpoint proves that the M1 diagnostic source can be built reproducibly into a verified ARM64 UEFI application using the pinned host toolchain and EDK2 revision.

It does **not** prove that the OnePlus 10T firmware can execute the application yet. On-device execution remains gated on exact-device read-only inspection and selection of a validated temporary launch/chain-load route.

## Safety state

- no UFS writes
- no partition formatting or repartitioning
- no persistent ABL/XBL/UEFI replacement
- no guessed framebuffer/MMIO activation
- no `ExitBootServices()` in the M1 diagnostic application

M1 remains active until the diagnostic is safely executed on the exact target device and runtime firmware information is captured.
