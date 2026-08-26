# M1 Host-Build Checkpoint

Status: **verified host build complete**

This document records reproducible, CI-verified AARCH64 EFI applications produced for the IzzOS M1 non-destructive diagnostic milestone.

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

## First EFI artifact

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

## Hardened M1 payload checkpoint

Before first physical-device execution, the diagnostic runtime was hardened without expanding its device-write capabilities. The changes add:

- bounded retry when the UEFI memory map grows during `GetMemoryMap()` capture;
- descriptor-size validation before allocation and descriptor walking;
- overflow-safe descriptor slack arithmetic;
- final memory-map geometry validation;
- guarded console-input protocol access;
- bounded key-read retries with safe return when console input is unavailable.

Verified hardened build:

- source head: `21d7af1b1e0b644907bb37fa0bce109b8060ed04`
- GitHub PR test merge revision recorded by `BUILD_INFO.txt`: `da3322d4390d6ac5d9e53f04fa2e40c85e497abd`
- pinned EDK2 revision: `d98a39d4ceeb7204b33fc330fdfee8cdb5ddbb43`
- GitHub Actions run: `32598598178` (run #139)
- artifact ID: `9482256396`
- artifact name: `OvaltineDiag-AARCH64`
- artifact archive digest: `sha256:9605c4f5bf18f37f0aa085abb9023358417169054b99581d3425614d3e21723f`
- EFI file: `OvaltineDiag.efi`
- EFI size: `24576` bytes
- EFI SHA256: `1459a4e3862ab56091dfc6ec2e53c62ac1bb448abd94dd28bf552ece281e007f`
- file classification: `PE32+ executable for EFI (application), ARM64, 3 sections`

The downloaded artifact was checked independently after CI completed. Its SHA256 matched both `BUILD_INFO.txt` and `SHA256SUMS`. The larger executable is expected because of the added runtime validation/retry paths.

The hardened payload remains read-only: CI passed the M1 safety gate, EFI identity verification, route-neutral staging checks, and all host-side evidence/readiness gates in run #139.

## CI gates passed

Current CI includes:

1. shell syntax validation;
2. device capability analyzer tests;
3. diagnostic-output analyzer tests;
4. stock boot metadata tests;
5. stock-image provenance and set-consistency tests;
6. M2 evidence, recovery, authorization, tamper and freshness tests;
7. M2 readiness report tests;
8. M1 read-only source/INF safety gate;
9. AArch64 EDK2 dependency installation;
10. OvaltineDiag build;
11. OvaltineDiag artifact verification;
12. route-neutral M2 staging verification;
13. artifact upload.

The final AARCH64 link requires EDK2's official `CompilerIntrinsicsLib` NULL library instance. Current EDK2 explicitly uses this on AARCH64 because compilers may emit freestanding intrinsic symbols such as `memcpy` and `memset`.

## What this proves

These checkpoints prove that the M1 diagnostic source can be built reproducibly into verified ARM64 UEFI applications using the pinned host toolchain and EDK2 revision, and that the current hardened payload passes the host-side safety and readiness regression suite.

They do **not** prove that the OnePlus 10T firmware can execute the application yet. On-device execution remains gated on exact-device read-only inspection and selection of a validated temporary launch/chain-load route.

## Safety state

- no UFS writes
- no partition formatting or repartitioning
- no persistent ABL/XBL/UEFI replacement
- no guessed framebuffer/MMIO activation
- no `ExitBootServices()` in the M1 diagnostic application

M1 remains active until the hardened diagnostic is safely executed on the exact target device and runtime firmware information is captured.
