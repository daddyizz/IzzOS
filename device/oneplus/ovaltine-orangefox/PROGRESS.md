# OrangeFox ovaltine progress

Last updated: 2026-09-01 UTC

## Target

- OnePlus 10T `CPH2413` / `ovaltine` / Qualcomm `taro`
- Board/product: `OP5552L1`
- Firmware: OxygenOS `15.0.0.1901(EX01)`
- OrangeFox: official experimental `fox_14.1`
- Build target: `twrp_ovaltine-ap2a-eng`, then `adbd recoveryimage`

## Durable checkpoints

- GitHub repository: `daddyizz/IzzOS`
- Branch: `orangefox-ovaltine-bringup`
- Device-tree path: `device/oneplus/ovaltine-orangefox`
- Block 2 implementation commit: `607f2b94434562626700882938d3ebcca5451d12`
- Stock-source archive: `OrangeFox-ovaltine-source-39ac2c4.zip`
- Stock prebuilts are intentionally excluded from Git.

## Verified stock inputs

| Input | Size | SHA-256 |
| --- | ---: | --- |
| `prebuilt/kernel` | 48,113,892 | `f5137d9b953455882ff4657f33c9966d173ab41d155f822c25434f35829f4bcb` |
| `prebuilt/dtbo.img` | 25,165,824 | `2f1efc6328c4a87923489f453c5acc455d3713694178cd2631d022924c106313` |
| `prebuilt/dtbs/stock.dtb` | 1,434,126 | `0fa5416a6b417f25007f62b75bcc012a76596b1c01d7af783fb090940abce5dd` |

## Completed

- Stock Android boot/vendor-boot v4 images and AVB/DTBO were validated.
- Stock kernel, DTB, DTBO and OxygenOS recovery fstab were imported.
- Device tree validation passes.
- QPR3 source pairing was proven by a successful
  `lunch twrp_ovaltine-ap2a-eng` using build ID `AP2A.240905.003`.
- Official OrangeFox recovery core, vendor tree, `se_omapi`, and upstream
  OrangeFox build/update-engine patches were applied in the disposable build
  workspace.
- Soong bootstrap compiled fully and reached Android.bp analysis.
- Safety audit removed the dangerous `oplusreserve2 -> /cache` mapping,
  restored `/persist`, completed the A/B partition list, and added validation
  assertions for these invariants.
- Block 2 produced `scripts/bootstrap-constrained.sh`, a reproducible minimal
  source bootstrap for the 14 GiB cgroup. It installs the pinned QPR3 local
  manifest before sync, overlays the three official OrangeFox repositories,
  sparsely checks out Linux-only Clang `r510928`, SDK 34 and misc prebuilts,
  while retaining uncertain dependency graphs until Soong proves they are safe
  to remove.
- Both constrained patches were generated against real
  `android-14.0.0_r67`/TeamWin checkouts and passed apply plus reverse-apply
  smoke tests. Tree validation and shell syntax validation pass.

## Last build result

### Block 4 constrained compile attempt (2026-09-07)

The complete QPR3/OrangeFox graph was exercised in the restored source tree.
Soong bootstrap and legacy Make parsing passed, and Ninja entered the real
recovery build (`22,094` actions). The host then ran out of resources: free
disk fell below 1 GiB during host/libc++ output, and a later graph regeneration
was killed by the 15.6 GiB cgroup memory limit. No `recovery.img` was produced.

The build-specific fixes are now part of the reproducible flow:

1. apply `patches/constrained/soong-path-no-socket.patch`;
2. set `DROP_MEDIAPROVIDER=1` and retain an empty MediaProvider sentinel after
   roomservice/lunch;
3. use a host with at least 32 GiB free disk and 24 GiB RAM (16 GiB is the
   documented minimum, but this graph was killed at 15.6 GiB);
4. run `GOMEMLIMIT=10GiB GOMAXPROCS=2 m -j1 recoveryimage`.

The successful boundary is the generated Ninja graph plus legacy Make rules;
the next attempt should resume from that checkpoint on a larger runner rather
than resyncing source.

The disposable 18 GiB source workspace was automatically cleared between
sessions. Before cleanup, Soong Android.bp analysis was killed by the 14 GiB
cgroup memory limit. This was not a device-tree compile error.

The next local build must set `GOMAXPROCS=2`, `GOMEMLIMIT=10GiB` and compile
only `m -j1 recoveryimage`. The build script now supplies these safe defaults.

Resolved before the memory stop:

1. sandbox Unix socket failure via lite PATH fallback;
2. missing Clang Soong plugin;
3. QPR3 compiler corrected to `clang-r510928`;
4. constrained SDK API/extension metadata;
5. omitted macOS/Windows prebuilt references;
6. unreleased MediaProvider API tracking disabled for recovery-only graph.

## Five-hour work blocks

1. **Checkpoint inputs** — restore stock archive, validate checksums, sync this
   progress record to Git.
2. **Minimum build graph — completed** — constrained bootstrap, sparse host
   prebuilts and recorded source patches are ready.
3. **Build host — next** — use a reproducible host or CI path that can securely obtain
   the ignored stock prebuilts.
4. **Compile** — build `adbd recoveryimage`; commit fixes after each stable
   milestone.
5. **Verify** — require image size <= 104,857,600 bytes, valid Android header,
   OrangeFox ramdisk markers and SHA-256.
6. **Deliver** — save the verified image and logs, then document temporary
   `fastboot boot` testing. Do not flash permanently before the boot test.

## Resume rule

At the end of every block, update this file and push the branch. Never repeat a
completed sync/audit unless its recorded input changed. `recovery.img` must be
taken from `out/target/product/ovaltine/recovery.img`; it is not contained in a
device-tree/source ZIP.

## CI blocker

GitHub discovers workflows only under the repository-root `.github/workflows`
directory. The workflow stored inside this device-tree folder is a template,
not an active workflow. A root workflow must download the three ignored stock
prebuilts from private storage, verify their pinned hashes, then call this
tree's scripts. See `docs/CI.md`.

## Block 3 handoff (2026-09-04)

The public repository now contains the root validation workflow and secure
stock-prebuilt staging utilities. Stock-derived binaries remain ignored and
are accepted only after size, regular-file, path-containment, and SHA-256
checks. Compilation must run from the private self-hosted workflow documented
in `docs/CI.md`; the old nested build workflow is not an active public CI job.
