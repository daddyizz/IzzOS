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
- Progress checkpoint commit: `c3485d7509fe8fbee836089dcee3ac20a9bb064f`
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

## Last build result

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
2. **Minimum build graph** — reduce source/module scan enough to fit the 14 GiB
   memory limit; record every source override in the manifest/scripts.
3. **Build host** — use a reproducible host or CI path that can securely obtain
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
