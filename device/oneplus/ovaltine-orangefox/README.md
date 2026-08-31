# OrangeFox Recovery for OnePlus 10T (ovaltine)

Unofficial, early bring-up tree for:

- Device: OnePlus 10T
- Codename: `ovaltine`
- Platform: Qualcomm `taro`
- Model: `CPH2413`
- Board/product: `OP5552L1`
- Firmware baseline: OxygenOS `15.0.0.1901(EX01)`
- OrangeFox base: official experimental `fox_14.1`

## Status

This is an **Alpha bring-up tree**, not a release image. It has not yet booted
on real hardware. Do not flash a build before it passes a temporary boot test.

The stock layout exposes a dedicated A/B `recovery` target while keeping the
kernel and first-stage modules in the slot's boot/vendor-boot chain. The normal
build target is therefore `recoveryimage`.

## Required stock files

All four files must come from the exact firmware baseline above:

- `boot.img` (201326592 bytes)
- `vendor_boot.img` (201326592 bytes)
- `dtbo.img` (25165824 bytes)
- `vbmeta.img` (12288 bytes)

The importer hard-checks the previously verified `vendor_boot.img` SHA-256:

`ef230a4e1b9957ce0093f86f9bc8728f344665e741aa0bc584cc65281652e6e0`

## Import stock prebuilts

After the OrangeFox 14.1 source has been synced, run:

```bash
./scripts/import-stock.sh \
  --boot /path/to/boot.img \
  --vendor-boot /path/to/vendor_boot.img \
  --dtbo /path/to/dtbo.img \
  --vbmeta /path/to/vbmeta.img \
  --unpack-tool /path/to/OrangeFox_14.1/tools/mkbootimg/unpack_bootimg.py
```

Then run `./scripts/validate-tree.sh`.

## Sync and build

Use the official OrangeFox sync repository:

```bash
git clone https://gitlab.com/OrangeFox/sync.git OrangeFox_sync
./OrangeFox_sync/orangefox_sync.sh --branch 14.1 --path /path/to/OrangeFox_14.1
./scripts/build-orangefox.sh /path/to/OrangeFox_14.1
```

The official documentation warns that the sync can consume 40-80 GB. The
included GitHub Actions workflow removes unused runner SDKs before syncing, but
a large self-hosted runner is more reliable.

For the Android 14 QPR3 build environment, use:

```bash
lunch twrp_ovaltine-ap2a-eng
```

TeamWin's `android-14.1` build branch must be paired with the matching QPR3
release config, Bazel, Blueprint, Soong, Go and Starlark sources.

## Safety gate

Before any on-device test:

1. Extract the stock `recovery.img` from the same OTA and keep it locally.
2. Keep both active-slot stock boot images and a working fastboot connection.
3. Verify the generated checksum and image header.
4. Construct a temporary boot-test image from the stock kernel plus the built
   recovery ramdisk; test with `fastboot boot`, where supported.
5. Only consider writing `recovery_a`/`recovery_b` after boot, display, touch,
   ADB, storage mounts and reboot have all passed.

Never flash a generated `vbmeta.img` from this project.

The temporary image can be assembled with OrangeFox/Magisk's `magiskboot`:

```bash
./scripts/make-boot-test.sh \
  --magiskboot /path/to/magiskboot \
  --stock-boot /path/to/boot.img \
  --recovery /path/to/recovery.img \
  --output /path/to/boot-test.img
```

The script preserves the stock boot header and kernel, substitutes only the
OrangeFox ramdisk, validates the 192 MiB stock input, and labels the output as a
temporary-test artifact.

## Known bring-up risks

- Android 15 FBE/decryption has not been validated.
- Touch/display brightness nodes may differ between panel variants.
- The fallback fstab is based on the current LineageOS sm8450-common tree and
  must be compared against the exact stock vendor-boot fstab.
- OrangeFox `fox_14.1` is marked experimental by its upstream project.
