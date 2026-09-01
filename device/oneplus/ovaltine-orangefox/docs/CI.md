# CI build requirements

The stock kernel, DTB and DTBO are firmware-derived binaries and are excluded
from normal Git history. Therefore the checked-in workflow template cannot
build from a plain repository checkout.

## Required layout

An active GitHub Actions workflow must live at repository root:

```text
.github/workflows/build-orangefox-ovaltine.yml
```

The device tree remains at:

```text
device/oneplus/ovaltine-orangefox
```

All validation/build commands in the root workflow must use that full path.

## Private prebuilt archive

Store a versioned archive in a private, access-controlled repository or other
private artifact store. It must contain only:

```text
prebuilt/kernel
prebuilt/dtbo.img
prebuilt/dtbs/stock.dtb
```

Expected hashes:

```text
f5137d9b953455882ff4657f33c9966d173ab41d155f822c25434f35829f4bcb  prebuilt/kernel
2f1efc6328c4a87923489f453c5acc455d3713694178cd2631d022924c106313  prebuilt/dtbo.img
0fa5416a6b417f25007f62b75bcc012a76596b1c01d7af783fb090940abce5dd  prebuilt/dtbs/stock.dtb
```

Use a fine-grained read-only token stored as an Actions secret to retrieve the
archive. Do not put binary data in Actions secrets and do not publish the stock
archive as a public release.

## Runner requirements

- Linux x86-64
- At least 16 GiB RAM; more is recommended
- At least 80 GiB free disk for a standard upstream sync
- Six-hour job timeout
- `GOMAXPROCS=2`, `GOMEMLIMIT=10GiB`
- Ninja/Soong build limited to one job

A hosted runner with insufficient disk should use the pinned QPR3 local
manifest and shallow sync. The build must validate that `recovery.img` exists,
is no larger than 104,857,600 bytes, and has a recorded SHA-256 before upload.
