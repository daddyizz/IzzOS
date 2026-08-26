# OnePlus 10T 5G (`ovaltine`) — Reference Device

## Identity

- Product: OnePlus 10T 5G / OnePlus Ace Pro family
- Codename: `ovaltine`
- Qualcomm platform: SM8475
- Commercial chipset: Snapdragon 8+ Gen 1
- GPU: Adreno 730

Known model identifiers include CPH2413, CPH2415, CPH2417 and CPH2419. The exact physical test device variant must be confirmed before any partition or flashing instructions are used.

## Source assets already available

OnePlus has published an SM8475 kernel source branch specifically named for the OnePlus 10T 5G, plus a companion kernel-modules/device-tree repository. Community Lineage development for `ovaltine` also exposes useful board configuration and partition information.

These sources are references for hardware discovery; they are not Windows drivers and do not make the phone Windows-compatible by themselves.

## Primary porting problems

### Boot firmware

Android devices use Qualcomm/OEM boot firmware rather than a PC UEFI implementation suitable for Windows. IzzOS needs a device-specific EDK2/UEFI layer that can coexist with the Qualcomm boot chain and be test-booted safely.

### ACPI

Windows ARM64 expects ACPI-described hardware. Android/Linux device-tree data must be translated into correct Windows-facing ACPI descriptions for the hardware that is enabled.

### Drivers

The largest compatibility risk is Windows driver availability, particularly for:

- Adreno 730 GPU
- UFS/storage controller
- USB controller
- touchscreen
- Wi-Fi/Bluetooth
- audio DSP/codecs
- battery/charging
- sensors
- modem/cellular stack

### Gaming

AAA gaming depends primarily on a working accelerated GPU driver, DirectX support, Windows ARM64/x64 application compatibility, thermal headroom and game-specific middleware/anti-cheat support. CPU speed alone is not enough.

## Development safety gates

Before touching the phone:

1. confirm exact model identifier and RAM/storage variant;
2. confirm bootloader-unlock state and rollback implications;
3. archive stock firmware and critical boot artifacts;
4. document EDL/recovery options that actually apply to the device;
5. create a non-destructive first-boot strategy;
6. do not repartition internal storage until Windows PE can boot and storage behavior is understood.

## First technical milestone

The first meaningful success is **not installing Windows**. It is safely reaching a custom EDK2/UEFI screen or EFI shell on the OnePlus 10T 5G with enough logging to continue hardware bring-up.
