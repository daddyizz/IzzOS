# Temporary Boot Strategy — OnePlus 10T 5G (Ovaltine)

Status: **research / not yet device-validated**

The M1 goal is to execute `OvaltineDiag.efi` without replacing permanent firmware or repartitioning internal storage.

## Safety hierarchy

Preferred launch paths, from safest to least desirable:

1. Existing OEM/UEFI shell or firmware loader, if an accessible path is confirmed on the exact device firmware.
2. Temporary fastboot boot of a correctly packaged boot image, **only if the exact bootloader reports support for the command**.
3. Temporary chain-load from a known-good recovery/test environment that does not overwrite boot-critical partitions.
4. Flashing a disposable boot slot only after stock images, active-slot state and rollback are fully verified.

Persistent ABL/XBL/UEFI replacement is **not** an M1 technique.

## Current OnePlus 10T evidence

Community evidence confirms that unlocked OnePlus 10T variants can interact with the `boot` partition through fastboot, and reports exist of `fastboot boot boot.img` being used on some firmware revisions. However, OnePlus/Oplus firmware updates have also changed or broken access to classic bootloader fastboot on some releases, with only fastbootd remaining available in affected cases.

Therefore IzzOS must not assume that `fastboot boot` is universally available across CPH2413/CPH2415/CPH2417/CPH2419 or across OxygenOS versions.

## Validation gate before any launch attempt

On the exact test phone, collect only read-only state first:

- exact model identifier;
- OxygenOS version/build;
- bootloader lock state;
- current A/B slot;
- output of `fastboot getvar all` with device identifiers redacted before committing logs;
- confirmation whether classic bootloader fastboot is available, not only fastbootd;
- confirmation whether the bootloader advertises/accepts temporary `boot` without flashing.

No command that writes a partition belongs in this validation step.

## Packaging requirement

`OvaltineDiag.efi` by itself is an EFI application, not an Android boot image. Even if temporary `fastboot boot` is supported, IzzOS still needs a non-destructive packaging/chain-load layer compatible with the OnePlus 10T boot image format and OEM boot chain.

The package must be derived from the exact stock boot/vendor_boot format rather than guessed from an older Snapdragon target.

## Exit condition

This strategy advances from research to validated only when we can demonstrate a repeatable command sequence that:

1. loads an IzzOS diagnostic payload temporarily;
2. performs no partition write;
3. reaches diagnostic output or a controlled failure;
4. returns to stock boot after reboot;
5. leaves slot metadata and user partitions unchanged.
