# Temporary Boot Strategy — OnePlus 10T 5G (Ovaltine)

Status: **research / not yet device-validated**

The M1 goal is to execute `OvaltineDiag.efi` without replacing permanent firmware or repartitioning internal storage.

## Safety hierarchy

Preferred launch paths, from safest to least desirable:

1. Existing OEM/UEFI shell or firmware loader, if an accessible path is confirmed on the exact device firmware.
2. Temporary fastboot boot of a correctly packaged boot image, **only if the exact bootloader reports support for the command and route validation confirms temporary execution**.
3. Temporary chain-load from a known-good recovery/test environment that does not overwrite boot-critical partitions.
4. A persistent/disposable-slot technique only in a later milestone after stock images, active-slot state, rollback and emergency recovery are fully verified. It is not an M1 launch path.

Persistent ABL/XBL/UEFI replacement is **not** an M1 technique.

## Current OnePlus 10T evidence

Community evidence confirms that unlocked OnePlus 10T variants can interact with the `boot` partition through fastboot, and reports exist of `fastboot boot boot.img` being used on some firmware revisions. However, OnePlus/Oplus firmware updates have also changed or broken access to classic bootloader fastboot on some releases, with only fastbootd remaining available in affected cases.

Therefore IzzOS must not assume that `fastboot boot` is universally available across CPH2413/CPH2415/CPH2417/CPH2419 or across OxygenOS versions.

## Validation gate before any launch attempt

On the exact test phone, collect only the minimum read-only state first:

- exact model/product identifier;
- OxygenOS version/build;
- bootloader lock state;
- current A/B slot and slot count;
- classic bootloader fastboot versus fastbootd state;
- bootloader version where exposed;
- selected read-only fastboot variables only: `product`, `current-slot`, `slot-count`, `unlocked`, `secure`, `is-userspace`, `version-bootloader`.

IzzOS intentionally does **not** request `fastboot getvar all`: broad dumps can expose device identifiers that are not required for M1.

No command that writes a partition belongs in this validation step.

## Temporary-boot capability interpretation

Seeing classic fastboot and an unlocked bootloader is only a **candidate state**. It does not prove that a specific firmware safely supports temporary `fastboot boot` for the package we intend to use.

Before a route can be marked validated, IzzOS must have route-specific evidence for the exact firmware and a recovery plan. The analyzer therefore reports conservative states such as `CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED` instead of treating an unlocked device as approval to launch.

The physical route record must also pass `verify-m2-route-evidence.sh`. A manifest that merely names a missing evidence path, or artifacts whose current bytes no longer match their recorded size/SHA256, cannot advance to route-specific packaging.

A detached signature can be checked with `verify-m2-route-attestation.py`. Internal M13 can additionally validate root-signed custody, rotation and revocation records with `verify-m2-route-attester-governance.py`, but its root is still caller supplied rather than repository enrolled. Both success classifications remain non-authorizing: signatures prove key endorsement of bytes, not physical truth by themselves.

## Packaging requirement

`OvaltineDiag.efi` by itself is an EFI application, not an Android boot image. Even if temporary boot is supported, IzzOS still needs a non-destructive packaging/chain-load layer compatible with the OnePlus 10T boot image format and OEM boot chain.

The package must be derived from the exact stock boot/vendor_boot format rather than guessed from an older Snapdragon target. See `docs/PRE_M2_PACKAGING.md` for the route-neutral packaging contract.

## Exit condition

This strategy advances from research to validated only when we can demonstrate a repeatable procedure that:

1. loads an IzzOS diagnostic payload temporarily;
2. performs no partition write;
3. reaches diagnostic output or a controlled failure;
4. returns to stock boot after reboot;
5. leaves slot metadata and user partitions unchanged.

Until all five conditions are evidenced on the exact device, M1 stays active and no persistent boot-critical operation is authorized.
