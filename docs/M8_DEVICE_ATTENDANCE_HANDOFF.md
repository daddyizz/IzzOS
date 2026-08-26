# Internal M8 Device-Attendance Handoff

Status: **host-side implementation complete; local phone attendance required**

This document uses the internal M1 engineering sequence. Internal M8 is not product-roadmap `M8 — GPU Acceleration / Adreno 730`; the GPU track remains separate and paused as recorded in the roadmap.

## Purpose

Internal M7 completed the host-side evidence/security gate implementation but product M1 still requires exact physical-device evidence. Internal M8 makes that boundary deterministic and privacy-safe: the existing read-only inspector now distinguishes host-tool, connection, authorization, selection and bootloader-mode states without printing device serial numbers or changing device state.

Run the collector only when a person can attend the phone:

```bash
bash scripts/collect-m1-device-inspection.sh out/m1-device-inspection
```

The collector executes capability queries only. It does not run `adb reboot`, `fastboot boot`, flash, erase, format, unlock, OEM commands or slot-changing commands.

## Attendance classifications

- `DEVICE_TOOLCHAIN_REQUIRED`: adb or fastboot evidence cannot be collected because the host toolchain is incomplete.
- `DEVICE_CONNECTION_REQUIRED`: neither an authorized Android device nor a fastboot device is present.
- `ADB_AUTHORIZATION_REQUIRED`: Android is visible but a person must unlock the phone and approve this host's USB-debugging fingerprint.
- `DEVICE_SELECTION_AMBIGUOUS_BLOCKED`: more than one authorized ADB or fastboot device is present, so identity queries are skipped.
- `NEED_EXACT_FASTBOOT_INSPECTION`: exact Android identity is captured; a person must enter classic bootloader-fastboot and rerun the collector.
- `FASTBOOTD_DETECTED_BLOCKED`: the observed transport is userspace fastbootd, not classic bootloader-fastboot.
- `LOCKED_BOOTLOADER_BLOCKED` or `BOOTLOADER_STATE_UNKNOWN_BLOCKED`: temporary-route work remains stopped.
- `CLASSIC_FASTBOOT_CANDIDATE_UNVERIFIED`: exact capability evidence is present, but temporary boot is still not authorized.

Analyzer output includes authorized and other ADB entry counts, never serial values. Ambiguous states are evaluated before any identity decision. Fastboot capability queries run only when exactly one fastboot device is present.

## Completion boundary

The internal M8 host-side milestone is complete when all of the following are true:

1. disconnected, unauthorized, ambiguous, ADB-only, fastbootd, locked and classic-fastboot candidate states are classified independently;
2. collector tests prove serial values do not appear in either authorized or unauthorized evidence bundles;
3. generated bundles remain checksum-bound and explicitly non-authorizing;
4. static safety checks reject reboot-, launch-, flash-, erase-, format-, unlock- and slot-changing command lines; and
5. the workflow runs the complete analyzer and collector tests on push and pull request.

These are host-tooling completion criteria only. Product M1 remains open until a person supplies authorized Android and exact classic-fastboot captures, the temporary route is independently validated, `M1-DIAG-R3` executes, GOP and memory-map evidence are captured, stock boot is restored without partition/slot changes, and the runtime record binds the externally verified payload hash.
