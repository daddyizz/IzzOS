# M7 Standalone Firmware Layout Contract

Status: **host-side region contract implemented; launch remains blocked**

This document uses the internal M1 engineering sequence. Internal Milestone 7 is not the product-roadmap milestone named “M7 — Core Device Drivers.” It is the standalone-firmware layout step inside the overall M1 UEFI bring-up.

## M6 handoff

Internal Milestone 6 is complete only when `scripts/verify-m1-kernel-region-geometry.py` classifies the exact stock evidence as:

```text
M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_RECONCILED
```

The verifier binds its result to the exact `uefiplat.cfg`, `boot.img`, and `vendor_boot.img` hashes. It also requires Android boot header v4, vendor boot header v4, a valid page size, in-region DTB/ramdisk placement, and a kernel payload that ends before the derived DTB load address.

Invalid or overlapping geometry is classified:

```text
M1_EXACT_STOCK_KERNEL_REGION_GEOMETRY_BLOCKED
```

## M7 region contract

Run:

```bash
python3 scripts/check-m7-layout-contract.py \
  out/m1-kernel-region-geometry.txt \
  out/uefiplat.cfg \
  out/m7-layout-contract.txt
```

The M7 checker independently verifies:

- the exact `uefiplat.cfg` hash still matches the M6 evidence;
- the named `Kernel` region is unique and matches the M6 base/size;
- the derived DTB and ramdisk placements remain inside that region and ordered correctly;
- M6 proved that the stock kernel payload ends before the DTB;
- no other named `uefiplat.cfg` region overlaps the bounded Kernel region.

A successful result is:

```text
M7_LAYOUT_REGION_CONTRACT_PASS
```

This result authorizes only host-side construction and validation work. It does not authorize a device launch.

## Actual FD capacity check

After a real standalone FD artifact exists, validate its actual bytes rather than a configured estimate:

```bash
python3 scripts/verify-m7-fd-capacity.py \
  out/m7-layout-contract.txt \
  out/ovaltine-standalone/Ovaltine.fd \
  out/m7-fd-capacity.txt
```

The verifier hashes the FD, checks that its real size is aligned to the exact stock page size recorded by M6, and ensures its aligned size does not cross the exact stock DTB load bound. A successful result is:

```text
M7_FD_CAPACITY_CONTRACT_PASS
```

This is a capacity result only. It deliberately does not choose the FD base or claim that the bootloader will enter the artifact.

## Exact selected-DTB binding

Before deriving GIC, timer, or other platform facts from a DTB, bind one extracted blob to all three sources of evidence:

```bash
python3 scripts/verify-m7-selected-dtb.py \
  out/m7-layout-contract.txt \
  out/m1-device-inspection/ovaltine-inspection-analysis.txt \
  out/vendor-boot-dtb-set/MANIFEST.txt \
  out/vendor-boot-dtb-set/dtb-1.dtb \
  output/vendor_boot.img \
  out/m7-selected-dtb.txt
```

The verifier requires a passing M7 layout contract, the exact `vendor_boot` hash carried from M6, a numeric device-reported DTB index, a matching extraction-manifest entry, matching DTB bytes, and the expected Cape identity. A successful result is:

```text
M7_EXACT_SELECTED_DTB_BOUND
```

This binds the DTB input for later platform analysis. It does not prove that static DTB MMIO values are sufficient for standalone initialization.

## Bound-DTB GIC and timer evidence

After the selected DTB binding passes, enumerate the architectural interrupt-controller and timer properties from those exact bytes:

```bash
python3 scripts/verify-m7-gic-timer-dtb.py \
  out/m7-selected-dtb.txt \
  out/vendor-boot-dtb-set/dtb-1.dtb \
  out/m7-gic-timer-dtb.txt
```

The verifier requires the DTB hash to match an `M7_EXACT_SELECTED_DTB_BOUND` artifact. It then requires one enabled `arm,gic-v3` interrupt controller with three or four interrupt cells and at least two structured register entries, plus one enabled `arm,armv8-timer` node with at least two complete interrupt specifiers. These bounds follow the upstream Devicetree schemas while leaving runtime initialization separately blocked. A successful enumeration is:

```text
M7_GIC_TIMER_DTB_EVIDENCE_ENUMERATED
```

This classification records source bytes and raw DTB properties only. It does not authorize copying static addresses into firmware PCDs, touching MMIO, assuming the boot exception level, or claiming that GIC/timer state survives the Android boot chain.

## Exact-stock AArch64 Linux entry contract

Bind the exact `boot.img` bytes to the M7 layout and validate both the Android v4 container header and the embedded 64-byte AArch64 Linux Image header:

```bash
python3 scripts/verify-m7-aarch64-entry-contract.py \
  out/m7-layout-contract.txt \
  output/boot.img \
  out/m7-aarch64-entry-contract.txt
```

The verifier checks the M6-carried `boot.img` hash, Android header v4 geometry, AArch64 magic/reserved fields/flags, `text_offset`, `image_size`, the 2 MiB placement relationship, and the exact pre-DTB capacity bound. A successful result is:

```text
M7_STOCK_AARCH64_LINUX_ENTRY_CONTRACT_ENUMERATED
```

The resulting report records the upstream Linux handoff requirements: `x0` carries the DTB address, `x1`–`x3` are zero, execution is non-secure EL2 or EL1, interrupts are masked, and the MMU is off. Those are source requirements, not observations of the Qualcomm handoff. The actual entry EL, system-register state and equivalence of a standalone EDK2 SEC entry remain unproven.

## Exact Android container input binding

Once the layout, capacity, selected-DTB and entry reports plus the actual FD exist, bind their exact bytes into one input-only evidence chain:

```bash
python3 scripts/verify-m7-android-container-inputs.py \
  out/m7-layout-contract.txt \
  out/m7-fd-capacity.txt \
  out/m7-selected-dtb.txt \
  out/m7-aarch64-entry-contract.txt \
  out/ovaltine-standalone/Ovaltine.fd \
  output/boot.img \
  output/vendor_boot.img \
  out/m7-android-container-inputs.txt
```

The verifier requires every prerequisite gate to pass while continuing to deny launch. It cross-checks the exact FD size/hash, the M6-carried and downstream `boot.img` and `vendor_boot.img` hashes, the exact device build, Android boot header v4, vendor boot header v4, and the stock page size. A successful result is:

```text
M7_ANDROID_CONTAINER_INPUTS_BOUND
```

This classification deliberately does not construct or repack an image. It authorizes no kernel replacement, vendor-boot modification, AVB bypass, fastboot command, persistent write, slot change, or launch. The Qualcomm container replacement/relocation semantics, FD base and route authorization remain separate evidence gates.

## Exact LinuxLoader placement evidence binding

Bind the exact stock AArch64 `LinuxLoader.efi` and its placement analyses to the exact M7 Android input set:

```bash
python3 scripts/verify-m7-linuxloader-placement-evidence.py \
  out/m7-android-container-inputs.txt \
  out/linuxloader/LinuxLoader.efi \
  out/linuxloader-placement-function.txt \
  out/linuxloader-bootparam-field-writes.txt \
  out/linuxloader-size-term-provenance.txt \
  out/linuxloader-v4-size-term-semantics.txt \
  output/boot.img \
  output/vendor_boot.img \
  out/m7-linuxloader-placement-evidence.txt
```

The verifier requires all three binary-analysis reports to carry the actual LinuxLoader hash, requires an AArch64 PE32+ image, binds the v4 size semantics to the exact boot/vendor hashes, and checks the source-matched ramdisk/DTB placement formulas and the exact-build dynamic guard. A successful result is:

```text
M7_EXACT_LINUXLOADER_PLACEMENT_EVIDENCE_BOUND
```

This binds the stock Linux-kernel placement arithmetic only. It does not prove the final runtime destination or that a standalone FD can replace an AArch64 Linux Image while satisfying Qualcomm entry, relocation, cache/MMU and security-state expectations. FD-base selection, container construction and launch remain unauthorized.

## Standalone SEC entry requirement binding

Bind the exact stock Linux handoff, LinuxLoader placement, selected DTB, and static GIC/timer evidence into one deliberately non-authorizing SEC/PrePi requirement manifest:

```bash
python3 scripts/verify-m7-standalone-sec-entry-requirements.py \
  out/m7-aarch64-entry-contract.txt \
  out/m7-linuxloader-placement-evidence.txt \
  out/m7-selected-dtb.txt \
  out/m7-gic-timer-dtb.txt \
  out/m7-standalone-sec-entry-requirements.txt
```

The verifier binds the boot and DTB hashes across all prerequisite reports and preserves their denial policies. It records the upstream [AArch64 Linux boot contract](https://www.kernel.org/doc/html/latest/arch/arm64/booting.html): `x0` carries the DTB, `x1`–`x3` are zero, execution is non-secure EL2 or EL1, DAIF is masked, the MMU is off, the instruction cache may be on or off without stale image entries, and the loaded image is clean to the point of coherency. It separately records that an EDK2 platform firmware volume is patched to its [SEC/PrePi entrypoint](https://github.com/tianocore/edk2-platforms/blob/master/Platform/ARM/JunoPkg/ArmJuno.fdf), rather than assuming a raw FD is a Linux Image. A successful result is:

```text
M7_STANDALONE_SEC_ENTRY_REQUIREMENTS_BOUND
```

This is a requirements result, not entry-equivalence proof. It requires a wrapper to capture `CurrentEL`, SCTLR/cache/MMU, DAIF and timer state; preserve the DTB register; establish a stack and temporary RAM; and normalize image coherency before SEC/PrePi. Until those observations and the final runtime destination are independently bound, direct FD substitution, DSC/FDF promotion, MMIO initialization, container construction and launch remain forbidden.

## Qualcomm entry observation schema gate

Validate a future pre-SEC register snapshot against the exact requirement manifest:

```bash
python3 scripts/verify-m7-qualcomm-entry-observation.py \
  out/m7-standalone-sec-entry-requirements.txt \
  out/m7-qualcomm-entry-observation-raw.txt \
  out/m7-qualcomm-entry-observation.txt
```

The raw snapshot must use schema `IZZOS_M7_QUALCOMM_ENTRY_V1` and bind the exact requirement-report, boot, LinuxLoader and selected-DTB hashes. It records the primary CPU's non-secure `CurrentEL`, matching `SCTLR_EL1` or `SCTLR_EL2`, `x0`–`x3`, DAIF, CNTFRQ, CNTVOFF, image coherency and secondary-CPU state. The verifier requires `x0` to match the stock DTB address, `x1`–`x3` to be zero, all DAIF masks to be set, the MMU to be off, CNTFRQ to be non-zero and CNTVOFF to be zero. A structurally consistent result is:

```text
M7_QUALCOMM_ENTRY_OBSERVATION_SCHEMA_PASS
```

This classification is intentionally limited to schema and consistency validation. The snapshot remains self-reported rather than independently attested, and the capture route is not authorized by this gate. Extension-specific system registers, SEC equivalence, wrapper implementation, DSC/FDF promotion, MMIO, container construction and launch remain separately blocked.

## AArch64 extension-register inventory schema gate

Bind a future raw CPU-feature and EL2-control inventory to the exact baseline snapshot:

```bash
python3 scripts/verify-m7-aarch64-extension-register-inventory.py \
  out/m7-qualcomm-entry-observation.txt \
  out/m7-aarch64-extension-registers-raw.txt \
  out/m7-aarch64-extension-registers.txt
```

Schema `IZZOS_M7_AARCH64_EXTENSION_REGISTERS_V1` carries `MIDR_EL1`, `MPIDR_EL1`, the relevant `ID_AA64*` feature registers, and raw `HCR_EL2`, `CPTR_EL2`, `CNTHCTL_EL2`, `MDCR_EL2`, `ICC_SRE_EL2`, `ZCR_EL2` and `SMCR_EL2` visibility. The verifier binds the inventory to the exact baseline-report hash, propagates the baseline's validated `CNTFRQ_EL0` and `CNTVOFF_EL2` state, requires explicit EL2 visibility when the payload enters at EL2, and derives only basic feature presence such as FP/SIMD, SVE, SME, MTE and pointer authentication. This follows the upstream [AArch64 boot system-register requirements](https://www.kernel.org/doc/html/latest/arch/arm64/booting.html) and [CPU feature-register definitions](https://kernel.org/doc/html/next/arm64/cpu-feature-registers.html). A structurally complete result is:

```text
M7_AARCH64_EXTENSION_REGISTER_INVENTORY_SCHEMA_PASS
```

Raw inventory is not bit-compliance proof. Conditional extension requirements, cross-core consistency, independent snapshot authentication, wrapper implementation, DSC/FDF promotion, MMIO and launch remain blocked.

## AArch64 extension control-bit assessment

Evaluate the conditional control bits in an inventory report that already passed the raw-register schema gate:

```bash
python3 scripts/verify-m7-aarch64-extension-bit-assessment.py \
  out/m7-aarch64-extension-registers.txt \
  out/m7-aarch64-extension-bit-assessment.txt
```

For an EL1 entry, the assessor checks a bounded set of applicable upstream requirements in `HCR_EL2`, `CPTR_EL2`, `CNTHCTL_EL2` and `ICC_SRE_EL2`, including feature-dependent SVE, MTE and pointer-authentication controls. It also requires visible primary-CPU `CNTFRQ_EL0` and `CNTVOFF_EL2` state. SME is deliberately blocked until its additional `SCTLR_EL2`, fine-grained trap and version-dependent controls are represented. An EL1 report that satisfies every control bit covered by this gate is classified:

```text
M7_AARCH64_EXTENSION_BIT_ASSESSMENT_PASS
```

For an EL2 entry, EL1-specific EL2 controls are not treated as proof of the incoming EL2 state. The relevant Secure EL3 prerequisites cannot be observed from a non-secure EL2 snapshot, so the safe classification is:

```text
M7_AARCH64_EXTENSION_BIT_ASSESSMENT_DEFERRED_SECURE_EL3_EVIDENCE
```

This is not full upstream system-register compliance. Both results remain bound to a self-reported snapshot; Secure EL3 prerequisites, unassessed extensions, cross-core `CNTVOFF_EL2`/`ZCR_EL2`/`SMCR_EL2` consistency, independent authenticity, capture-route authorization, wrapper implementation, DSC/FDF promotion, MMIO and launch remain unproven and unauthorized.

## AArch64 cross-core register consistency gate

Validate a future read-only rendezvous inventory against both the exact primary-CPU register report and the enabled CPU affinity set parsed from the exact selected DTB:

```bash
python3 scripts/verify-m7-aarch64-cross-core-registers.py \
  out/m7-aarch64-extension-registers.txt \
  out/m7-selected-dtb.txt \
  out/vendor-boot-dtb-set/dtb-1.dtb \
  out/m7-aarch64-cross-core-registers-raw.txt \
  out/m7-aarch64-cross-core-registers.txt
```

Schema `IZZOS_M7_AARCH64_CROSS_CORE_REGISTERS_V1` carries one canonical record per enabled DTB CPU. The verifier masks non-affinity `MPIDR_EL1` bits, rejects missing, extra, duplicate or out-of-order affinities, and requires every record's `CNTFRQ_EL0`, `CNTVOFF_EL2`, `ZCR_EL2` and `SMCR_EL2` state to match the exact primary snapshot where the feature is present. This implements the bounded cross-CPU consistency requirements from the upstream [AArch64 Linux boot contract](https://www.kernel.org/doc/html/latest/arch/arm64/booting.html). A complete and internally consistent result is:

```text
M7_AARCH64_CROSS_CORE_REGISTER_CONSISTENCY_PASS
```

The classification validates topology coverage and the four represented register states only. It does not independently attest the snapshot or prove coherency-domain membership, Secure EL3 state, capture-route safety, wrapper execution, DSC/FDF promotion, MMIO or launch.

## Coherency-domain and secondary-CPU assertion schema gate

Bind a future implementation-defined firmware assertion to the exact cross-core register report:

```bash
python3 scripts/verify-m7-coherency-secondary-state.py \
  out/m7-aarch64-cross-core-registers.txt \
  out/m7-coherency-secondary-state-raw.txt \
  out/m7-coherency-secondary-state.txt
```

Schema `IZZOS_M7_COHERENCY_SECONDARY_STATE_V1` requires one canonical record per bound CPU affinity, exactly one primary matching the primary snapshot, one opaque firmware domain token, maintenance-broadcast assertions on every CPU, and secondary CPUs parked or not released without running the payload. It also rejects any assertion that a secondary release, coherency configuration, or maintenance operation was performed during collection. A structurally complete result is:

```text
M7_COHERENCY_SECONDARY_STATE_ASSERTION_SCHEMA_PASS
```

The upstream [AArch64 Linux boot contract](https://www.kernel.org/doc/html/latest/arch/arm64/booting.html) explicitly allows coherency enablement to require implementation-defined initialization. Therefore this gate intentionally validates assertion structure only: the opaque domain token and broadcast state remain self-reported, not register-attested proof. Capture-route authorization, the exact Qualcomm coherency mechanism, Secure EL3 state, wrapper implementation, DSC/FDF promotion, MMIO and launch remain blocked.

## SM8475 coherency provenance boundary gate

Bind the assertion report to an immutable snapshot of the OnePlus-published Cape device tree and PSCI binding:

```bash
python3 scripts/verify-m7-sm8475-coherency-provenance.py \
  out/m7-coherency-secondary-state.txt \
  out/m7-sm8475-coherency-provenance-raw.txt \
  out/m7-sm8475-coherency-provenance.txt
```

Schema `IZZOS_M7_SM8475_COHERENCY_PROVENANCE_V1` pins OnePlus commit `a24e032ef338174bfa835bed0f8e2ad3620f4ffc`, the exact `cape.dtsi` blob, and the exact PSCI binding blob. At that snapshot, [Cape declares eight CPUs with `enable-method = "psci"`](https://github.com/OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8475/blob/a24e032ef338174bfa835bed0f8e2ad3620f4ffc/kernel_platform/qcom/proprietary/devicetree/qcom/cape.dtsi), an `arm,psci-1.0` node, and the SMC conduit. The bound [PSCI documentation](https://github.com/OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8475/blob/a24e032ef338174bfa835bed0f8e2ad3620f4ffc/kernel_platform/qcom/proprietary/devicetree/bindings/arm/psci.txt) assigns CPU power operations such as CPU_ON to PSCI-compatible firmware. A complete provenance result is:

```text
M7_SM8475_COHERENCY_PROVENANCE_BOUNDARY_PASS
```

This result proves only the public firmware-interface boundary: secondary CPU enable/power control is exposed through PSCI over SMC. The public OnePlus files do not disclose an exact SM8475 coherency register, mask, or firmware sequence. The gate therefore rejects invented `CPUECTLR_EL1.SMPEN` claims, guessed MMIO addresses, or any attempt to turn this source provenance into wrapper, DSC/FDF, or launch authorization.

## Secure EL3 handoff-state assertion schema gate

Bind a future EL3-owned handoff record to the exact extension inventory/assessment, bound-DTB GIC evidence, and SM8475 coherency provenance report:

```bash
python3 scripts/verify-m7-secure-el3-handoff-state.py \
  out/m7-aarch64-extension-registers.txt \
  out/m7-aarch64-extension-bit-assessment.txt \
  out/m7-gic-timer-dtb.txt \
  out/m7-sm8475-coherency-provenance.txt \
  out/m7-secure-el3-handoff-state-raw.txt \
  out/m7-secure-el3-handoff-state.txt
```

Schema `IZZOS_M7_SECURE_EL3_HANDOFF_STATE_V1` accepts only a record explicitly generated at EL3 by the existing platform firmware; it rejects any claim that non-secure EL2 directly read EL3-only registers. The bounded no-trap profile requires a non-secure AArch64 EL2 target, SMC/HVC availability, the GICv3 system-register interface, cross-CPU `SCR_EL3.FIQ` and `ICC_CTLR_EL3.PMHE` assertions, and only the extension controls applicable to features enumerated in the bound inventory. These requirements follow the upstream [AArch64 Linux boot contract](https://www.kernel.org/doc/html/latest/arch/arm64/booting.html) and the reference [TF-A EL3 context setup](https://github.com/ARM-software/arm-trusted-firmware/blob/master/lib/el3_runtime/aarch64/context_mgmt.c). A structurally complete record is:

```text
M7_SECURE_EL3_HANDOFF_ASSERTION_SCHEMA_PASS
```

This remains a schema-only result. The record is self-reported, its capture route is not independently authorized, and feature controls absent from the current inventory are not assessed. It does not prove Secure EL3 compliance or authorize secure-monitor changes, wrapper implementation, DSC/FDF promotion, MMIO, or launch.

## SMCCC EL3 feature-availability route gate

Validate a future read-only Arm Architecture Service capture against the exact Secure EL3 handoff assertion:

```bash
python3 scripts/verify-m7-smccc-el3-feature-availability.py \
  out/m7-secure-el3-handoff-state.txt \
  out/m7-smccc-el3-feature-availability-raw.txt \
  out/m7-smccc-el3-feature-availability.txt \
  out/m7-pre-sec-smccc-route-authorization.txt \
  out/m7-smccc-capture-provisioning.txt
```

The final gate rehashes the exact route-authorization and capture-provisioning reports plus all seven collector/transport/emitter/orchestrator source components. It recomputes the canonical capture-provision binding and requires the serialized report digest, provision binding, single-use authorization binding, and bounded output-buffer geometry to match byte-for-byte. It also couples `SUPPORTED` to collector outcome `COMPLETE` and `NOT_SUPPORTED` to `FEATURE_UNAVAILABLE`. This closes the host-side evidence chain without turning the declared project-owner review into cryptographic attestation and without authorizing device launch, MMIO, persistent writes or slot changes.

Schema `IZZOS_M7_SMCCC_EL3_FEATURE_AVAILABILITY_V1` permits only `SMCCC_VERSION` (`0x80000000`), `SMCCC_ARCH_FEATURES` (`0x80000001`), and the SMC64 `SMCCC_ARCH_FEATURE_AVAILABILITY` function (`0xC0000003`) under Arm Architecture Service owner zero. The exact register opcodes are pinned to `SCR_EL3`, `CPTR_EL3`, and `MDCR_EL3`. This follows the upstream [TF-A Arm Architecture Service implementation](https://github.com/ARM-software/arm-trusted-firmware/blob/master/services/arm_arch_svc/arm_arch_svc_setup.c) and its [identifier/mask definitions](https://github.com/ARM-software/arm-trusted-firmware/blob/master/include/services/arm_arch_svc.h).

If discovery succeeds, the gate checks the returned sanitized availability masks against only the applicable FP/SIMD, pointer-authentication, MTE, SVE, and SME claims. A complete result is:

```text
M7_SMCCC_EL3_FEATURE_AVAILABILITY_CORROBORATION_PASS
```

If discovery returns `NOT_SUPPORTED`, the required safe result is `M7_SMCCC_EL3_FEATURE_AVAILABILITY_ROUTE_UNSUPPORTED`; no register query may then be issued. This is a valid capability finding, not permission to fall back to vendor/SiP calls or direct EL3 reads. The service deliberately reports normalized extension enablement rather than raw EL3 state, and omits the base `NS/RW/HCE/FIQ`, GIC, coherency and cross-CPU properties. Both outcomes therefore leave independent authenticity, complete Secure EL3 compliance, wrapper implementation, MMIO and launch unproven.

## Non-integrated SMCCC collector contract

`M7SmcccFeatureAvailabilityCollector` is a bounded library prototype for a future pre-SEC non-secure EL2 capture path. It is intentionally absent from `OvaltineDiag.dsc` and `OvaltineDiag.inf`: the current UEFI application does not establish the required caller exception/security state.

Before issuing any call, the collector requires a declared non-secure EL2 caller and a bound single-use route token. The former `RouteIsAuthorized` boolean has been removed. The token carries the exact route-authorization report digest, the deterministic evidence-binding digest, exact non-secure output-buffer geometry, a one-invocation budget, a five-call limit and the complete fixed safety-policy flags. Token values must match a separately provisioned expectation; zero or changed digests, unknown flags, unsafe or mismatched buffers and replay are rejected before the transport can run. A valid token is marked consumed and its budget is cleared before the first call. Its two digests and exact buffer geometry are then copied into `M7_SMCCC_CAPTURE` before the first call so the evidence chain cannot lose the authorization identity. The collector then enforces this fixed sequence:

1. `SMCCC_VERSION`; stop if unavailable or older than 1.1.
2. `SMCCC_ARCH_FEATURES` for `0xC0000003`; stop if unsupported or any error is returned.
3. Exactly three `SMCCC_ARCH_FEATURE_AVAILABILITY` queries, in canonical `SCR_EL3`, `CPTR_EL3`, `MDCR_EL3` order; stop on the first error.

The maximum is five SMC calls. FIDs and register opcodes are compile-time constants, not caller-supplied values. The separate AArch64 transport contains one `smc #0` instruction and no EL3 register access. Host tests inject a fake transport, so tests execute no SMC. They cover null and mismatched tokens, wrong EL, unknown policy flags, buffer mismatch, replay, consumption on terminal outcomes and the canonical supported/unsupported/error paths. A static source gate also rejects MMIO/storage/launch operations and any accidental integration into the current diagnostic build:

```text
M7_SMCCC_COLLECTOR_SOURCE_CONTRACT_PASS
```

The prototype is not device-route authorization. Its real transport must not be linked or invoked until a separate gate proves the exact pre-SEC non-secure EL2 route, recovery context and capture-output binding.

## Exact pre-SEC SMCCC collector route authorization

Validate a future reviewed route record before allowing the real collector transport to be invoked:

```bash
python3 scripts/verify-m7-pre-sec-smccc-route-authorization.py \
  out/m7-standalone-sec-entry-requirements.txt \
  out/m7-qualcomm-entry-observation.txt \
  out/m2-recovery-evidence.txt \
  out/m7-pre-sec-smccc-route-evidence.txt \
  out/m7-pre-sec-smccc-route-authorization.txt
```

Schema `IZZOS_M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_V1` fail-closes unless the route binds the exact SEC requirement and Qualcomm entry-observation reports, verified hard-recovery evidence, collector/transport/emitter/orchestrator source identities, and one aligned non-secure pre-SEC output buffer. The observed entry must be non-secure EL2 on the primary CPU. The route permits exactly one collector invocation, caps the Arm Architecture Service sequence at five calls, and fixes the allowed functions to `SMCCC_VERSION`, `SMCCC_ARCH_FEATURES`, and `SMCCC_ARCH_FEATURE_AVAILABILITY`. Its report also emits `IZZOS_M7_PRE_SEC_SMCCC_AUTHORIZATION_BINDING_V1`, a deterministic SHA-256 over all input/component digests, the route-evidence digest, route candidate and exact output-buffer geometry for provisioning into the C token.

Vendor/SiP SMCs, direct EL3 register reads, secure-monitor changes, MMIO, device or persistent writes, slot changes, flash/erase/format actions and payload launch must all remain forbidden. Tests reject changed evidence/source hashes, duplicate fields, EL1 routes, repeated invocation, extra calls, unsafe or undersized buffers, assisted-only recovery, write claims and relaxed launch policy. A structurally complete future record is:

```text
M7_PRE_SEC_SMCCC_ROUTE_AUTHORIZATION_PASS
```

The authorization scope is one bound feature-availability capture only; it is not payload-launch permission. The gate records project-owner review but does not claim cryptographic attestation. The current exact CPH2413 evidence remains blocked because hard recovery is only `ASSISTED_HARD_RECOVERY_DOCUMENTED` and the temporary route remains candidate-only.

## Deterministic route-token provisioning

Convert a passing route-authorization report into the exact C token and matching expectation consumed by the collector:

```bash
python3 scripts/generate-m7-smccc-route-token.py \
  out/m7-pre-sec-smccc-route-authorization.txt \
  out/generated/M7SmcccRouteAuthorizationProvision.h \
  out/generated/M7SmcccRouteAuthorizationProvision.c \
  out/m7-smccc-route-token-generation.txt
```

The generator accepts no caller-supplied token fields. It revalidates the unique `PASS` classification, binding schema/digest, exact CPH2413 build, verified hard-recovery status, all current collector/transport/emitter/orchestrator hashes, one-capture scope, non-launch/write policy and bounded aligned output-buffer geometry. It hashes the complete authorization report and expands that digest plus `authorization-binding-sha256` into fixed 32-byte C initializers. All policy flags, magic, version, structure size, one-use budget and five-call limit remain compile-time constants from the collector header.

Output is deterministic and consists of a generated header declaring the mutable token and immutable expectation plus a generated C definition. Host tests compare repeated output byte-for-byte, compile it with the collector on Linux, complete one fake-transport capture, reject replay, and reject changed classification, component hash, binding digest, recovery state, buffer, launch policy, invocation scope and duplicate fields. On any validation failure the generator removes stale header/source outputs at the exact requested paths. A successful report is:

```text
M7_SMCCC_ROUTE_TOKEN_PROVISIONING_PASS
```

Generated provision files remain absent from the DSC/INF and do not authorize payload launch. Because the current physical-device route evidence does not pass the preceding gate, no actionable token can currently be generated from the real evidence set.

## Deterministic collector transcript emitter

`M7SmcccCaptureTranscript` converts only a structurally valid `M7_SMCCC_CAPTURE` into `IZZOS_M7_SMCCC_COLLECTOR_CAPTURE_V1`. It reconstructs the call list from compile-time FIDs and the canonical register-opcode array; no caller-supplied FID, opcode, call count or outcome text is rendered. Only `COMPLETE` and `FEATURE_UNAVAILABLE` captures are serializable. Version, discovery, count, opcode and per-query status invariants must all match the collector state machine. A nonzero route-report digest, authorization-binding digest and bounded/aligned authorized output-buffer record are mandatory.

The emitter owns no storage or firmware I/O. It first measures the complete transcript, rejects an undersized caller buffer without touching it, and writes a NUL-terminated record only when capacity is sufficient. It emits the route-report and authorization-binding digests copied by the collector, the exact authorized buffer geometry and `route-authorization-input: BOUND_SINGLE_USE_TOKEN`. Eight additional SHA-256 bindings remain mandatory: the Secure EL3 handoff report plus the collector header, C state machine, AArch64 transport, emitter header/source and orchestrator header/source. Hash spelling is normalized to lowercase, giving byte-identical output for equivalent bindings.

The implementation remains absent from the current DSC/INF. A static source gate and host C harness verify the fixed schema/safety lines, canonical supported and unsupported paths, deterministic output, invalid binding/capture rejection, no partial buffer write, and end-to-end compatibility with the serializer and SMCCC route gate:

```text
M7_SMCCC_TRANSCRIPT_EMITTER_SOURCE_CONTRACT_PASS
```

This is an output-format bridge only. It neither invokes SMC nor proves or authorizes the pre-SEC route.

## Bound capture orchestrator

`M7SmcccCaptureOrchestrator` is the single fail-closed C entrypoint that joins a provisioned route token, the collector and the deterministic transcript emitter. It remains deliberately absent from `OvaltineDiag.dsc` and `OvaltineDiag.inf`.

Before calling the collector, the orchestrator validates all nine transcript-binding hashes and requires the actual output pointer and capacity to match the immutable route expectation exactly. It constructs the collector caller state internally as non-secure EL2, so callers cannot relax that property through this API. It invokes the collector once, permits transcript emission only for `COMPLETE` or `FEATURE_UNAVAILABLE`, and returns all other collector outcomes without modifying the authorized output buffer. Token replay, changed binding, changed expectation, redirected buffer and query-error paths fail closed.

The orchestrator accepts a transport callback only after those host-provisioned conditions pass; it neither calls `M7SmcccInvokeAArch64` directly nor chooses a real transport. Its host C harness uses a fake transport to cover supported, unsupported, replay, invalid binding, mismatched route digest, redirected buffer and terminal query-error behavior. A static gate also proves the source remains free of direct SMC/system-register instructions, storage/device-write APIs and current diagnostic integration:

```text
M7_SMCCC_CAPTURE_ORCHESTRATOR_SOURCE_CONTRACT_PASS
```

This source contract makes the future call sequence explicit but does not authenticate the physical-device route, integrate the real transport, authorize MMIO or grant payload-launch permission.

## Deterministic bound-capture provisioning

Generate the exact transcript binding and wrapper that join a passing handoff report, passing route authorization and the already generated single-use token artifacts to the orchestrator:

```bash
python3 scripts/generate-m7-smccc-capture-provision.py \
  out/m7-secure-el3-handoff-state.txt \
  out/m7-pre-sec-smccc-route-authorization.txt \
  out/generated/M7SmcccRouteAuthorizationProvision.h \
  out/generated/M7SmcccRouteAuthorizationProvision.c \
  out/m7-smccc-route-token-generation.txt \
  out/generated/M7SmcccCaptureProvision.h \
  out/generated/M7SmcccCaptureProvision.c \
  out/m7-smccc-capture-provisioning.txt
```

The generator recalculates the exact handoff and route-report hashes, all seven runtime component hashes, and the actual token header/source hashes. It requires the token-generation report to bind those same bytes and to retain the one-capture, verified-recovery, no-launch/no-write policy. A canonical `IZZOS_M7_SMCCC_CAPTURE_PROVISION_BINDING_V1` digest covers those inputs and the authorized buffer geometry. The generator emits a nine-hash `M7_SMCCC_TRANSCRIPT_BINDING`—eight source/handoff identities plus that provision digest—and `M7RunProvisionedSmcccFeatureAvailabilityCapture`, which supplies only that binding and the exact generated token/expectation to the fail-closed orchestrator. The real transport remains caller-supplied and is never generated or selected.

Output uses fixed LF bytes so the hashes recorded in both generation reports match the artifacts on Windows and Linux. Repeated generation is byte-identical. Tests reject altered handoff classification, relaxed route policy, changed runtime component, edited token source/report and duplicate authorization fields; failed generation removes stale capture-provision outputs. On Linux, the C harness maps only a temporary process buffer at the fixture address and runs supported, unsupported and replay paths through a fake transport. A complete host-side result is:

```text
M7_SMCCC_CAPTURE_PROVISIONING_PASS
```

Generated token and capture-provision sources remain under `out/generated`, absent from the DSC/INF and unusable with the current blocked physical-device evidence. This step performs no SMC, device command, persistent write, MMIO initialization or payload launch.

## Deterministic collector-capture serializer

Convert a future collector transcript into the sanitized manifest consumed by the SMCCC route gate:

```bash
python3 scripts/serialize-m7-smccc-feature-availability-capture.py \
  out/m7-secure-el3-handoff-state.txt \
  out/m7-smccc-collector-capture.txt \
  out/m7-smccc-el3-feature-availability-raw.txt \
  out/m7-smccc-capture-serialization.txt \
  out/m7-pre-sec-smccc-route-authorization.txt \
  out/m7-smccc-capture-provisioning.txt
```

Schema `IZZOS_M7_SMCCC_COLLECTOR_CAPTURE_V1` binds the exact handoff report, exact route-authorization report, canonical capture-provision digest, propagated single-use token digest, authorized buffer geometry and SHA-256 identities of the collector header, C state machine, AArch64 transport, emitter header/source and orchestrator header/source. The serializer revalidates both reports, recomputes the provision binding, and records the exact capture-provisioning report SHA-256 in the sanitized manifest. It accepts only `COMPLETE` with five canonical calls or `FEATURE_UNAVAILABLE` with the two discovery calls. It rejects version/call errors, reordered or additional calls, changed evidence/source identities, report or provision-binding changes, buffer changes, vendor/SiP actions, write/launch claims, and any direct `SCR_EL3`, `CPTR_EL3`, `MDCR_EL3`, GIC, ZCR or SMCR field. A failed serialization removes any stale raw manifest at the exact output path.

The output is deterministic and contains only the normalized feature-availability masks already defined by the Arm service. A successful serializer report is:

```text
M7_SMCCC_CAPTURE_SERIALIZATION_PASS
```

Round-trip tests feed both supported and unsupported serialized manifests into the existing SMCCC route gate. This proves format and binding behavior only; the transcript remains self-reported and does not authorize invoking the collector on the device.

## Standalone host-readiness audit

Summarize the complete internal-M7 report chain without confusing it with product-roadmap M7 or authorizing promotion:

```bash
python3 scripts/report-m7-standalone-readiness.py \
  out \
  out/m7-standalone-readiness.txt
```

The auditor requires 20 exact report classifications and verifies the available cross-report SHA-256 links from the SEC requirements and entry observation through extension, coherency, Secure EL3, route-token, capture-provisioning, serialization and final SMCCC reports. Missing reports, duplicate classifications, changed upstream bytes and unsupported promotion claims fail closed.

A complete host-only chain is classified:

```text
M7_HOST_CONTRACT_CHAIN_COMPLETE_DEVICE_EVIDENCE_REQUIRED
```

This status explicitly records that the product roadmap remains at `M1 — Non-Destructive UEFI Diagnostic Payload` while the internal engineering sequence is at M7. It still requires independently authenticated exact-device evidence and verified SEC/PrePi wrapper execution; DSC/FDF promotion, Android container construction and device launch remain blocked.

## Exact-device and recovery promotion audit

After the separate ADB and classic bootloader-fastboot captures have been merged, and exact-build recovery evidence passes the M2 recovery gate, bind those inputs to the host-readiness report offline:

```bash
python3 scripts/report-m7-device-promotion-readiness.py \
  out/m7-standalone-readiness.txt \
  out/m1-exact-device-evidence/M1_EXACT_DEVICE_EVIDENCE.txt \
  out/m2-recovery-evidence.txt \
  out/m7-device-promotion-readiness.txt
```

The audit requires the exact OnePlus 10T target and OxygenOS build, classic bootloader-fastboot, unlocked state, matching A/B slot, verified exact-stock recovery images, a verified hard-recovery status, and a route requiring neither persistent writes nor slot changes. It records the SHA-256 identity of all three inputs and fails closed on missing, duplicate, contradictory or unsafe fields.

A consistent chain is classified:

```text
M7_DEVICE_RECOVERY_EVIDENCE_CHAIN_BOUND_WRAPPER_EXECUTION_REQUIRED
```

This means only that the supplied files are internally consistent and their exact bytes are bound by the report. It does not cryptographically attest who collected them. Independent capture authenticity and actual SEC/PrePi wrapper execution remain blockers; DSC/FDF promotion, container construction and every device command remain unauthorized.

## SEC/PrePi wrapper execution assertion schema

The repository deliberately contains no SEC/PrePi wrapper implementation while its execution route remains unauthorized. A host-only verifier is available to fail closed on a future self-reported execution assertion without treating that assertion as proof:

```bash
python3 scripts/verify-m7-sec-prepi-wrapper-execution.py \
  out/m7-standalone-sec-entry-requirements.txt \
  out/m7-qualcomm-entry-observation.txt \
  out/m7-device-promotion-readiness.txt \
  out/non-integrated-sec-prepi-wrapper.bin \
  out/m7-sec-prepi-wrapper-execution-raw.txt \
  out/m7-sec-prepi-wrapper-execution.txt
```

The verifier binds the exact prerequisite reports and wrapper artifact bytes, requires the pre-wrapper register state to match the exact entry observation, and checks DTB preservation, zero `x1`–`x3`, masked exceptions, disabled MMU, stable timer state, bounded stack within temporary RAM, image coherency normalization and one non-returning transfer to a patched SEC/PrePi entrypoint. Duplicate fields, changed input or artifact bytes, a moved DTB register, enabled MMU, invalid stack range, MMIO, SMC, monitor changes, writes, slot changes or launch claims fail closed.

A structurally consistent assertion is classified:

```text
M7_SEC_PREPI_WRAPPER_EXECUTION_ASSERTION_SCHEMA_PASS_ROUTE_AUTHENTICITY_REQUIRED
```

This status remains self-reported. The verifier does not inspect the artifact's code semantics, authorize the execution route, establish final runtime-destination ownership, prove that execution occurred, or permit wrapper implementation/integration. DSC/FDF promotion, container construction and launch remain blocked.

## Final runtime-destination ownership gate

Mathematical gaps in the static Cape reserved-memory map are not safe placement evidence. A future exact-device snapshot must enumerate physical-memory ranges and exclusions for fixed and dynamic reserved memory, bootloader relocation, kernel, selected DTB, vendor ramdisk and framebuffer. Bind that snapshot to the exact wrapper assertion, FD capacity report, selected-DTB report and FD bytes:

```bash
python3 scripts/verify-m7-runtime-destination-ownership.py \
  out/m7-sec-prepi-wrapper-execution.txt \
  out/m7-fd-capacity.txt \
  out/m7-selected-dtb.txt \
  out/ovaltine-standalone/Ovaltine.fd \
  out/m7-runtime-ownership-snapshot.txt \
  out/m7-runtime-destination-ownership.txt
```

The verifier reproduces 64-bit range arithmetic host-side. It requires the FD, temporary RAM and stack to lie inside declared physical memory; the SEC/PrePi entrypoint to lie inside the FD; the stack to lie inside temporary RAM; and the preserved DTB address to lie inside the declared DTB exclusion. FD and temporary RAM must not overlap each other or any declared exclusion. Changed FD/report bytes, malformed or overlapping physical ranges, incomplete exclusion categories, duplicate fields, unresolved dynamic pools, an out-of-range entry/stack, or any write/launch claim fail closed.

A clear declared snapshot is classified:

```text
M7_RUNTIME_DESTINATION_OWNERSHIP_SCHEMA_PASS_AUTHENTICITY_FRESHNESS_REQUIRED
```

This result is deliberately limited to one self-reported capture instant. Runtime allocation ownership can change, so the snapshot must be independently authenticated and fresh at any separately authorized execution. It does not select a persistent PCD, authorize wrapper execution, promote DSC/FDF files, construct a container or authorize launch.

## Fresh one-shot execution-authorization readiness gate

Bind the exact ownership result to the wrapper and device-promotion reports, a five-minute-or-shorter UTC window, a single-use request and an explicit used-token ledger:

```bash
python3 scripts/verify-m7-one-shot-execution-authorization.py \
  out/m7-runtime-destination-ownership.txt \
  out/m7-sec-prepi-wrapper-execution.txt \
  out/m7-device-promotion-readiness.txt \
  out/m7-one-shot-execution-authorization-request.txt \
  out/m7-used-one-shot-token-ledger.txt \
  2026-08-25T00:01:00Z \
  out/m7-one-shot-execution-authorization-readiness.txt
```

The request schema is `IZZOS_M7_ONE_SHOT_EXECUTION_AUTHORIZATION_REQUEST_V1`. Its token is SHA-256 over the listed request fields other than `authorization-token-sha256`, rendered in the verifier's fixed field order as UTF-8 `key=value` lines with LF endings and a final LF. The token binds the exact three report hashes, raw ownership-snapshot hash, exact build and capture identity, UTC authorization window, 256-bit nonce, one-use count and all no-write/no-launch policy fields.

The verifier requires the capture to be no more than 300 seconds old at the explicitly supplied evaluation time, the authorization start to follow the capture, a positive window no longer than 300 seconds, and evaluation inside that window. It rejects malformed time, changed upstream bytes, duplicate request fields, a non-canonical token, more than one use, unsafe policy claims, malformed/duplicate ledger entries and any token already recorded in the supplied `IZZOS_M7_USED_ONE_SHOT_TOKEN_LEDGER_V1` ledger.

A fresh unused candidate is classified:

```text
M7_FRESH_ONE_SHOT_EXECUTION_TOKEN_READY_ATOMIC_CONSUMPTION_REQUIRED
```

This is deliberately readiness evidence rather than execution permission. The verifier neither authenticates the self-reported capture or declared project-owner authority nor writes the ledger. An independent authority must authenticate both and atomically record the token as used before any separately authorized wrapper invocation; otherwise concurrent checks could replay it. Wrapper execution, DSC/FDF promotion, container construction, payload launch and every device command remain unauthorized.

## Token-consumption receipt and execution-result binding

A future external executor must preserve both sides of the token-ledger transition and bind its self-reported result to the exact authorization chain and evidence bytes:

```bash
python3 scripts/verify-m7-token-consumption-execution-result.py \
  out/m7-one-shot-execution-authorization-readiness.txt \
  out/m7-one-shot-execution-authorization-request.txt \
  out/m7-used-token-ledger-before.txt \
  out/m7-used-token-ledger-after.txt \
  out/m7-token-consumption-receipt.txt \
  out/m7-wrapper-execution-evidence.bin \
  out/m7-wrapper-execution-result.txt \
  out/m7-token-consumption-execution-result-verification.txt
```

The host verifier requires the post-use ledger to be the exact pre-use bytes plus one canonical lowercase entry for the authorized token. The token must be absent before and present exactly once after. Schema `IZZOS_M7_ATOMIC_TOKEN_CONSUMPTION_RECEIPT_V1` binds both ledger hashes, the passing readiness report, authorization request, token and non-empty evidence artifact; it asserts a compare-and-append operation, one-to-zero invocation budget and ledger-only write scope. Consumption must occur after readiness evaluation and before authorization expiry.

Schema `IZZOS_M7_BOUND_WRAPPER_EXECUTION_RESULT_V1` then binds the same request, readiness report, token, receipt and evidence artifact. It permits only one asserted non-returning wrapper transfer within the authorization window and rejects SMC, MMIO, storage-write, slot-change, promotion, container or payload-launch claims. Changed artifacts, altered ledgers, duplicate token entries, expired consumption, multiple invocations, unsafe claims, missing bindings and duplicate fields fail closed.

A consistent supplied chain is classified:

```text
M7_TOKEN_CONSUMPTION_RESULT_SCHEMA_PASS_ATOMICITY_AUTHENTICITY_REQUIRED
```

Exact before/after bytes prove only the declared ledger transition, not that the external compare-and-append was atomic. Both atomicity and execution remain self-reported and not independently attested. This gate performs no ledger write or device command, cannot retroactively authorize an invocation, and does not permit DSC/FDF promotion, container construction or payload launch.

## Independent authority-attestation signature gate

Replace an unsigned self-report with a detached Ed25519 endorsement whose exact public key is pinned by a repository-reviewed manifest:

```bash
python3 scripts/verify-m7-authority-attestation.py \
  out/m7-token-consumption-execution-result-verification.txt \
  out/m7-trusted-authority-key-manifest.txt \
  out/m7-authority-public-key.pem \
  out/m7-authority-attestation-envelope.txt \
  out/m7-authority-attestation-signature.bin \
  2026-08-25T00:01:05Z \
  out/m7-authority-attestation-verification.txt
```

`IZZOS_M7_TRUSTED_AUTHORITY_KEY_V1` pins the SHA-256 of one Ed25519 public-key file, exact authority role and scope, a validity period of at most 366 days, repository trust-anchor source, external key custody and no-write/no-launch policy. The verifier rejects an unpinned or non-Ed25519 key, expired or declared-revoked key, duplicate or non-canonical manifest and verification outside the validity window.

The signed canonical `IZZOS_M7_AUTHORITY_ATTESTATION_ENVELOPE_V1` binds the complete token-consumption/result verification report, token, receipt, evidence-artifact digest, exact build and capture identity. It can endorse capture authenticity, atomic token consumption, wrapper-result authenticity and device-route authenticity only within the narrow bound-evidence scope. Attestation must follow the bound result and precede verification. Any changed byte, wrong key, truncated signature, duplicate field, altered upstream report or signed SMC/MMIO/write/launch claim fails closed. Signature verification uses OpenSSL `pkeyutl` with `-rawin`; tests create temporary Ed25519 keys and retain no private key.

A cryptographically valid endorsement is classified:

```text
M7_AUTHORITY_ATTESTATION_SIGNATURE_PASS_KEY_GOVERNANCE_REQUIRED
```

This proves that the holder of the pinned private key endorsed the exact envelope bytes. It does not prove private-key custody, revocation handling or physical-device truth to the verifier, retroactively authorize an execution route, or permit DSC/FDF promotion, container construction or payload launch.

## Authority-key revocation, rotation and anti-rollback governance

Bind a passing authority attestation to the exact currently active key, a separately pinned offline governance root, a signed rotation record and a repository-distributed monotonic checkpoint:

```bash
python3 scripts/verify-m7-key-rotation-governance.py \
  out/m7-authority-attestation-verification.txt \
  out/m7-active-authority-key-manifest.txt \
  out/m7-active-authority-public-key.pem \
  out/m7-previous-authority-public-key.pem \
  out/m7-previous-key-governance-state.txt \
  out/m7-key-governance-root-manifest.txt \
  out/m7-key-governance-root-public-key.pem \
  out/m7-authority-key-rotation-record.txt \
  out/m7-previous-key-handover-signature.bin \
  out/m7-governance-root-approval-signature.bin \
  out/m7-key-governance-anti-rollback-checkpoint.txt \
  2026-08-25T00:03:00Z \
  out/m7-key-rotation-governance-verification.txt
```

The canonical `IZZOS_M7_AUTHORITY_KEY_ROTATION_RECORD_V1` binds a positive governance epoch and sequence, the verifier-calculated digest of a non-empty previous-state artifact, revoked previous-key identity, active manifest/key identity, effective time and strict no-write/no-launch policy. `DUAL_CONTROL_SCHEDULED_HANDOVER` requires valid detached Ed25519 signatures from both the previous authority key and offline governance root. `ROOT_AUTHORIZED_COMPROMISE_REVOCATION` forbids relying on a potentially compromised previous key, requires an empty previous-key signature artifact and accepts only a governance-root signature with reason `COMPROMISE_RECOVERY`.

The canonical `IZZOS_M7_KEY_GOVERNANCE_ANTI_ROLLBACK_CHECKPOINT_V1` must pin the exact rotation-record SHA-256, previous-state digest, active key, governance root and the same minimum epoch/sequence. A lower, altered or mismatched checkpoint fails. The passing authority-attestation report must bind the newly active manifest and key; an attestation using the revoked key fails even if its older signature once verified. Tests also reject changed signed bytes, rogue previous/root signatures, failure to revoke the old key, duplicate fields and signed launch claims.

A consistent supplied governance state is classified:

```text
M7_KEY_ROTATION_GOVERNANCE_PASS_CHECKPOINT_DISTRIBUTION_REQUIRED
```

The verifier cannot discover whether a newer checkpoint exists elsewhere. Anti-rollback therefore still depends on distributing the latest repository-reviewed checkpoint and protecting the offline governance-root custody/recovery process. This gate performs no key or device write and does not authorize wrapper execution, promotion, container construction or launch.

## Checkpoint publication quorum and governance-root recovery policy

Require the currently pinned governance root and at least two of three independent publication witnesses to sign the exact same short-lived checkpoint publication and recovery-policy bytes:

```bash
python3 scripts/verify-m7-checkpoint-publication-root-recovery.py \
  out/m7-key-rotation-governance-verification.txt \
  out/m7-key-governance-anti-rollback-checkpoint.txt \
  out/m7-key-governance-root-manifest.txt \
  out/m7-key-governance-root-public-key.pem \
  out/m7-checkpoint-publication-root-recovery-policy.txt \
  out/m7-publication-witness-1-public-key.pem \
  out/m7-publication-witness-1-signature.bin \
  out/m7-publication-witness-2-public-key.pem \
  out/m7-publication-witness-2-signature.bin \
  out/m7-publication-witness-3-public-key.pem \
  out/m7-publication-witness-3-signature.bin \
  out/m7-recovery-custodian-1-public-key.pem \
  out/m7-recovery-custodian-2-public-key.pem \
  out/m7-recovery-custodian-3-public-key.pem \
  out/m7-governance-root-policy-signature.bin \
  2026-08-25T00:04:00Z \
  out/m7-checkpoint-publication-root-recovery-verification.txt
```

Canonical schema `IZZOS_M7_CHECKPOINT_PUBLICATION_AND_ROOT_RECOVERY_POLICY_V1` binds the exact passing key-governance report and checkpoint bytes, their epoch/sequence, a publication window of at most 900 seconds, three distinct Ed25519 witness keys, a two-of-three publication threshold, the currently pinned governance root and three distinct recovery-custodian keys. Every governance-root, witness and recovery public key must be distinct. The root signs the complete policy, and at least two pinned witnesses must independently sign those exact same bytes.

The recovery portion is policy only. It pins a future two-of-three custodian requirement for a new root manifest and requires the previous root to be revoked before replacement activation. It neither proves possession of the recovery private keys nor accepts or executes a recovery event. Changed checkpoint/report bytes, expired publication, fewer than two valid witness signatures, a rogue root signature, duplicate fields, reused keys or any root-and-quorum-signed write/launch claim fail closed.

A consistent fresh supplied quorum is classified:

```text
M7_CHECKPOINT_PUBLICATION_QUORUM_ROOT_RECOVERY_POLICY_PASS_EXTERNAL_DISTRIBUTION_REQUIRED
```

The verifier still cannot discover a newer checkpoint that was never supplied to it. External distribution diversity, witness availability, private-key custody and any future root-recovery event remain separate operational responsibilities. This gate performs no device command, key write, recovery activation, wrapper execution, promotion, container construction or launch.

## Governance-root recovery event gate

Validate a concrete root-replacement event against the exact previously approved recovery policy, without modifying repository or device trust state:

```bash
python3 scripts/verify-m7-governance-root-recovery-event.py \
  out/m7-checkpoint-publication-root-recovery-verification.txt \
  out/m7-checkpoint-publication-root-recovery-policy.txt \
  out/m7-key-governance-anti-rollback-checkpoint.txt \
  out/m7-previous-governance-root-manifest.txt \
  out/m7-previous-governance-root-public-key.pem \
  out/m7-replacement-governance-root-manifest.txt \
  out/m7-replacement-governance-root-public-key.pem \
  out/m7-governance-root-recovery-event.txt \
  out/m7-recovery-custodian-1-public-key.pem \
  out/m7-recovery-custodian-1-signature.bin \
  out/m7-recovery-custodian-2-public-key.pem \
  out/m7-recovery-custodian-2-signature.bin \
  out/m7-recovery-custodian-3-public-key.pem \
  out/m7-recovery-custodian-3-signature.bin \
  out/m7-replacement-root-event-signature.bin \
  out/m7-governance-root-recovery-checkpoint.txt \
  out/m7-replacement-root-checkpoint-signature.bin \
  2026-08-25T00:06:00Z \
  out/m7-governance-root-recovery-event-verification.txt
```

Canonical schema `IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_EVENT_V1` binds the exact prior publication verification, recovery policy and anti-rollback checkpoint; the revoked previous root; the replacement root manifest/key; and a strictly monotonic transition to the next governance epoch with sequence one. At least two of the three policy-pinned recovery custodians must sign the same event bytes. The replacement root must also sign the event to prove key possession.

The canonical `IZZOS_M7_GOVERNANCE_ROOT_RECOVERY_CHECKPOINT_V1` binds the event, previous checkpoint, replacement manifest/key, new epoch/sequence and revoked old-root state. A separate replacement-root signature covers the complete checkpoint. Changed bytes, fewer than two valid custodian signatures, a rogue replacement key, failure to revoke the old root, a non-advancing epoch, duplicate fields or any signed write/launch claim fail closed.

A consistent supplied recovery transition is classified:

```text
M7_GOVERNANCE_ROOT_RECOVERY_EVENT_PASS_REPUBLICATION_REQUIRED
```

This result validates supplied cryptographic evidence only. It does not alter a trust store, prove external private-key custody or make the recovered checkpoint globally current. The recovered checkpoint still requires fresh independent republication and witness quorum before distributed trust can move to it. No device command, wrapper execution, promotion, container construction or launch is authorized.

## Recovered-checkpoint republication quorum gate

Validate that the exact recovered checkpoint has been republished promptly under the replacement root and independently witnessed, without changing repository or device trust state:

```bash
python3 scripts/verify-m7-recovered-checkpoint-republication.py \
  out/m7-governance-root-recovery-event-verification.txt \
  out/m7-governance-root-recovery-event.txt \
  out/m7-governance-root-recovery-checkpoint.txt \
  out/m7-replacement-governance-root-manifest.txt \
  out/m7-replacement-governance-root-public-key.pem \
  out/m7-recovered-checkpoint-republication.txt \
  out/m7-republication-witness-1-public-key.pem \
  out/m7-republication-witness-1-signature.bin \
  out/m7-republication-witness-2-public-key.pem \
  out/m7-republication-witness-2-signature.bin \
  out/m7-republication-witness-3-public-key.pem \
  out/m7-republication-witness-3-signature.bin \
  out/m7-replacement-root-republication-signature.bin \
  2026-08-25T00:08:00Z \
  out/m7-recovered-checkpoint-republication-verification.txt
```

Canonical schema `IZZOS_M7_RECOVERED_CHECKPOINT_REPUBLICATION_V1` binds the exact passing recovery report, root-recovery event, recovered checkpoint, replacement-root manifest/key, revoked old-root state and new epoch/sequence. The replacement root must sign the complete record, and at least two of three distinct pinned republication witnesses must independently sign those same bytes within the 900-second republication window.

Changed checkpoint bytes, an unpinned or reused witness key, fewer than two valid witness signatures, a rogue replacement-root signature, an expired record, rollback of epoch or sequence, duplicate fields or any signed write/launch claim fail closed. A consistent supplied republication is classified:

```text
M7_RECOVERED_CHECKPOINT_REPUBLICATION_QUORUM_PASS_EXTERNAL_DISTRIBUTION_REQUIRED
```

This result proves quorum over the supplied record only. It cannot discover a newer checkpoint that was withheld, prove durable external distribution or authorize device activity. Independent distribution and monitoring remain operational responsibilities; no device command, key write, wrapper execution, promotion, container construction or launch is performed.

## Recovered-checkpoint external-distribution gate

Validate signed observations of the exact recovered checkpoint from three replacement-root-pinned external distribution channels, without contacting a network or changing repository or device trust state:

```bash
python3 scripts/verify-m7-recovered-checkpoint-external-distribution.py \
  out/m7-recovered-checkpoint-republication-verification.txt \
  out/m7-recovered-checkpoint-republication.txt \
  out/m7-governance-root-recovery-checkpoint.txt \
  out/m7-replacement-governance-root-manifest.txt \
  out/m7-replacement-governance-root-public-key.pem \
  out/m7-recovered-checkpoint-external-distribution-policy.txt \
  out/m7-replacement-root-distribution-policy-signature.bin \
  out/m7-distribution-channel-1-public-key.pem \
  out/m7-distribution-channel-1-receipt.txt \
  out/m7-distribution-channel-1-receipt-signature.bin \
  out/m7-distribution-channel-2-public-key.pem \
  out/m7-distribution-channel-2-receipt.txt \
  out/m7-distribution-channel-2-receipt-signature.bin \
  out/m7-distribution-channel-3-public-key.pem \
  out/m7-distribution-channel-3-receipt.txt \
  out/m7-distribution-channel-3-receipt-signature.bin \
  2026-08-25T00:09:00Z \
  out/m7-recovered-checkpoint-external-distribution-verification.txt
```

Canonical schema `IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_POLICY_V1` is signed by the replacement root and binds the exact passing republication report, republication record, recovered checkpoint, epoch/sequence and three distinct HTTPS channels. Each channel has a different operator identifier, origin host and Ed25519 key pin.

Each channel signs its own canonical `IZZOS_M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_RECEIPT_V1` receipt. All three receipts must bind the same policy and checkpoint, report exact SHA-256 availability, arrive within 3600 seconds of republication and be no more than 3600 seconds old at verification. A stale or delayed receipt, repeated channel identity, unpinned key, rogue signature, changed checkpoint, duplicate field or signed write/launch claim fails closed.

A consistent supplied three-channel distribution set is classified:

```text
M7_RECOVERED_CHECKPOINT_EXTERNAL_DISTRIBUTION_PASS_CONTINUOUS_MONITORING_REQUIRED
```

This result validates signed one-shot observations only. It performs no network request and cannot prove continuous availability or discover a newer checkpoint withheld from all supplied channels. Continuous independent monitoring remains a separate gate; no device command, key write, wrapper execution, promotion, container construction or launch is authorized.

## Still required before standalone DSC/FDF promotion

The following remain separate evidence gates:

- actual FD size and alignment from a concrete SEC/PEI/DXE composition;
- final runtime destination and FD base, plus exact Qualcomm FD-for-kernel replacement/relocation behavior beyond the bounded stock Linux arithmetic;
- independently authenticated Qualcomm entry observation and capture route beyond the schema-only snapshot gate;
- a passing exact pre-SEC non-secure EL2 route-authorization artifact for the non-integrated collector (current assisted-only recovery and candidate route do not pass), independently authenticated EL3-owned handoff evidence beyond the self-reported schema and optional sanitized SMCCC corroboration, the exact Qualcomm EL3/internal coherency implementation beyond the public PSCI/SMC boundary, and verified execution of the required SEC/PrePi wrapper;
- runtime GIC/timer/platform-init ownership and exception-level requirements beyond the bounded static-DTB enumeration;
- exact temporary Android boot-container construction only after the input-binding gate and Qualcomm semantics both pass;
- recovery and exact-device route authorization.

Storage writes, slot changes, flashing, and guessed MMIO initialization remain forbidden.
