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

## Still required before standalone DSC/FDF promotion

The following remain separate evidence gates:

- actual FD size and alignment from a concrete SEC/PEI/DXE composition;
- final runtime destination and FD base, plus exact Qualcomm FD-for-kernel replacement/relocation behavior beyond the bounded stock Linux arithmetic;
- independently authenticated Qualcomm entry observation and capture route beyond the schema-only snapshot gate;
- Secure EL3 extension-state evidence for an EL2 entry, independently validated Qualcomm coherency-mechanism evidence and verified execution of the required SEC/PrePi wrapper beyond the bounded assertion schema;
- runtime GIC/timer/platform-init ownership and exception-level requirements beyond the bounded static-DTB enumeration;
- exact temporary Android boot-container construction only after the input-binding gate and Qualcomm semantics both pass;
- recovery and exact-device route authorization.

Storage writes, slot changes, flashing, and guessed MMIO initialization remain forbidden.
