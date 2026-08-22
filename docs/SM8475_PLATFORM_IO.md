# SM8475 / Cape Platform I/O Map

Status: **source-verified, runtime validation pending**

This file records platform I/O resources obtained directly from the OnePlus-published `qcom/cape.dtsi` on the OnePlus 10T 5G SM8475 branch. The initial IzzOS EDK2 payload remains read-only and must not issue UFS write operations.

## Debug UART hand-off

The Cape DTS declares the chosen stdout path as:

`/soc/qcom,qup_uart@99c000:115200n8`

This gives the bring-up firmware a source-verified candidate for early serial logging. The complete UART register/clock/pinctrl configuration still needs to be extracted and validated before IzzOS initializes the UART itself.

## Embedded UFS

Cape aliases the embedded storage controller as:

`ufshc1 = &ufshc_mem`

### UFS PHY

| Resource | Base | Size |
|---|---:|---:|
| `ufsphy_mem` | `0x01D80000` | `0x00002000` |

The DTS declares two lanes per direction.

### UFS host controller and inline crypto resources

| DTS reg-name | Base | Size |
|---|---:|---:|
| `ufs_mem` | `0x01D84000` | `0x00003000` |
| `ufs_ice` | `0x01D88000` | `0x00008000` |
| `ufs_ice_hwkm` | `0x01D90000` | `0x00009000` |

Interrupt:

- GIC SPI **265**, level-high

The node references `ufsphy_mem` and uses a 19.2 MHz device reference clock according to the source comment.

## SRAM

Cape defines an MMIO SRAM region:

| Resource | Base | Size |
|---|---:|---:|
| `sram` | `0x17D09400` | `0x00000400` |

It contains an SCP shared-memory subregion at offset zero with size `0x400`.

## Safety classification

For M0/M1:

- UFS host/PHY addresses are **VERIFIED_FROM_DTS**.
- UFS initialization sequence is **UNKNOWN**.
- UFS clock/reset sequencing is **NOT YET PORTED**.
- UFS reads are **NOT YET ENABLED**.
- UFS writes are **FORBIDDEN**.
- ICE/HWKM must not be touched until the Qualcomm secure-world requirements are understood.
- UART base is visible from the chosen path, but direct firmware initialization remains **NOT YET VALIDATED**.

## Source

Repository:

`OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8475`

Branch:

`oneplus/sm8475_s_12.1_oneplus_10t_5g`

File:

`kernel_platform/qcom/proprietary/devicetree/qcom/cape.dtsi`

The values in this document must still be cross-checked against the exact target phone's runtime DT/boot state before they become active EDK2 platform constants.