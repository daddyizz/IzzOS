/*
 * Transport only. This file is intentionally not referenced by the current
 * diagnostic DSC/INF. The caller must satisfy and authorize the collector's
 * non-secure EL2 precondition before this function can be selected.
 */

  .text
  .align  2
  .global M7SmcccInvokeAArch64
  .type   M7SmcccInvokeAArch64, %function

M7SmcccInvokeAArch64:
  stp     x29, x30, [sp, #-32]!
  mov     x29, sp
  str     x2, [sp, #16]
  smc     #0
  ldr     x2, [sp, #16]
  stp     x0, x1, [x2]
  ldp     x29, x30, [sp], #32
  ret

  .size   M7SmcccInvokeAArch64, .-M7SmcccInvokeAArch64
