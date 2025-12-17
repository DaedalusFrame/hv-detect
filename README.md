# hv-detect

A Windows kernel driver that probes for the presence of a hypervisor by stress-testing architectural edge cases around IDT storage/loading, paging, privilege transitions, and timing. It sets up an isolated “safety net” execution environment to run sensitive checks safely and reports pass/fail for each detection.

## What it does
- Initializes a controlled execution context (custom `GDT`, `IDT`, `TSS`, and CR3) via the project’s safety net utilities.
- Temporarily adjusts paging to allow supervisor access and maps required memory safely.
- Executes a suite of IDT-centric detections (`SIDT`/`LIDT`) and logs whether behavior matches bare‑metal expectations.

## Implemented detections

Detections are grouped into SIDT (store IDT) and LIDT (load IDT). Each check flags a failure when behavior deviates from architecturally expected bare‑metal results, which often indicates a hypervisor footprint.

### SIDT detections (`idt::storing`)
1. Lock prefix on `SIDT` should fault (`#UD`). If it does not or the vector differs, a hypervisor is suspected.
2. `SIDT` with an invalid (unmapped) memory operand should fault with `#PF`. Any other outcome indicates interference.
3. `SIDT` storing to a page present in TLB but unmapped in CR3 should succeed; an exception suggests emulation artifacts.
4. Timing: measure minimal `SIDT` latency via TSC; excessive/suspiciously adjusted timing implies virtualization.
5. Compatibility mode storage size: execute `SIDT` in 32‑bit compatibility mode and compare stored size (6 bytes expected). Storing 10 bytes hints at incorrect emulation.
6. Non‑canonical memory operand should cause `#GP`; divergent behavior indicates monitor involvement.
7. Non‑canonical operand via `SS` (stack) should cause `#SS`.
8. `SIDT` at CPL=3 with `CR4.UMIP=0` should go through; exception implies abnormal filtering.
9. `SIDT` at CPL=3 with `CR4.UMIP=1` should cause `#GP(0)`; different vector or error code suggests faulty handling.

### LIDT detections (`idt::loading`)
1. Lock prefix on `LIDT` should fault (`#UD`).
2. `LIDT` with an invalid (unmapped) operand should fault with `#PF`.
3. `LIDT` from a page resident in TLB but unmapped in CR3 should succeed; failure indicates emulation side effects.
4. Timing: measure minimal `LIDT` latency via TSC; excessive/adjusted timing implies virtualization.
5. Non‑canonical memory operand should cause `#GP`.
6. Non‑canonical operand via `SS` (stack) should cause `#SS`.
7. `LIDT` executed at CPL=3 should fault with `#GP(0)` regardless of `CR4.UMIP`; divergence points to incorrect filtering.

## Safety net components
- Custom `GDT` with kernel/user segments and a properly configured `TSS` and IST.
- Custom `IDT` with gates for relevant exception vectors and a central SEH‑aware handler.
- CPL switching (CPL 0/3) via `syscall`/`sysret`, with MSRs (`IA32_STAR`, `IA32_LSTAR`, `IA32_FMASK`) managed and restored.
- Compatibility mode execution helper to run 32‑bit shellcode safely.
- Physical memory utilities to construct and use a dedicated CR3, map/unmap pages, and adjust supervisor bits without global disruption.

## Output and reporting
Each detection logs pass/fail with indented messages and a summary per family. A “Failed detection N” typically indicates behavior inconsistent with bare metal and therefore a potential hypervisor presence.

## Scope
- Focused on IDT storage/loading and closely related paging/privilege behavior.
- No build or usage instructions are included here by design.