# PAC Key Extraction from Kernel Memory

**Date:** 2026-11-13  
**Device:** iPhone 16 Plus, iOS 26.6.1 (A18)  
**Status:** Key register values extractable. Apple custom cipher complicates offline forgery.

## Discovery

By disassembling the iOS 26.6.1 kernelcache's context switch code, I found that the PAC B-key
"derivation" from `rop_pid` to actual hardware register values is trivially simple — just
consecutive integers.

## Context Switch Disassembly

The function `set_process_dependent_keys_and_sync_context` lives at `0xfffffff00a651910`.
Here's the annotated B-key loading sequence:

```
0xfffffff00a651910: LDR X3, [X0, #432]        ; X3 = thread->cpu_data (offset 0x1B0)
0xfffffff00a651918: LDR X1, [X0, #448]        ; X1 = thread->rop_pid  (offset 0x1C0)
0xfffffff00a65191c: LDR X2, [X3, #512]        ; X2 = cpu_data->cached_rop_key (0x200)
0xfffffff00a651920: CMP X1, X2                ; same process? skip reload
0xfffffff00a651924: B.EQ skip

0xfffffff00a651928: MSR APIBKeyLo_EL1, X1     ; APIBKeyLo = rop_pid
0xfffffff00a65192c: ADD X2, X1, #1
0xfffffff00a651930: MSR APIBKeyHi_EL1, X2     ; APIBKeyHi = rop_pid + 1
0xfffffff00a651934: ADD X2, X2, #1
0xfffffff00a651938: MSR APDBKeyLo_EL1, X2     ; APDBKeyLo = rop_pid + 2
0xfffffff00a65193c: ADD X2, X2, #1
0xfffffff00a651940: MSR APDBKeyHi_EL1, X2     ; APDBKeyHi = rop_pid + 3
0xfffffff00a651944: ADD X2, X2, #1
0xfffffff00a651948: ADD X2, X2, #1            ; skip +4
0xfffffff00a65194c: MSR S3_4_C15_C13_6, X2   ; Apple IMP-DEF = rop_pid + 5
0xfffffff00a651950: ADD X2, X2, #1
0xfffffff00a651954: MSR S3_4_C15_C13_7, X2   ; Apple IMP-DEF = rop_pid + 6
0xfffffff00a651958: STR X1, [X3, #512]        ; update cache
```

Then the A-key (KernelKey) loading:

```
0xfffffff00a651960: LDR X1, [X0, #456]        ; X1 = thread->jop_pid  (offset 0x1C8)
0xfffffff00a651964: LDR X2, [X3, #520]        ; X2 = cpu_data->cached_jop_key (0x208)
0xfffffff00a651968: CMP X1, X2
0xfffffff00a65196c: B.EQ skip

0xfffffff00a651970: MSR S3_4_C15_C1_0, X1     ; KernelKeyLo = jop_pid
0xfffffff00a651974: ADD X2, X1, #1
0xfffffff00a651978: MSR S3_4_C15_C1_1, X2     ; KernelKeyHi = jop_pid + 1
0xfffffff00a65197c: STR X1, [X3, #520]        ; update cache
```

This pattern is confirmed across all 4 entry points in the kernelcache (`0xfffffff00a651928`,
`0xfffffff00a6519d8`, `0xfffffff00a651bc4`, `0xfffffff00a651e20`).

## Key Architecture

### B-keys (ROP/data protection)
Written to **standard ARM PAC registers** via MSR. Per-process, derived from `rop_pid`:

| Register | Value |
|----------|-------|
| APIBKeyLo_EL1 | `rop_pid` |
| APIBKeyHi_EL1 | `rop_pid + 1` |
| APDBKeyLo_EL1 | `rop_pid + 2` |
| APDBKeyHi_EL1 | `rop_pid + 3` |

### A-keys (JOP/instruction protection)
Standard APIA/APDA registers are **never written by XNU** — set by SPTM at boot, immutable.

Instead, XNU writes **KernelKey** registers (Asahi Linux naming: `SYS_APL_KERNELKEYLO/HI_EL1`):

| Register | Value |
|----------|-------|
| S3_4_C15_C1_0 (KernelKeyLo) | `jop_pid` |
| S3_4_C15_C1_1 (KernelKeyHi) | `jop_pid + 1` |

KernelKey is an additional diversifier mixed into PAC computation when `KernKeyEn` is
enabled in `APCTL_EL1` (S3_4_C15_C0_4). This only affects kernel-mode PAC operations.

### Undocumented registers

| Register | Value | Notes |
|----------|-------|-------|
| S3_4_C15_C13_6 | `rop_pid + 5` | Not in any public docs or Asahi wiki |
| S3_4_C15_C13_7 | `rop_pid + 6` | Purpose unknown |

## Thread Struct Offsets (compiled, iOS 26.6.1 A18)

| Offset | Size | Field |
|--------|------|-------|
| +0x1B0 (432) | 8 | cpu_data pointer |
| +0x1C0 (448) | 8 | `rop_pid` — B-key seed |
| +0x1C8 (456) | 8 | `jop_pid` — KernelKey seed |

## XNU Source Confirmation

From [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu) `genassym.c`:

```c
#if defined(HAS_APPLE_PAC)
DECLARE("TH_ROP_PID", offsetof(struct thread, machine.rop_pid));
DECLARE("TH_JOP_PID", offsetof(struct thread, machine.jop_pid));
DECLARE("TASK_ROP_PID", offsetof(struct task, rop_pid));
DECLARE("TASK_JOP_PID", offsetof(struct task, jop_pid));
DECLARE("CPU_ROP_KEY", offsetof(cpu_data_t, rop_key));
DECLARE("CPU_JOP_KEY", offsetof(cpu_data_t, jop_key));
#endif
```

From `osfmk/arm/task.h`:

```c
#define TASK_ADDITIONS_PAC \
    uint64_t rop_pid; \
    uint64_t jop_pid; \
    uint8_t disable_user_jop;
```

Both `rop_pid` (B-keys) and `jop_pid` (KernelKey) are plain `uint64_t` fields. `rop_pid`
is per-process (random at creation, inherited on fork). `jop_pid` is tied to the shared
region — all arm64e processes on the same shared cache share the same value.

## The Cipher Complication

Apple does **not** use the standard QARMA cipher for PAC computation. The cipher is
unpublished, and there may be a per-boot diversifier mixed in at the hardware level.

This means knowing the key register values (extractable via kernel read) may not be
sufficient for offline PAC forgery. The register values are the **inputs** to the cipher,
but reproducing the cipher's output requires knowing the algorithm.

### Empirical Test Plan

Once kernel R/W is achieved:

1. Read a known PACDB-signed pointer from kernel heap (e.g., vtable)
2. Read the unsigned value (strip PAC bits)
3. Read `rop_pid` from thread struct at +0x1C0
4. Compute APDB key: Lo=`rop_pid+2`, Hi=`rop_pid+3`
5. Try QARMA-64 and known variants — compare against the real signature
6. If reproduction succeeds: full offline PAC forgery is possible
7. If not: pivot to kernel signing oracle (force the kernel to sign for us)

## What This Means

**Best case:** The custom cipher is reversible from key+context+pointer, and extracting
`rop_pid` gives us full PACIB/PACDB forgery capability. This would be a complete PAC bypass.

**Worst case:** The cipher requires additional unknown state. We still know where the keys
live and what they contain, which dramatically narrows the attack surface. And the
ICMP6_FILTER data-only path works regardless of PAC (it preserves signed fields instead
of forging them).

## How to Reproduce

1. Extract the iOS 26.6.1 kernelcache for iPhone17,4 (build 23G83)
2. Locate `__TEXT_EXEC`: file offset `0x01278000`, VA `0xfffffff00827c000`, size `0x02c68000`
3. Search for MSR instructions targeting PAC key registers:
   - `APIBKeyLo_EL1` encoding: `0xD518214x`
   - `APIBKeyHi_EL1` encoding: `0xD518216x`
   - `APDBKeyLo_EL1` encoding: `0xD518224x`
   - `APDBKeyHi_EL1` encoding: `0xD518226x`
4. All 16 hits cluster around `0xfffffff00a651900` — that's the context switch
5. Disassemble backward from the first MSR to see the LDR source (thread struct offset)
