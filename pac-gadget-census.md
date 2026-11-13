# PAC Signing Gadget Census — iOS 26.6.1 Kernelcache (A18)

**Date:** 2026-11-13  
**Kernelcache:** 23G83, iPhone17,4  
**Region scanned:** `__TEXT_EXEC` (46.5MB, 0x02c68000 bytes)

## Instruction Counts

| Instruction | Count | Notes |
|---|---|---|
| PACIA Xd, Xn | 15,128 | 15,124 are X16,X17 (indirect call trampolines) |
| PACDA Xd, Xn | 2 | Self-referential (X9,X9 and X8,X8) |
| PACIB Xd, Xn | 0 | Not used in kernel |
| PACDB Xd, Xn | 182 | Data pointer signing — the interesting set |
| PACIZA Xd | 750 | All X16 (zero-context instruction signing) |
| PACDZA / PACIBZ / PACDBZ | 0 | Not used in kernel |
| **Total** | **16,062** | |

## PACIA X16, X17 — The Ubiquitous Trampoline

12,115 instances of the standard indirect call pattern. This is how the kernel signs
call targets before branching.

**Key finding:** 1,670 of these are followed by `STR X16` (store the signed value to memory)
rather than `BR X16` or `BLR X16` (branch to it). These are **signing oracles** — they
compute a PAC signature and write it to a controlled memory location.

Example:
```
0xfffffff00827e118: PACIA X16, X17
0xfffffff00827e11c: STR X16, [X21, #176]    ; signed value → memory
```

The remaining ~10,445 are the normal call pattern (sign then branch). Not useful as gadgets.

## Non-X16 PACIA — All in SPTM Area

Only 4 PACIA instructions use registers other than X16. All are in the SPTM/exception
vector area (~`0xfffffff00a650000`), all use X31 (SP) as context. Not controllable from
kernel R/W.

## PACDB Sign-and-Store Helpers

103 candidates where PACDB is followed by STR — actual helper functions with clean calling
conventions that sign a data pointer and write the result to memory.

### Notable gadgets:

```
0xfffffff008d16844:
    PACDB X8, X1           ; sign X8 using X1 as context
    STR X8, [X0, #0]       ; store to [X0]
    STR X8, [X0, #16]      ; store to [X0+16]
    RET
    ; Interface: X0=output addr, X1=context, X8=value to sign

0xfffffff009c528b8:
    PACDB X8, X1
    STR X8, [X0, #0]
    RET
    ; Same shape, single store

0xfffffff00a604408:
    PACDB X8, X8           ; self-referential — pointer is its own context
    STR X8, [X1, #0]
    RET

0xfffffff00ade1af0 cluster (~0x56a0 range):
    PACDB X9, X0           ; multiple variants with different context regs
    STR X9, [X8, #8]
    RET
    ; Also variants: PACDB X9,X1 and PACDB X9,X2
```

## The Chicken-and-Egg Problem

These gadgets exist and have clean interfaces, but **using them requires redirecting kernel
code execution to the gadget address**. That requires PAC bypass — which is what we're
trying to achieve. Circular dependency.

### Resolution paths:

1. **Key extraction** — If we can extract PAC keys from kernel memory (see
   [pac-key-extraction.md](pac-key-extraction.md)) and reverse the cipher, we don't need
   the gadgets at all. We can forge signatures offline.

2. **Confused deputy** — Find kernel code paths where a PACDB/AUTDB operation loads BOTH
   the signed value AND its context from memory we can corrupt. If both come from the same
   corrupted heap object, we can construct a valid pair without knowing the key.

3. **Data-only approach** — Bypass PAC entirely by only modifying unsigned data fields.
   This is what our ICMP6_FILTER battery tweak does — it preserves PAC-signed bytes and
   only modifies the unsigned `value` field of an OSNumber.

## Method

Scanned the full `__TEXT_EXEC` region for PAC instruction encodings:

```python
# ARM64 PAC instruction encodings (mask out Rt, bottom 5 bits)
PACIA_X16_X17 = 0xDAC10230  # full encoding for PACIA X16, X17
PACDB_MASK    = 0xFFFFFC00  # PACDB Xd, Xn: 0xDAC10D00 | (Xn << 5) | Xd
PACIZA_MASK   = 0xFFFFFFE0  # PACIZA Xd:    0xDAC123E0 | Xd
```

For sign-and-store patterns, checked the instruction following each PAC instruction:
if `STR` (encoding `0xF900xxxx` for 64-bit unsigned offset), the signed value goes to memory
instead of being used as a branch target.
