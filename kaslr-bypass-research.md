# KASLR Bypass Research — iOS 26.6.1 (A18)

**Last updated:** 2026-11-16  
**Current status: No confirmed bypass. AVE2 OOB read is the leading candidate.**

---

## Summary Table

| Approach | CVE | Status | Killed by |
|----------|-----|--------|-----------|
| SysBumps TLB side-channel | CVE-2024-54531 | **DEAD** | SPTM blocks speculative TTBR1 walk on A18 |
| OOL descriptor stale sp+208 | "CVE-2026-65405" (mislabeled) | **DEAD** | 26.7.0-only code path, never in 26.6.1 |
| host_info/proc_info uninit residue | CVE-2026-65405 (real) | **Needs re-probe** | Probe incomplete — host_statistics section empty |
| AVE2 OOB read → VPS/SPS/PPS | CVE-2026-112466 | **Leading candidate** | Unconfirmed — wrong NTL used in prior probe |

---

## SysBumps — DEAD (killed Nov 13)

**CVE-2024-54531.** Exploits timing difference between TLB hits and misses on kernel virtual
addresses to infer which kernel pages are mapped, defeating KASLR.

**What we tried:**
- 7 syscalls used as probes: `chdir`, `access`, `stat`, `lstat`, `open`, `readlink`, raw `syscall(12)`
- Interleaved A/B comparison: scan known-mapped VA vs. unknown VA, alternating
- 1000 calls per batch, mach_absolute_time at 24MHz (41.67ns/tick)

**Result:** Median timing difference = 0 ticks. Range: [-1, +1] ticks across all conditions.

**Nov 7 false positive:** An earlier batch run showed 55–70 ticks vs. 47–53 ticks "gap". The
interleaved A/B method proved this was a monotonically decreasing warmup gradient — higher
address values happened to come later in the batch, not because of kernel mapping status.

**Root cause:** SPTM runs at EL2 and prevents speculative TLB walks of TTBR1_EL1 from EL0.
The fundamental timing oracle the attack relies on does not exist on A18/iOS 26.

---

## OOL Descriptor sp+208 — DEAD (killed Nov 16)

**Mislabeled as CVE-2026-65405 in earlier notes.** Not a real CVE on 26.6.1.

**Hypothesis:** `ipc_kmsg_copyout_ool_descriptor` in XNU stores a kernel pointer to `sp+208`
at some point during OOL message handling. If a helper function returns 0 (error path), sp+208
is never zeroed before the receive buffer is returned to userspace — leaking the kernel pointer.

**Binary analysis (Nov 16):** The vulnerable code path — a 260-byte block where a kernel
pointer from an internal table gets ORR'd into the user receive buffer — **does not exist in
iOS 26.6.1**. That block was introduced during 26.7.0 development and immediately patched
with `STR wzr, [sp, #0xd0]` before 26.7.0 shipped.

The `ipc_kmsg_copyout_ool_descriptor` in 26.6.1 (VA `0xfffffff00a66a518`, 4256 bytes):
- sp+208 is written with `xzr` (zero) or `w27` (user-controlled OOL size, 32-bit)
- sp+208 is **never read back** anywhere in the function
- No kernel pointer ever reaches sp+208

**Time spent:** ~3 hours chasing this across 3 probe versions. The lesson: verify
the vulnerable code path exists in the target kernel before probing.

---

## host_info / proc_info Uninit — Needs Re-Probe

**Real CVE-2026-65405.** Reporter: Billy Jheng Bing Jhong + Pan Zhenpeng (@Peterpan0927),
STAR Labs SG. Fixed in iOS 26.7 (Sep 14 2026). "An app may be able to determine kernel
memory layout." CWE-457: uninitialized variable.

**What we know:**
- Apple describes this as returning kernel pointer residue from an uninitialized struct field
- The API is host_info or proc_info (from STAR Labs attribution pattern — they typically find
  mach_host/task info leaks)
- The fix is "improved memory handling" in a kernel struct initialization
- Confirmed unpatched on 26.6.1 by Apple's advisory

**What we probed (probe: `kaslr_targeted.py`, Nov ~9):**
- `host_info` flavors 1–25: no kernel pointers
- `host_statistics` flavors 1–10: **empty section in log** — all flavors likely returned KERN_INVALID_ARGUMENT; this section was never actually tested
- `proc_info(callnum=2)` flavors 1–20: found `0xffffffff00000000` at offset +104 for flavors 2, 3, 18 — these are routing/CIDR sentinels (INADDR_BROADCAST pattern), NOT kernel text addresses
- `proc_info(callnum=3)` PIDFDINFO, callnum=4, etc.: empty sections in log
- `mach_vm_region_recurse`: section appeared empty (may have crashed)

**Problem with the probe:**
- Bounds used: `0xfffffff000000000 ≤ q ≤ 0xffffffffffffffff` (too broad, catches sentinels)
- `host_statistics64` and `mach_vm_region_recurse` sections never actually ran
- Probe did not test: `task_info` with extended flavors, `processor_info`, `mach_port_kernel_object`

**Re-probe needed:**
- Tighter kernel pointer bounds: `0xfffffff000000000 ≤ q ≤ 0xfffffff0ffffffff` (kernel text range)
- Test `host_statistics64` explicitly (call it with try/except, log every KERN_* error code)
- Two-pass: run same API twice, compare values — randomized value = KASLR leak
- Target struct sizes just above what the kernel says the struct is (probe for padding beyond declared size)

---

## AVE2 OOB Read → VPS/SPS/PPS — Leading Candidate

**CVE-2026-112466.** Hcamael + 章鱼哥@aipy. OOB read in `AVEVideoEncoder`.
Apple impact: "Terminate OR **read kernel memory**". Fix: "Improved input validation".
Patched in iOS 26.7.2. **Unpatched on 26.6.1.**

**The primitive:**

In `AVE_DLB::AssignUnitPreempt` (kext offset `0x53a6d8`):
```asm
0x53aa0c: ldr w11, [x20, #0x28]         ; slot = cmd->field_0x28  ← UNVALIDATED
0x53aa14: orr x11, x12, x11, lsl #5     ; x11 = 8 | (slot<<5)
0x53aa20: add x16, x8, x11              ; eu_base + 8 + 32*slot
0x53aa2c: ldr x8, [x12]                 ; ← CPU-side OOB READ (NOT DART)
0x53aa30: cmp x10, x8                   ; bounds check AFTER the read
```

This is a **CPU-side kernel read** — the kernel kext reads adjacent memory, not the
AVE2 firmware DMA. DART IOMMU is irrelevant here (that only protects firmware DMA).

**Why it's different from the DPB path (CVE-2026-112468–470, now dead):**
- DPB overflow: 32-bit integer wraps in firmware → firmware DMA writes OOB → DART blocks
- AssignUnitPreempt OOB: unvalidated `cmd->field_0x28` → CPU-side kernel `ldr` → no DART

**KASLR hypothesis:**
When the OOB-read value at `eu_base + 8 + 32*OOB_SLOT` is an adjacent kernel heap pointer,
that value flows into HEVC parameter set (VPS NAL unit) construction. The VPS bytes return
to userspace in the `VTCompressionSession` encode callback's `CMSampleBuffer` →
`CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 0 /*VPS*/, ...)`.

Scan returned VPS bytes for 8-byte sequences with `0xfffffff0` prefix = kernel text pointer.

**Trigger conditions (from exploit_chain_design.md):**
- Codec: HEVC (`hvc1`)
- Resolution: 1280×720
- `encoderSpec = {RCMode: 20, EncoderUsage: 1}` passed to `VTCompressionSessionCreate`
- `NumberOfTemporalLayers = 16463` (NOT 16462 — that's the safe boundary)
- 2+ frames required (frame 0 is in-bounds, frame 1 triggers OOB)

**Prior probe failure:**
`ave2_sbuf_leak.py` used NTL=16462 (safe). No OOB triggered. Frames were dropped
(`kVTEncodeInfo_FrameWasDropped`, info=0x1) before reaching hardware. The
`encoderSpec` dict was also missing (`None` passed).

**Current status:** Fixed probe (`probe_ave2_sbuf_v2.py`) submitted to device Nov 16.
Results pending.

---

## Notes on the 26.6.1 KASLR Landscape

As of November 2026, no public KASLR bypass exists for iOS 26.6.1 on A18. The public
jailbreak landscape:
- **Dopamine 3.0 / Momentarius**: A12/A13 only, iOS 26.0–26.0.1
- **Titan**: A14–A17, iOS 16.5.1–17.3.1 only (AGX hibernation trick, patched in 17.4b4)
- **No public A18/iOS 26 bypass**

This means our chain must implement its own KASLR bypass — AVE2 OOB read is the current
best candidate. CVE-2026-65405 (STAR Labs) is the backup if the AVE2 path causes a panic
rather than a silent read.
