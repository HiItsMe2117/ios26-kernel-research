# iOS 26.6.1 Kernel Security Research

Personal security research on an iPhone 16 Plus (iPhone17,4, A18, iOS 26.6.1).
Everything here is tested on my own device for educational purposes.

**Goal:** Understand the iOS 26 kernel exploit chain lifecycle end-to-end — from
bug discovery through KASLR defeat, kernel R/W primitives, and post-exploitation
on modern SPTM+PAC+TPRO hardware.

## What's Here

| Document | TL;DR |
|----------|-------|
| [Chain Design](chain-design.md) | Full exploit chain architecture and stage-by-stage status |
| [PAC Key Extraction](pac-key-extraction.md) | Disassembled the context switch — B-key derivation is `rop_pid, +1, +2, +3` |
| [PAC Gadget Census](pac-gadget-census.md) | 16,062 PAC instructions catalogued; 1,670 sign-and-store gadgets found |
| [Post-Exploitation Analysis](post-exploitation.md) | What's dead and what's viable on SPTM devices |
| [Kernel Read Primitive](kernel-read.md) | getsourcefilter proven on-device (200 entries) |
| [Kernel Write Primitive](kernel-write.md) | RB-tree rotation write — binary-verified, no PAC |
| [PoC Survey](poc-survey.md) | Analysis of 4 recent iOS 26/27 PoCs + exploitation patterns |
| [Modern PAC Bypasses](modern-pac-bypasses.md) | DarkSword, Predator, Coruna — how they worked and what we learn |
| [Sandbox Escape](sandbox-escape.md) | worse_query containermanagerd TOCTOU — unpatched userland sandbox escape |

## The Chain (Nov 16 — updated)

```
AVE2 AssignUnitPreempt OOB Read    ← KASLR bypass (unconfirmed, probe running)
  (CVE-2026-112466, NTL=16463)
       |
       v
  Kernel VA in HEVC VPS/SPS/PPS
  → KASLR slide
       |
       +─────────────────────────────+
       |                              |
       v                              v
  ICMP6_FILTER write (confirmed)   AVE2 OOB write (CVE-2026-112468–470)
  → ucred uid=0 → root              → heap spray → kernel R/W
                                     → physmap SpringBoard __DATA
                                     → IMP overwrite → battery tweak
```

**Dead ends:** IGMP UAF (CVE-2026-86916) — patched in 26.6.1. SysBumps KASLR — SPTM
blocks on A18. OOL descriptor leak (CVE-2026-65405 OOL) — 26.7.0-only code path.
IOGPU race (CVE-2026-43743) — PAC blocks post-UAF. AVE2 DPB write — DART blocks.

See [kaslr-bypass-research.md](kaslr-bypass-research.md) for the full KASLR history.

## Key Findings

### ICMP6_FILTER Write Primitive — Confirmed (Nov 15)

`setsockopt(IPPROTO_ICMPV6, ICMP6_FILTER, 32B)` writes exactly 32 bytes of controlled
data to `*in6p_icmp6filt`. Fully reachable from app sandbox (DGRAM IPPROTO_ICMPV6 socket).
No PAC on the write path. Without KASLR, can't aim it; with KASLR, targets ucred uid/gid
or any 32-byte kernel object.

### PAC Key Derivation is Trivially Simple (Nov 13)

Disassembled `set_process_dependent_keys_and_sync_context` at `0xfffffff00a651910` in the
iOS 26.6.1 kernelcache. The B-key "derivation" is just consecutive integers from `rop_pid`:

```
APIBKeyLo_EL1 = rop_pid           // thread+0x1C0
APIBKeyHi_EL1 = rop_pid + 1
APDBKeyLo_EL1 = rop_pid + 2
APDBKeyHi_EL1 = rop_pid + 3
```

Written directly via MSR — no SPTM call, no hash, no transform. A-keys use Apple
proprietary KernelKey registers (`SYS_APL_KERNELKEYLO/HI_EL1`) with the same `+1` pattern
from `jop_pid` (thread+0x1C8). Standard APIA/APDA registers are never written by XNU —
they're set by SPTM at boot and immutable from EL1.

**Complication:** Apple uses a custom PAC cipher (not QARMA), so extracting key register
values may not be sufficient for offline signature forgery. Empirical testing needed.

### Every Post-Exploitation Path is Dead Except Data-Only

On iOS 26.6.1 with SPTM:
- Credentials: RO zones (SPTM-backed)
- Sandbox kext: 0 writable `__DATA` refs
- Pipe buffers: PAC-signed (AUTDA)
- IPC ports: PAC + zone_require
- Code signing: `__DATA_CONST` (locked)
- PAC density: ~2.4 data sign ops per function

The only viable path is **PAC-preserving data modification** via ICMP6_FILTER — writing
32 bytes to a kernel object while preserving its PAC-signed vtable.

## Device

- iPhone 16 Plus (iPhone17,4, D48AP)
- iOS 26.6.1 (23G83)
- A18 (SPTM + TXM + PAC)
- Kernelcache: `__TEXT_EXEC` at VA `0xfffffff00827c000`, file offset `0x01278000`, size `0x02c68000`

## Status (Nov 16)

| Component | Status |
|-----------|--------|
| KASLR bypass | **Blocked** — AVE2 OOB read probe submitted, results pending |
| ICMP6_FILTER write | **Confirmed** on device (needs KASLR to aim) |
| getsourcefilter read | Confirmed API, needs UAF to corrupt tree (UAF dead) |
| Sandbox escape (worse_query) | Confirmed — orthogonal to kernel chain |
| IGMP UAF (CVE-2026-86916) | **DEAD** — patched in 26.6.1 |
| SysBumps KASLR | **DEAD** — SPTM blocks on A18 |

The chain is gated on KASLR. See [Chain Design](chain-design.md) and
[KASLR Bypass Research](kaslr-bypass-research.md) for full status.

## References

- [XNU PAC overview](https://gist.github.com/networkextension/24bac6ffb8cb875e1d8b4f8672cdba3b)
- [Project Zero PAC analysis](https://projectzero.google/2019/02/examining-pointer-authentication-on.html)
- [pois0nSword writeup](https://varik.dev/blog/jsc/pois0nsword-native-calls)
- [Predator PAC bypass](https://www.jamf.com/blog/predator-spyware-ios-kernel-exploitation-engine/)
- [scrw-lab](https://github.com/drawjoshua31/scrw-lab) — data-only approach validation
- [Apple Security Guide](https://support.apple.com/guide/security/operating-system-integrity-sec8b776536b/web)
