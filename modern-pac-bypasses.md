# Modern PAC Bypass Techniques (Patched, Educational)

**Date:** 2026-11-13  
**Purpose:** Document how real-world PAC bypasses worked to inform future research.  
All techniques below are patched.

## 1. DarkSword / pois0nSword (CVE-2026-20700) — Patched iOS 26.3

**Pattern: Confused deputy via dyld**

The most elegant PAC bypass discovered in the wild. Instead of forging PAC signatures,
it tricks dyld — which legitimately holds PAC signing authority — into signing attacker-
controlled data.

### How it worked:

1. **Target:** `dyld4::RuntimeState.interposingTuplesAll` at RS+0xb8 (buffer pointer) and
   RS+0xc0 (count). These fields sit in `__TPRO_CONST` — a memory region that only dyld
   itself can write to (Thread Permission Read-Only).

2. **The trick:** Freeze a thread mid-`dlopen()` at the right point. Forge an `lsl::Vector`
   structure on the stack. dyld's `free()` implementation writes to RS+0xb8/RS+0xc0 as part
   of its normal deallocation logic — a confused deputy.

3. **Result:** Attacker controls the interposing tuple table. Every subsequent symbol
   resolution by dyld is hijacked.

4. **PAC signing:** ImageIO's lazy CMPhoto resolver provides PAC-signed `dlopen`/`dlsym`/
   `signPointer`. Uses `blraaz` (zero-context authenticate) so signed pointers can be reused
   at different addresses.

**Key lesson:** "Don't forge PAC — make the system sign for you."

Source: [varik.dev writeup](https://varik.dev/blog/jsc/pois0nsword-native-calls)

## 2. Predator Spyware — Signing Gadget in JSC

**Pattern: Find a PACIA instruction with controllable inputs**

Jamf's analysis of the Predator (Cytrox) iOS spyware revealed a PAC bypass that searches
for signing instructions in loaded frameworks.

### How it worked:

1. **Search:** `memmem()` for bytes `30 02 C1 DA` within 0x1000 bytes of
   `JSC::JSArrayBuffer::isShared()` in JavaScriptCore.

2. **Pattern found:** `PACIA X16, X17` — signs register X16 using X17 as context.

3. **Exploitation:** Build a 256-entry signing cache (one per top-byte PAC value).
   Each entry computed via `remotePACIA` calls. 512 total calls to fill the cache.

4. **Result:** Arbitrary pointer signing — any pointer can be PAC-signed by looking up
   or computing the right cache entry.

**Key lesson:** PAC signing instructions are everywhere (~15K in the kernel alone).
The challenge is finding one where you control both inputs.

Source: [Jamf analysis](https://www.jamf.com/blog/predator-spyware-ios-kernel-exploitation-engine/)

## 3. Coruna — GOT Swap Confused Deputy

**Pattern: Redirect PAC-authenticated calls through attacker-controlled data**

Discovered by NadSec/Google, targeting iOS 13–17.2.1.

### How it worked:

1. **Target:** Unsigned GOT (Global Offset Table) entries in Apple system frameworks.
   On older iOS, the GOT was in writable `__DATA` (not `__DATA_CONST`).

2. **Swap:** Replace a GOT entry with a pointer to attacker-controlled data.

3. **Trigger:** Cause the framework to make a PAC-authenticated call that reads the
   swapped GOT entry. The framework's own signing/verification logic processes the
   attacker's data through a legitimate code path.

4. **Additional technique:** "PACDB rolling-hash forgery algorithm" — details not public.

5. **PPL bypass:** Leverages CVE-2023-38606 (same bug as Operation Triangulation).

**Key lesson:** The gap between PAC-protected control flow and unprotected data flow is
the real attack surface. PAC signs pointers, not the data those pointers reference.

Source: [NadSec](https://www.nadsec.online/blog/coruna-technical-analysis),
[Google TAG](https://blog.google/threat-analysis-group/government-backed-actors-exploiting-zero-day-vulnerabilities/)

## Common Patterns

All three bypasses share a principle: **use the system's own signing authority** rather
than trying to forge signatures from scratch.

| Technique | Who signs? | What's controlled? |
|-----------|-----------|-------------------|
| DarkSword | dyld (via free() confused deputy) | Interposing tuples → symbol resolution |
| Predator | JSC (PACIA gadget in framework) | Register inputs to signing instruction |
| Coruna | Framework (authenticated call path) | GOT entries → call targets |

### The 2026 picture

On iOS 26.6.1 with SPTM+TXM:
- `__DATA_CONST` GOT is locked → Coruna-style GOT swaps dead
- TPRO hardens dyld's RuntimeState → DarkSword-style interposing dead (patched 26.3)
- JSC JIT hardening → Predator-style gadget scanning harder (but pattern still works)

The **confused deputy** principle remains the most promising approach for future bypasses.
The question is finding a new code path where:
1. A privileged component (dyld, kernel, coprocessor) signs data
2. The data being signed comes from attacker-controlled memory
3. The signing path hasn't been hardened against this specific attack
