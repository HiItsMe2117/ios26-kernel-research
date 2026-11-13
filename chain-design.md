# Exploit Chain Design — iOS 26.6.1 (A18)

**Last updated:** 2026-11-13  
**Target:** iPhone 16 Plus (iPhone17,4, D48AP), iOS 26.6.1 (23G83), A18

## Architecture

```
IGMP UAF ──> Kernel Read ──> KASLR + IOKit Registry Walk + PAC Keys
(CVE-2026-86916) (getsourcefilter)           |
                                             v
                                   Kernel Write (RB rotation)
                                             |
                                             v
                                  ICMP6_FILTER Overwrite (32B)
                                             |
                                             v
                                    Battery Value Tweak
```

If PAC key extraction + cipher reversal succeeds, the chain upgrades:

```
                                    PAC Key Extraction
                                   (rop_pid → B-keys)
                                             |
                                             v
                                    Forge signed pointers
                                             |
                                             v
                                   Full post-exploitation
```

## Stage-by-Stage

### Stage 1: IGMP UAF Trigger — 40% confidence

**CVE-2026-86916** — the critical-path blocker for the entire chain.

The bug: `ip_msource` nodes in the multicast source filter RB-tree can be freed while
references still exist. The deferred release queue (`flush_relq`) races with membership
operations.

**What we've tried:**
- 7 probe versions on device. None triggered the race.
- v1-v4: Direct leave/join racing — too fast, no release queue population
- v5-v6: Timer-based, closer but never hit the window
- v7: Rapid group cycling with reader thread — detected stale data once but not reproducible

**Probe v8 design (not yet tested):**
1. Join 100 multicast groups on individual sockets (ff02::dead:1 through ff02::dead:64)
2. Close all 100 sockets → each enters MLD_LEAVING_MEMBER state
3. Wait 500ms for timer tick
4. Mac on same link sends MLDv1 General Query
5. `mld_v2_cancel_link_timers()` fires → mass enqueue to deferred release queue
6. Race: new joins + setsockopt hammer + getsourcefilter reader simultaneously
7. Detection: Z_ZERO patterns, invalid sockaddr, kernel pointers in source list

Key insight from v7 failure: the release queue must be populated via the **MLD state
machine** (not just socket close), requiring a Mac on the same link to inject MLD queries.

### Stage 2: Kernel Read — 90% confidence (PROVEN)

**`getsourcefilter()` is proven on device.**

Tested Nov 7: joined 200 IPv4 multicast sources, all 200 read back via
`getsockopt(IP_MSFILTER)`. Each source entry is 128 bytes (`sockaddr_storage`).

After UAF reclamation, the RB-tree nodes contain kernel heap pointers instead of
source addresses. `getsourcefilter` copies them to userspace — free kernel read.

```c
int getsourcefilter(int fd, uint32_t ifindex, struct sockaddr *group,
                    socklen_t grouplen, uint32_t *fmode, uint32_t *numsrc,
                    struct sockaddr_storage *slist);
```

- `ifindex` = 22 (en0 on our device)
- Returns 128 bytes per source entry
- 200 entries = 25.6KB per read operation
- Works from app sandbox

### Stage 3: KASLR Defeat — FREE (from read primitive)

Previously a separate stage (SysBumps timing side-channel). SysBumps turned out to be dead
on A18 in practice (CVE-2024-54531 has a ~20 tick gap but 100% noise on device;
CVE-2026-65405 is a single instruction fix).

Now KASLR is free: any kernel pointer leaked through the read primitive gives the slide.
Kernel pointers in reclaimed RB-tree nodes start with `0xfffffff0` — subtract the known
unslid base to get the slide.

### Stage 4: Kernel Write — 75% confidence (BINARY-VERIFIED)

**RB-tree rotation write primitive.** Disassembled `ip_msource_tree` `RB_REMOVE` at
`0xfffffff00aa314f0`. No PAC on any tree pointer — confirmed plain `LDR`/`STR`.

During tree rotation (rebalancing after node removal):

```
WRITE:  *(old->rbe_parent + {0 or 8}) = succ
```

- **WHERE** = controlled by corrupting `rbe_parent` in a reclaimed node
- **VALUE** = `succ` (a kernel heap pointer, leakable via the read primitive)

Combined with **ICMP6_FILTER**: `setsockopt(ICMP6_FILTER)` writes exactly 32 bytes of
controlled data to `*in6p_icmp6filt`. By redirecting `in6p_icmp6filt` via the RB rotation
write, we get arbitrary 32-byte writes.

The `ip_msource` struct is ~40 bytes → `kalloc.48` bucket. RB_ENTRY at offset 0:
```
+0x00: rbe_left    (8 bytes)
+0x08: rbe_right   (8 bytes)
+0x10: rbe_parent  (8 bytes, LSB = color bit)
+0x18: ims_haddr   (4 bytes, sort key)
```

### Stage 5: Post-Exploitation — Battery tweak viable

See [post-exploitation.md](post-exploitation.md) for the full dead-ends analysis.

The viable path: **PAC-preserving ICMP6_FILTER overwrite** of an OSNumber in the IOKit
registry:

```
Step 1: Kernel read → traverse IOKit registry → find OSNumber for CurrentCapacity
Step 2: Read OSNumber's 32 bytes (PAC-signed vtable | metadata | value | size)
Step 3: RB rotation → redirect in6p_icmp6filt to OSNumber address
Step 4: setsockopt(ICMP6_FILTER) with:
        [original_vtable_signed | original_metadata | 100 | original_size]
Step 5: OSNumber.value = 100 → battery reads as 100%
```

PAC-signed vtable bytes are preserved because they're written back to the **same address**
they were read from. The DA key context includes the storage address, so the signature
remains valid.

## IOKit Registry Traversal Offsets (RESOLVED)

From kernelcache analysis (587+ code sites cross-referenced):

```
IORegistryEntry + 0x18 → fPropertyTable (OSDictionary*)
OSDictionary + 0x0C    → count
OSDictionary + 0x20    → dictEntry*
dictEntry + 0x00       → key (OSSymbol*)
dictEntry + 0x08       → value (OSObject*), stride = 16 bytes
OSSymbol + 0x10        → char* string
OSNumber + 0x10        → uint64_t value (THE TARGET)
```

## Confidence Table

| Goal | Confidence | Blocker |
|------|-----------|---------|
| Kernel R/W | 40% | IGMP UAF trigger |
| Battery tweak | 40% | UAF + IPC struct offsets |
| PAC key extraction | 40% (gated on UAF) | Thread traversal + cipher test |
| Full jailbreak | 15% | PAC bypass + sandbox path |
