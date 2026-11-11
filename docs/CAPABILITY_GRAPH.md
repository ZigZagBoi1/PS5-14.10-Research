# Capability & Evidence Graph — PS5 14.10

> **Generated:** 2026-11-11 — from CLAUDE.md, EXPLOITATION_STATUS.md, FINDINGS.md, ATTACK_PRIORITY_REFERENCE.md, STATE.md

## Chain Status

```
  ✅ DONE               ✅ DONE              ⬜ OPEN               ⬜ OPEN              ⬜ GOAL
┌──────────────┐   ┌───────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌──────────────┐
│ Userland     │   │ Kernel base   │   │ WebProcess    │   │ Code-reuse chain │   │ Kernel R/W   │
│ code exec    │──▸│ discovery     │   │ text base:    │──▸│ (forged vtable   │──▸│              │──▸ HV
│ (Lua TCP)    │   │ (fault oracle)│   │ VP [M], RVA ? │   │  dispatch → ROP) │   │              │   bypass
└──────────────┘   └───────────────┘   └───────────────┘   └──────────────────┘   └──────────────┘
                                             ▲
                                             │
                                    ┌────────┴────────┐
                                    │ FontFace UAF    │
                                    │ VP leak [M]     │
                                    │ Canvas2D UAF    │
                                    └─────────────────┘
```

**Gap 1 — WebProcess text base RVA:** VP is leaked per-boot [M], but the RVA offset is [I] (p807 overclaim retracted 2026-11-10). Needs a measured ELF-magic anchor or binary analysis. Active vector.

**Gap 2 — Kernel vulnerability:** Lua-side syscall surface exhausted (~400 BSD + Sony 532-676 + 32M ioctls). WebKit FontFace UAF → forged vtable dispatch → kernel exploit is the sole remaining path.

**Gap 3 — Kernel R/W primitive:** No kernel memory read or write. Fault oracle gives presence (base address), not content. Every syscall-side leak is dead.

---

## Capabilities

### Capability 1: Userland Code Execution (Lua Loader)
- **Status**: VERIFIED [M]
- **Evidence**: TCP 9026 Lua 5.1 loader; every probe in the repository executes through it
- **Dependencies**: PS5 firmware 14.10, game process with Lua loader
- **Enables**: All other capabilities (syscall access, memory operations, WebKit entry)
- **Blockers**: None — this is the entry point

### Capability 2: KASLR Defeat (Fault Oracle)
- **Status**: VERIFIED [M]
- **Evidence**: Probes 995a-1006a, 1008a-1010a, 1199a-1199c. User-fault status words differ across mapped/unmapped kernel VA. Two measured boots: `0xFFFFFFFF91800000` (slide `0x46800000`) and `0xFFFFFFFFD5000000` (slide `0x55000000`). 512 probes, 33s per boot. STATE.md: `kernel_text: 0xFFFFFFFFD5000000`
- **Dependencies**: Userland code execution
- **Enables**: Targeted kernel exploitation once a R/W primitive exists; kernel structure address calculation (allproc, security_flags, rootvnode all derived)
- **Blockers**: Presence-only oracle — cannot READ kernel memory, only detect mapped vs unmapped. Supervisor bit enforced.

### Capability 3: Heap R/W (GPU mmap)
- **Status**: VERIFIED [M]
- **Evidence**: Syscall 477 (mmap). 384 MiB of zeroed pages, 16KB granularity. EXPLOITATION_STATUS.md primitive #6.
- **Dependencies**: Userland code execution
- **Enables**: Spray data staging, large heap buffers for exploitation primitives
- **Blockers**: GPU bus space, not system RAM (probes 262a/263a, 563a-563k confirmed). Cannot access kernel memory through this mapping.

### Capability 4: Userland ASLR Bypass (dynlib_get_info 593)
- **Status**: VERIFIED [M]
- **Evidence**: Syscall 593 returns bases for 39 loaded modules. EXPLOITATION_STATUS.md primitive #7.
- **Dependencies**: Userland code execution
- **Enables**: Gadget address resolution for the Lua loader process. Full eboot gadget catalog (pop_rax, pop_rdi, pop_rsi, pop_rdx, pop_rcx, pop_r8 at known RVAs). Primitive #12.
- **Blockers**: Loader-process only — returns Lua loader address space, NOT WebProcess addresses. Cannot derive WebProcess VA from it.

### Capability 5: Child Thread ROP Syscalls (thr_new 455)
- **Status**: VERIFIED [M]
- **Evidence**: Probes 271g/272a/396f (close, write, socketpair, setsockopt from child thread), 56l (rdi=arg, child executes gadget chain), 383a (thr_new works). 5-arg syscall delivery confirmed.
- **Dependencies**: Userland code execution, userland ASLR bypass (for gadget addresses)
- **Enables**: Native-speed concurrent kernel calls, race condition exploitation, thread-based timing primitives
- **Blockers**: Thread budget varies per loader (25/11/9 measured ceilings, probes 242a/244a/245a). fork/rfork blocked.

### Capability 6: thr_create(430) Full Register Control
- **Status**: VERIFIED [M]
- **Evidence**: Probes 156c/156d. GP regs, RIP, RSP, CS=0x43, SS=0x3B all controllable.
- **Dependencies**: Userland code execution
- **Enables**: Alternative thread primitive with more register control than thr_new
- **Blockers**: Same thread budget limits as thr_new

### Capability 7: CClosure Redirect (Selected Targets)
- **Status**: SUPPORTED [S]
- **Evidence**: Probes 56c/56f/56d-56d7. Lua arguments delivered, target-like output and restore checks recorded for rawequal/rawget/select. rax=0/1/6/7/8 return count control confirmed (56d series).
- **Dependencies**: Userland code execution
- **Enables**: Userland code execution through Lua C function redirection
- **Blockers**: Machine-register arguments and general native targets NOT established. Only selected Lua C function targets demonstrated.

### Capability 8: native.fcall_with_rax
- **Status**: VERIFIED [M]
- **Evidence**: Probe 129b. getpid (0x22a), socket (0x16), close (0x0) confirmed working.
- **Dependencies**: Userland code execution
- **Enables**: Arbitrary userland function calls by syscall number
- **Blockers**: Userland only — no kernel memory access

### Capability 9: Network Packet Injection
- **Status**: VERIFIED [M]
- **Evidence**: 700+ network protocol fuzz packets (probes 48a-50d). Socket creation and raw packet sending confirmed working.
- **Dependencies**: Userland code execution
- **Enables**: Network-side attack surface exploration
- **Blockers**: Zero crashes from 700+ packets. Network protocol fuzz declared DEAD as attack vector.

### Capability 10: WebKit Canvas2D UAF (CVE-2026-43720)
- **Status**: VERIFIED [M]
- **Evidence**: Probe p553 (executed 2026-10-26). Bidirectional R/W, spray[9] alias, 7 numeric properties confirmed. Result: `results/phase13_webkit/p553_canvas_uaf_write_confirm_20261026.txt`
- **Dependencies**: Userland code execution (for WebKit entry), browser access from Lua loader
- **Enables**: Browser-side write primitive (48B transform + properties). Control primitive for exploitation chain.
- **Blockers**: NOT arbitrary write — limited to 48B transform + properties. WebProcess restarts on every navigation (single-shot, single-page constraint, p584).

### Capability 11: FontFace UAF Chain (VP Leaked)
- **Status**: VERIFIED [M] for VP leak; INFERRED [I] for RVA
- **Evidence**:
  - VP leak: p691 (4-read walk chain, VP = `0x80f4b9b28` on one committed boot)
  - Delta invariance: p804 (16/16 WALK-ok + DELTA-INVARIANT across 16 distinct per-boot VPs) [M@16]
  - 100% reclaim: `m_refCount` 0→1, live `WeakPtrImpl*` at `+0x68` (p580/p581)
  - Two-phase forge write: p656 (forged +0x58 retained == T1, W2 nonzero, rc seed+1)
  - Null-spray: p599 v4i (7/7 = 100% survival without 80B spray)
  - GC destructor path: p599 v1/v2/v4a (destructor reachable via GC after wrapper pin expires)
  - Spray buffer self-address: p691 (+0x38 marker oracle, SELF = 0x1000384480)
  - **RVA overclaim retracted (2026-11-10)**: p807 `0x724DB28` regraded to [I]. Zero `P807-BASE`/`RVA`/`SCAN`/`HIT` beacons in committed corpus.
- **Dependencies**: Browser access from Lua loader, Canvas2D UAF (control primitive)
- **Enables**: Once RVA is measured → WebProcess text base per boot → code-reuse chain through forged vtable dispatch → kernel exploit entry
- **Blockers**:
  1. RVA not measured — needs fresh-boot capture with ELF-magic discriminator
  2. Heap NX — forged vtable dispatch dies on NX heap; must use code-reuse (ROP/gadgets in WebProcess .text)
  3. LLInt-only (all JIT tiers OFF) — no DFG/FTL/Baseline, limits CVE applicability
  4. W^X enforced — all code exec must be ROP/gadgets

### Capability 12: Kernel Image Base + Derived Addresses
- **Status**: VERIFIED [M] (base); SUPPORTED [S] (derived offsets)
- **Evidence**: STATE.md records: `kernel_text: 0xFFFFFFFFD5000000`, `kernel_data: 0xFFFFFFFFD5CE0000` (TEXT + 0xCE0000, SDK v0.45), `allproc: 0xFFFFFFFFD85B9EA0`, `security_flags: 0xFFFFFFFFD6A84064`, `rootvnode: 0xFFFFFFFFD8E3B510`
- **Dependencies**: KASLR defeat (fault oracle)
- **Enables**: Once kernel R/W exists, these addresses enable targeted credential patching, process escalation, rootvnode manipulation
- **Blockers**: No kernel R/W primitive to use these addresses. Derived offsets from SDK v0.45 — validity on 14.10 not fully confirmed (constant drain: 1/25 confirmed valid, 7/25 wrong).

### Capability 13: Sigreturn Frame Injection
- **Status**: VERIFIED [M]
- **Evidence**: Probes 417/421. Kernel copies 0xC0 bytes from user frame, cookie=RFLAGS(0x202).
- **Dependencies**: Userland code execution
- **Enables**: Register state control (userland only)
- **Blockers**: Userland only — does not provide kernel access

### Capability 14: POSIX Shared Memory + Sendfile
- **Status**: VERIFIED [M]
- **Evidence**: Probes 391a-391d. Named/anonymous shm, MAP_SHARED, sendfile all working.
- **Dependencies**: Userland code execution
- **Enables**: Kernel object creation (shared memory objects)
- **Blockers**: shm_open2(571) is nosys — no large-page shared memory

### Capability 15: Event Synchronization (EVFILT_TIMER + socketpair)
- **Status**: VERIFIED [M]
- **Evidence**: Probe 271i. 1ms timer resolution, AF_UNIX pipe.
- **Dependencies**: Userland code execution
- **Enables**: Precise timing for race conditions
- **Blockers**: None for timing; but all tested race vectors are DEAD

### Capability 16: Child Thread Fake TCB
- **Status**: VERIFIED [M]
- **Evidence**: Probe 384b. sysarch(SET_FSBASE=129) + 4KB self-ref TCB.
- **Dependencies**: Child thread creation (thr_new/thr_create)
- **Enables**: errno access in child threads (required for reliable syscall returns)
- **Blockers**: None

---

## Dependency Graph (Text)

```
Lua Loader (entry)
├── KASLR Defeat (fault oracle) ──▸ Kernel Base + Derived Addrs ──▸ [BLOCKED: no R/W]
├── Heap R/W (GPU mmap) ──▸ Spray staging
├── Userland ASLR Bypass (593) ──▸ Eboot gadget catalog
├── Child Thread ROP (455/430) + Fake TCB ──▸ Concurrent syscalls + races
├── CClosure Redirect ──▸ Userland function calls
├── native.fcall_with_rax ──▸ Arbitrary userland calls
├── Sigreturn Frame Injection ──▸ Register control
├── POSIX shm + sendfile ──▸ Kernel object creation
├── Event Sync (timer + socketpair) ──▸ Race timing
└── WebKit Entry
    ├── Canvas2D UAF (CVE-2026-43720) ──▸ Browser write primitive
    └── FontFace UAF Chain
        ├── VP leak [M] + Delta invariance [M@16]
        ├── 100% reclaim + Two-phase forge write
        ├── GC destructor path + Null-spray survival
        └── [BLOCKED: RVA [I]] ──▸ Text base ──▸ Code-reuse chain ──▸ Kernel exploit
```

---

## Evidence Quality Summary

| # | Capability | Grade | Strongest Evidence | Contradictions / Caveats |
|---|-----------|-------|-------------------|--------------------------|
| 1 | Userland code execution | M | Every probe in repository | None |
| 2 | KASLR defeat (fault oracle) | M | 1199a-c: base + slide measured on 2 boots | Presence-only, not content read |
| 3 | Heap R/W (GPU mmap) | M | Syscall 477: 384 MiB zeroed pages | GPU bus space, not system RAM (262a/263a) |
| 4 | Userland ASLR bypass (593) | M | 39 module bases returned | Loader-process only, not WebProcess |
| 5 | Child thread ROP (455) | M | 271g/272a/396f: multi-arg syscalls from child | Thread budget varies (25/11/9) |
| 6 | thr_create(430) register control | M | 156c/156d: full GP regs + RIP/RSP | Same budget limits |
| 7 | CClosure redirect | S | 56c/56f: selected Lua C targets | Machine-register args NOT established |
| 8 | native.fcall_with_rax | M | 129b: getpid/socket/close confirmed | Userland only |
| 9 | Network packet injection | M | 48a-50d: 700+ packets sent | Zero crashes — DEAD as attack vector |
| 10 | Canvas2D UAF (CVE-2026-43720) | M | p553: bidirectional R/W, spray alias | 48B limited, not arbitrary write |
| 11 | FontFace UAF — VP leak | M | p691: 4-read walk chain; p804: 16/16 boots | RVA is [I] not [M] (p807 overclaim retracted) |
| 12 | FontFace UAF — reclaim | M | p580/p581: refcount 0→1, WeakPtrImpl at +0x68 | Single-shot constraint (WebProcess restarts) |
| 13 | FontFace UAF — forge write | M | p656: forged +0x58 retained, W2 nonzero | Write is BLIND (needs target VA) |
| 14 | FontFace UAF — GC destructor | M | p599 v1/v2/v4a: destructor reachable via GC | Ordering constraint: forge AFTER unpin |
| 15 | Kernel base + derived addrs | M/S | STATE.md: measured base + SDK offsets | Derived offsets: 1/25 confirmed (constant drain) |
| 16 | Sigreturn frame injection | M | 417/421: 0xC0 bytes copied | Userland only |
| 17 | WebProcess text base RVA | **I** | p807: `0x724DB28` — **OVERCLAIM RETRACTED** | Zero P807-BASE/RVA/SCAN/HIT beacons; both terminal branches bypass ELF-magic discriminator |

**Legend:** M = measured on device, S = source-read / inferred from source, I = inference (not device-confirmed)
