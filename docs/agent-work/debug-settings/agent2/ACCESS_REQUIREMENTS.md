# PS5 Debug Settings: Access Requirements Analysis

Agent 2 — Offline research only. 2026-10-24.

## Executive Summary

Debug Settings visibility on PS5 14.10 requires modifying kernel data segment values (`target_id` and/or `qa_flags`) that are initialized from hardware identity at boot and are not writable from userland. No userland-only path exists. The minimum technical requirement is arbitrary kernel write plus KASLR defeat.

---

## 1. Requirements hierarchy

```
Debug Settings visible
  └── SblRcMgrIsAllowDebugMenuForSettings returns true
        └── Kernel data: target_id <= 0x82  OR  qa_flags has debug menu bit set
              └── Kernel data segment write
                    ├── Kernel R/W primitive (e.g., UAF exploitation)
                    │     └── Kernel memory corruption (e.g., AIO double-free)
                    └── KASLR defeat (to locate security_flags)
                          └── Kernel address leak (NONE FOUND on 14.10)
```

### Alternative path

```
Debug Settings visible (etaHEN approach)
  └── ShellUI process patched to show custom menu
        └── Cross-process memory write into ShellUI
              └── Kernel R/W primitive
                    └── (same prerequisites as above)
```

Both paths converge on the same prerequisite: **arbitrary kernel R/W + KASLR defeat**.

---

## 2. Requirement breakdown

### 2.1 Runtime feature flag

**YES — this is a runtime flag, not a compile-time or build-time condition.**

The flag is a byte/dword in the kernel's `.data` segment, checked at Settings menu construction time. It can theoretically be changed at any time during the console's uptime, and the Settings app will reflect the change upon re-entry.

However, the flag is in kernel memory, making it a kernel-write requirement, not a userland one.

### 2.2 System configuration state

**YES — the console's identity configuration controls visibility.**

| Configuration | Source | Mutable at runtime? |
|---|---|---|
| `target_id` | Hardware IDPS → sflash → kernel `.data` at boot | Only via kernel write |
| `qa_flags` | sflash/NVS → kernel `.data` at boot | Only via kernel write |
| `security_flags` | sflash/NVS → kernel `.data` at boot | Only via kernel write |
| `utoken_flags` | sflash/NVS → kernel `.data` at boot | Only via kernel write |

The hardware identity (IDPS) is factory-fused and cannot be changed. However, the kernel's in-memory copy of the derived flags CAN be changed if kernel R/W is available. Changes are volatile — lost on reboot.

### 2.3 Process privilege or capability

**NOT DIRECTLY — but indirectly required.**

The Debug Settings visibility check reads kernel globals, not per-process credentials. A game process's `ucred` (authid `+0x58`, capabilities `+0x60`/`+0x64`) does not need to change for the menu to appear. However:

- Obtaining kernel R/W to write the flags typically requires privilege escalation
- The process performing the write needs to be able to reach kernel memory
- A game process on 14.10 has capability `0x20000000` at `cred+0x64` and zero at `cred+0x60` (bit 62 clear). This blocks access to privileged syscalls (618, 646, 671) but does not directly affect Debug Settings visibility

### 2.4 Device/debug mode

**YES — this is fundamentally a device mode question.**

Debug Settings is designed for DevKit (`target_id=0x81`) and TestKit (`target_id=0x82`) consoles. Enabling it on retail (`target_id=0x83`) requires either:

1. Changing the kernel's in-memory `target_id` to a non-retail value, OR
2. Setting QA flag bits that bypass the `target_id` check

Both are kernel writes. There is no userland API to enter "debug mode."

### 2.5 Settings application condition

**YES — the Settings app must be reopened after flag modification.**

The visibility predicate runs at menu construction time, not continuously. After modifying kernel flags, the user must:

1. Fully exit Settings (not just navigate away — close the application)
2. Reopen Settings

The Debug Settings entry then appears in the menu tree.

### 2.6 Kernel-mediated authorization decision

**YES — this is the core mechanism.**

The authorization is performed entirely in kernel space:
1. ShellUI's Settings component calls a syscall or reads a mapped kernel page to check the flag
2. The kernel function `SblRcMgrIsAllowDebugMenuForSettings` (or equivalent) reads the `security_flags` region
3. The result is returned to userland as a boolean
4. Settings uses this to decide whether to include the Debug Settings branch

The game process and ShellUI are separate processes. There is no IPC between them that could influence this check.

---

## 3. What this repository has established

### 3.1 Relevant positive evidence

| Finding | Probe | Relevance |
|---|---|---|
| AIO double-free confirmed | 65l | First kernel memory corruption on 14.10. Potential path to kernel R/W |
| `security_flags` 14.10 offset known | ps5-payload-dev/sdk | `DATA_BASE + 0x0DA4064`. Requires `DATA_BASE` (KASLR) |
| Process credential structure mapped | 55e, 332a/333a | authid gates understood; identity not writable from userland |
| All userland flag-modification paths exhausted | 55a, 257a/258a, 43f, 356a | sys 643, 560, sysctl writes all dead |
| Gezine demonstrated 14.10 Debug Settings | External (2026-10-20) | Proves it's possible; method undisclosed |

### 3.2 Relevant negative evidence (walls)

| Wall | Evidence | Impact |
|---|---|---|
| No KASLR defeat | ~400 syscalls, 34 devices, all CTL_* trees, GPU pool, signal frames | Cannot locate `security_flags` in memory |
| No kernel R/W | AIO double-free unexploited | Cannot write the flags |
| No kernel pointer anywhere | Exhaustive scanning | No address to anchor an offset |
| W^X enforced by hypervisor | mprotect, sys 588 | Cannot execute shellcode even if written |
| Process isolation | No cross-process write | Cannot patch ShellUI directly |
| `/dev/icc_configuration` closed | Device inventory | Cannot reach hardware identity store |
| `/dev/sbl_srv` closed | Device inventory | Cannot reach SBL security service |
| `/dev/qafutkn` absent from game jail | Device inventory (76 nodes, not listed) | Cannot reach QA flag device |

---

## 4. Minimum viable path to Debug Settings on 14.10

### Step 1: KASLR defeat
Obtain any kernel address. No method exists on 14.10.

**Candidates under investigation:**
- AIO double-free → heap spray → reclaim freed object with controlled data → read back kernel pointer
- sys 624 VM-op counter as side channel (confirmed working but no intra-kernel discrimination — probe 56f)
- Undiscovered info leak in remaining untested syscall contracts

### Step 2: Kernel R/W
Use the AIO double-free to corrupt a kernel object, then spray matching allocations to reclaim the freed slot. Read/write through the dangling pointer.

**Status:** Confirmed corruption (65l). Exploitation not attempted.

### Step 3: Write kernel flags
With kernel R/W and a known `DATA_BASE`:

```
security_flags_addr = DATA_BASE + 0x0DA4064
target_id_addr      = security_flags_addr + 0x09
qa_flags_addr       = security_flags_addr + 0x24
```

Write `target_id` to `0x82` (or lower) and/or set the appropriate `qa_flags` bits.

### Step 4: Reopen Settings
Fully exit Settings and reopen. The `SblRcMgrIsAllowDebugMenuForSettings` predicate will re-evaluate and the Debug Settings entry will appear.

---

## 5. Questions for Agent 1 (safe, offline-designed)

These are information-gathering queries, not exploit attempts. All can be tested safely from the existing userland entry.

### Q1: Does `/dev/qafutkn` exist in the device tree?
The 76-node inventory from probe 259a may not be exhaustive if Sony added nodes after that scan. A targeted `open("/dev/qafutkn", O_RDONLY)` would confirm presence or absence.

**Risk:** LOW — open() on a nonexistent path returns -1. Open on a refused path also returns -1.

### Q2: What does `sysctl kern.osreldate` return?
The FreeBSD release date would help narrow the upstream source tree and identify which `sceSblRcMgr` functions are present.

**Risk:** NONE — sysctl read.

### Q3: Can sys 621 (`sceKernelIsNeoMode`) be called?
This is in the 13.60 sysent as a real handler. If it returns a value, it tells us whether mode-detection syscalls are accessible, which would inform whether other `sceKernelIs*` predicates might be reachable.

**Risk:** LOW — single syscall with no arguments.

### Q4: Does `/dev/rootparam` open?
The wiki says it's "used by SceShellCore for verifying root param SFO/JSON." If accessible, it might expose console identity parameters.

**Risk:** LOW — open() attempt.

---

## 6. Confidence assessment

| Conclusion | Confidence | Basis |
|---|---|---|
| Debug Settings requires kernel flag modification | **HIGH** | Every public implementation confirms this; no counter-evidence exists |
| No userland-only path exists | **HIGH** | Exhaustive syscall/device/sysctl testing on 14.10 |
| `SblRcMgrIsAllowDebugMenuForSettings` is the gate function | **MEDIUM** | Named on PS5 wiki; confirmed on PS4; no PS5 binary analysis |
| 14.10 `security_flags` offset is `D + 0x0DA4064` | **MEDIUM** | From ps5-payload-dev/sdk commit (community source, untested by this repo) |
| `target_id` at `security_flags + 0x09` | **HIGH** | Consistent across all firmware versions in the Apollo offset table |
| `qa_flags` at `security_flags + 0x24` | **HIGH** | Same consistency |
| AIO double-free is the most promising path to kernel R/W | **HIGH** | Confirmed corruption; only known kernel memory bug on 14.10 |
| Gezine's 14.10 method uses a different kernel exploit (not Relapse) | **HIGH** | Gezine stated this explicitly |

---

## 7. What remains unavailable

| Data | Why unavailable | What it would provide |
|---|---|---|
| 14.10 plaintext kernel image | Encrypted; PUP outer decryption yields opaque inner | Exact `SblRcMgrIsAllowDebugMenuForSettings` implementation, all offsets, all gates |
| PS5 ShellUI binary | Not extracted or publicly available for 14.10 | Settings menu construction code, visibility predicate call site |
| Exact QA flag bit layout for PS5 | Not publicly documented; PS4 layout is partial reference | Which single bit to set for minimum Debug Settings visibility |
| Gezine's 14.10 exploit method | Private | Whether an alternative (non-AIO) kernel bug exists on 14.10 |
| `DATA_BASE` for live 14.10 console | No KASLR defeat | Actual addresses for kernel flag writes |

---

## Sources

- [PS5Dev/PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak) — offset tables and README
- [etaHEN](https://github.com/etaHEN/etaHEN) — Toolbox approach documentation
- [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk) — 14.10 kernel offsets (commit a7685ce8)
- [PS5 Developer Wiki](https://www.psdevwiki.com/ps5/) — Debug Settings, Button Combos, Devices
- [PS4 Developer Wiki](https://www.psdevwiki.com/ps4/) — QA Flagging, SBL Kernel module
- [Poops-PS5-Java](https://github.com/jaigaresc/Poops-PS5-Java) — GPU DMA flag patching
- [DuskFal1/p2jb](https://github.com/DuskFal1/p2jb) — kstuff with security_flags references
- [Hacking Adventures](https://www.hackingadventures.ca/posts/ps4-retailkit-part-2/) — RcMgr analysis
- Local: `docs/PRIVATE_UPSTREAM_1410_KERNEL_OFFSETS_2026-10-21.md`
- Local: `docs/DEBUG_SETTINGS_14_10_PATH.md`
- Local: `docs/ATTACK_SURFACE.md`
- Local: `docs/agent-work/debug-settings/agent1/STATUS.md`
- Local: `artifacts/usb_pre_reset_2026-10-20/PS4/APOLLO/*/kernel_offset.lua`
- Local: probe results 55a, 55e, 257a/258a, 332a/333a, 356a, 65l
