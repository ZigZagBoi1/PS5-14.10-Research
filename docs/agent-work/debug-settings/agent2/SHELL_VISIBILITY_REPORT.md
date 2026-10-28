# PS5 Debug Settings: Shell Visibility Architecture

Agent 2 — Offline research only. No console contact. 2026-10-24.

## 1. How the Settings menu is constructed

### 1.1 System architecture

The PS5 Settings application runs inside **SceShellUI**, a privileged system process separate from any game process. SceShellUI is the UI compositor and menu renderer; **SceShellCore** is the background service daemon that drives system policy, backup/restore, credential validation, and IPC with the kernel.

Debug Settings is **not a separate application**. It is a menu branch within the existing Settings hierarchy, whose visibility is controlled at runtime by a flag check before the branch is registered in the menu tree.

### 1.2 Menu item visibility

Evidence from multiple public implementations converges on the same model:

1. When Settings opens (or is re-entered after a full exit), the menu tree is rebuilt.
2. Each top-level branch has a visibility predicate. Debug Settings' predicate calls into the kernel (or reads a cached kernel value) to decide whether to show the entry.
3. The predicate is a kernel function in the `sceSblRcMgr` family: **`SblRcMgrIsAllowDebugMenuForSettings`** (see §2 for provenance).
4. If the predicate returns false/0, the Debug Settings branch is suppressed. The UI never renders it.

This is why every public jailbreak says "fully exit Settings and reopen it" after modifying kernel flags — the visibility check runs at menu construction time, not continuously.

### 1.3 Retail vs. DevKit/TestKit

| Console type | target_id | Debug Settings | Notes |
|---|---|---|---|
| Retail (CEX) | `0x83` | Hidden by default | Requires kernel flag modification |
| TestKit (DEX) | `0x82` | Visible | Many features still limited |
| DevKit (TOOL) | `0x81` | Visible | Full developer access |
| Diag (TEST) | `0x80` | Visible | Manufacturing/QA |

On retail hardware, the `SblRcMgrIsAllowDebugMenuForSettings` check fails because the kernel's `target_id` byte and QA flag bits are set for retail operation. DevKits and TestKits pass the check because their factory-programmed identity values satisfy the predicate.

Source: AlexAltea/orbital env-common.cfg target_id mapping; PS5 Developer Wiki Debug Settings page; PS5-UMTX-Jailbreak offset tables.

### 1.4 Dynamic vs. static determination

The determination is **dynamic at Settings launch time** but based on **kernel data segment values** that are static across the console's lifetime unless modified by a kernel exploit:

- `security_flags`: a dword in the kernel `.data` segment
- `target_id`: a byte at `security_flags + 0x09`
- `qa_flags`: a dword at `security_flags + 0x24`
- `utoken_flags`: a byte at `security_flags + 0x8C`

These values are initialized from hardware-fused identity (ICC/sflash) at boot and are not modifiable from userland. The kernel does not expose a syscall, sysctl, or device that writes them.

## 2. The gate function: `SblRcMgrIsAllowDebugMenuForSettings`

### 2.1 Provenance and confidence

| Source | Platform | Confidence |
|---|---|---|
| PS5 Developer Wiki (Button Combo Menus page) | PS5 | **MEDIUM** — community wiki, names the function as a prerequisite for the Start+L3 hidden debug menu |
| PSXHAX forum (debug settings thread) | PS5 | **LOW** — secondhand report citing the function name |
| PS4 SBL Kernel module wiki page | PS4 | **HIGH** for PS4 — documents the `sceSblRcMgr*` function family as kernel exports |
| Hacking Adventures RetailKit series | PS4 | **HIGH** for PS4 — documents `sceSblRcMgrIsAllowULDebugger` and related functions as patchable kernel checks |
| PS4 Debug Settings 1.01 / Toggle_QA.PKG thread | PS4 | **HIGH** for PS4 — documents QA flag bits controlling debug menu |

### 2.2 What the function likely checks

Based on cross-referencing PS4 documentation and PS5 jailbreak implementations:

```
SblRcMgrIsAllowDebugMenuForSettings():
    if target_id < 0x82:          // DevKit or Diag
        return true
    if qa_flags & QA_DEBUG_MENU_BIT:
        return true
    return false
```

The exact bit position in `qa_flags` is not publicly documented for PS5. On PS4, the QA flag byte layout is partially documented on PSDevWiki, with bit 0 of the first QA flags byte controlling the debug menu. The PS5 layout is believed to be similar but **not verified** — every public PS5 jailbreak writes multiple QA flag bytes rather than documenting individual bits.

### 2.3 The `sceSblRcMgr` function family

This kernel module provides authorization predicates. Known members (PS4, likely present on PS5):

| Function | Purpose |
|---|---|
| `sceSblRcMgrIsAllowDebugMenuForSettings` | Gate for Debug Settings visibility |
| `sceSblRcMgrIsAllowDebugMenuForPsm` | Gate for PSM debug menu |
| `sceSblRcMgrIsAllowULDebugger` | Gate for userland debugger |
| `sceSblRcMgrIsAllowDisablingAslr` | Gate for ASLR disable option |
| `sceSblRcMgrIsAllowRegistryAccess` | Gate for registry editor access |

All read from the same kernel data region: `security_flags`, `target_id`, and/or `qa_flags`. None of them have a "set" counterpart — they are read-only predicates over boot-time constants.

### 2.4 Assist mode

One community report says the hidden debug menu "only works on assist mode." This likely refers to a secondary predicate that checks whether the console is in Sony's Assist Mode (a service/debug configuration). This is a separate gate from the main Debug Settings visibility check and has not been reverse-engineered on PS5.

## 3. What must change for visibility

### 3.1 Minimum change set

Based on public PS5 jailbreak implementations, the minimum kernel modifications to make Debug Settings appear:

1. **`target_id`** — set to `0x82` (TestKit/DEX) or lower
2. **`qa_flags`** — set specific bits that `SblRcMgrIsAllowDebugMenuForSettings` checks

Both are in the kernel `.data` segment and require kernel R/W to modify.

### 3.2 The full jailbreak sequence (from PS5-UMTX-Jailbreak)

The public implementation performs four kernel data writes:

| Field | Offset from `security_flags` | What is written | Purpose |
|---|---|---|---|
| `security_flags` | `+0x00` | Modified (exact value not extracted) | Disables security checks |
| `target_id` | `+0x09` | Changed from `0x83` (CEX) | Changes console identity |
| `qa_flags` | `+0x24` | Set (exact bits not extracted) | Enables QA/debug features |
| `utoken_flags` | `+0x8C` | Set (exact bits not extracted) | Enables utoken features |

Additionally, the jailbreak modifies the process's `ucred` structure (authid, capabilities) and replaces the filesystem root, but those changes are for privilege escalation and sandbox escape — **not** for Debug Settings visibility.

### 3.3 Alternative: ShellUI process patch (etaHEN approach)

etaHEN does not enable the native Debug Settings. Instead, it:

1. Uses kernel R/W to inject code into the ShellUI process
2. Replaces the Debug Settings menu entry with its own "Toolbox"
3. Provides custom debug-like functionality through the injected code

This also requires kernel R/W. It does not toggle a kernel flag.

### 3.4 GPU DMA approach (Poops/BD-J)

The Poops PS5 Java exploit uses a different write mechanism: GPU DMA to patch the kernel `.data` segment directly, bypassing the kernel's own write restrictions on its data region. The targets are the same: `qa_flags`, `target_id`, and `utoken_flags`. This is still a kernel R/W primitive — it just uses the GPU's DMA engine instead of a software kernel exploit to perform the write.

## 4. Can visibility be enabled without a kernel exploit?

### 4.1 Assessed paths

| Path | Feasibility | Evidence |
|---|---|---|
| Kernel flag write from userland syscall | **NO** | No syscall writes `security_flags`/`target_id`/`qa_flags`. Sys 643 (`set_chicken_switches`) is process-local and has no effect on kernel globals (probe 55a, 356a). Sys 560 (`debug_init`) returns 0 but changes nothing (probes 257a/258a). |
| Sysctl write | **NO** | All sysctl write attempts return -1 (probe 43f). `kern.securelevel` write rejected. |
| IPC to ShellUI/ShellCore | **NO** | No accessible IPC channel to the Settings process. Compositor sockets accept connections but do not carry configuration commands. |
| Device node ioctl | **NO** | ~32M ioctl calls across 34 open `/dev` nodes: zero commands modify system configuration (probes 273a-287a, 387a/387c). `/dev/icc_configuration` and `/dev/sbl_srv` refuse to open from a game process. |
| Credential manipulation | **NO** | `cred+0x58` (authid) is never writable from userland. Sys 587 is read-only and returns only a capability mask. No handler writes the identity. |
| Configuration file/registry | **NO** | No accessible filesystem path contains a settings configuration that controls menu visibility. `/app0` is the game's read-only partition; `/savedata0` is game save data. `/system` returns -1 from stat. |
| Hardware button combo | **PARTIAL** | Start+L3 opens a hidden menu IF `SblRcMgrIsAllowDebugMenuForSettings` returns true — i.e., only after the kernel flag is already set. The combo is not a bypass. |

### 4.2 Conclusion

**Debug Settings visibility cannot be enabled from userland alone on PS5 14.10.**

The gate is a kernel data segment read performed by `SblRcMgrIsAllowDebugMenuForSettings`. The data is initialized from hardware identity at boot and is not writable through any userland interface. Every public implementation that enables Debug Settings does so by first obtaining arbitrary kernel R/W (via UMTX UAF, AIO race, IPv6 UAF, GPU DMA, or equivalent) and then writing the flag bytes directly.

The AIO double-free (probe 65l) is the first confirmed kernel memory corruption primitive on 14.10, but it has not been exploited into a controlled kernel R/W yet.

## 5. What evidence would settle remaining uncertainties

| Question | What would settle it | Difficulty |
|---|---|---|
| Exact PS5 `SblRcMgrIsAllowDebugMenuForSettings` implementation | Plaintext 14.10 kernel image + Ghidra decompile | HIGH — encrypted kernel |
| Exact QA flag bits for debug menu | Kernel image analysis or controlled write + observe | HIGH |
| Whether any undiscovered Sony IPC can toggle the flag | Comprehensive IPC protocol RE of ShellCore, or 14.10 kernel strings showing a setter | HIGH |
| Exact 14.10 `security_flags` offset | Live KASLR defeat + kernel read | HIGH — no KASLR defeat |
| Whether Gezine's method uses a different gate | Public disclosure of the 14.10 method | EXTERNAL — private |

## Sources

- [PS5Dev/PS5-UMTX-Jailbreak](https://github.com/PS5Dev/PS5-UMTX-Jailbreak) — public PS5 kernel exploit with offset tables
- [etaHEN](https://github.com/etaHEN/etaHEN) — PS5 HEN with Toolbox replacing Debug Settings
- [PS5 Developer Wiki — Debug Settings](https://www.psdevwiki.com/ps5/%E2%98%85_Debug_Settings) — community documentation
- [PS5 Developer Wiki — Button Combo Menus](https://www.psdevwiki.com/ps5/Button_Combo_Menus) — hidden menu documentation
- [PS5 Developer Wiki — Devices](https://www.psdevwiki.com/ps5/Devices) — device node reference
- [PS4 Developer Wiki — QA Flagging](https://www.psdevwiki.com/ps4/QA_Flagging) — PS4 QA flag documentation
- [PS4 Developer Wiki — SBL Kernel module](https://www.psdevwiki.com/ps4/SBL_Kernel_module) — SBL function reference
- [Hacking Adventures — PS4 RetailKit Part 2](https://www.hackingadventures.ca/posts/ps4-retailkit-part-2/) — RcMgr function analysis
- [AlexAltea/orbital](https://github.com/AlexAltea/orbital) — target_id definitions
- [Poops-PS5-Java](https://github.com/jaigaresc/Poops-PS5-Java) — GPU DMA debug settings enabler
- [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk) — PS5 payload SDK with 14.10 kernel offsets
- [ps5-payload-dev/ftpsrv](https://github.com/ps5-payload-dev/ftpsrv) — FTP server with firmware-specific offsets
- [hammer-83/ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader) — kernel offset reference
- Local: `artifacts/usb_pre_reset_2026-10-20/PS4/APOLLO/*/kernel_offset.lua` — cross-firmware offset table
- Local: `docs/PRIVATE_UPSTREAM_1410_KERNEL_OFFSETS_2026-10-21.md` — upstream 14.10 offsets
- Local: `docs/DEBUG_SETTINGS_14_10_PATH.md` — prior analysis
- Local: `docs/agent-work/debug-settings/agent1/STATUS.md` — Agent 1 findings
