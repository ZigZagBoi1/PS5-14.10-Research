# PS5 Debug Settings: Symbol Reference Map

Agent 2 — Offline research only. 2026-10-24.

## Purpose

Map every symbol, function, and kernel structure relevant to Debug Settings visibility. For each, record its actual source, platform verification status, and whether it has been observed in the 14.10 research.

---

## 1. Kernel functions

### `SblRcMgrIsAllowDebugMenuForSettings`

| Property | Value |
|---|---|
| **Type** | Kernel predicate function |
| **Returns** | Boolean (0/1) |
| **Purpose** | Controls whether Debug Settings is visible in the Settings menu |
| **PS4 verified** | YES — documented in PS4 Developer Wiki SBL Kernel module page; mentioned in QA Flagging page |
| **PS5 verified** | PARTIAL — named on PS5 Developer Wiki Button Combo Menus page (community wiki, not official). No PS5 binary containing this symbol has been analyzed in this repository |
| **14.10 verified** | NO — no 14.10 kernel image available for analysis |
| **Reads from** | `security_flags` region: likely `target_id` and `qa_flags` |
| **Confidence** | HIGH that this function (or an equivalent) exists on PS5. The name may differ slightly. The read targets are confirmed by jailbreak implementations |

### `IsDebugMenuEnable`

| Property | Value |
|---|---|
| **Type** | Unknown — possibly a userland wrapper or ShellUI-internal function |
| **PS4 verified** | NO — not found in PS4 wiki or RetailKit analysis |
| **PS5 verified** | NO — not found in any PS5 binary or documentation |
| **14.10 verified** | NO |
| **Confidence** | LOW — may be a speculative or third-party name. No primary source found |

### `SettingsRootHandler.OnCheckVisible`

| Property | Value |
|---|---|
| **Type** | Unknown — likely a UI framework callback in the Settings application |
| **PS4 verified** | NO — not found in PS4 kernel or ShellUI documentation |
| **PS5 verified** | NO — not found in any PS5 source. May be a class method in a managed/JS framework used by ShellUI |
| **14.10 verified** | NO |
| **Confidence** | LOW — speculative. The PS5 Settings UI framework is not publicly documented. This could be an internal React/web component lifecycle method if Settings uses a web-based UI |

### `sceSblRcMgrIsAllowULDebugger`

| Property | Value |
|---|---|
| **Type** | Kernel predicate function |
| **PS4 verified** | YES — documented in Hacking Adventures RetailKit Part 2 |
| **PS5 verified** | NO — not tested or found on PS5 |
| **14.10 verified** | NO |
| **Reads from** | Same `security_flags` region |
| **Confidence** | HIGH for PS4. MEDIUM for PS5 (likely exists but unverified) |

### `sceSblRcMgrIsAllowDisablingAslr`

| Property | Value |
|---|---|
| **Type** | Kernel predicate function |
| **PS4 verified** | YES — mentioned in cturt's PS4 exploitation writeup |
| **PS5 verified** | NO |
| **14.10 verified** | NO |
| **Confidence** | HIGH for PS4. MEDIUM for PS5 |

### `sceSblRcMgrIsAllowRegistryAccess`

| Property | Value |
|---|---|
| **Type** | Kernel predicate function |
| **PS4 verified** | YES — mentioned in cturt's PS4 exploitation writeup |
| **PS5 verified** | NO |
| **14.10 verified** | NO |
| **Confidence** | HIGH for PS4. MEDIUM for PS5 |

### `sceSblACMgrIsDebuggableProcess`

| Property | Value |
|---|---|
| **Type** | Kernel predicate function |
| **PS4 verified** | YES — documented in RetailKit series |
| **PS5 verified** | NO |
| **14.10 verified** | NO |
| **Reads from** | Process credential structure |
| **Confidence** | HIGH for PS4. MEDIUM for PS5 |

### `sceSblACMgrIsAllowedSystemLevelDebugging`

| Property | Value |
|---|---|
| **Type** | Kernel predicate function |
| **PS4 verified** | YES — documented in RetailKit series |
| **PS5 verified** | NO |
| **14.10 verified** | NO |
| **Confidence** | HIGH for PS4. MEDIUM for PS5 |

### `sceKernelCheckDipsw`

| Property | Value |
|---|---|
| **Type** | Kernel function — reads DIP switch (hardware/fuse) state |
| **PS4 verified** | YES — used in FUSE initialization (RetailKit series) |
| **PS5 verified** | PARTIAL — `/dev/dipsw` device node exists and opens from game process (probe device inventory) |
| **14.10 verified** | Device node exists; function behavior unverified |
| **Confidence** | HIGH that it exists. Its role in Debug Settings is indirect — it gates other subsystems |

### `sceSblAIMgrIsDevKit` / `sceSblAIMgrIsTestKit`

| Property | Value |
|---|---|
| **Type** | Kernel predicate functions — check IDPS product code |
| **PS4 verified** | YES — documented in RetailKit series, used in FUSE init |
| **PS5 verified** | NO — not directly tested |
| **14.10 verified** | NO |
| **Reads from** | Hardware identity (IDPS), not mutable from software |
| **Confidence** | HIGH for existence. These check hardware identity, not the software-mutable `target_id` byte. Changing `target_id` in kernel memory may or may not bypass these checks |

---

## 2. Kernel data structures

### `security_flags` (kernel `.data` segment)

| Property | Value |
|---|---|
| **Type** | Dword in kernel data segment |
| **PS5 verified** | YES — present in every PS5 jailbreak offset table (1.00 through 13.60) |
| **14.10 offset** | `DATA_BASE + 0x0DA4064` (from ps5-payload-dev/sdk commit a7685ce8, 2026-10-12) |
| **Writable from userland** | NO — kernel data segment, not exposed by any syscall |
| **Repository evidence** | `docs/PRIVATE_UPSTREAM_1410_KERNEL_OFFSETS_2026-10-21.md` records this offset |

### `target_id` (at `security_flags + 0x09`)

| Property | Value |
|---|---|
| **Type** | Byte |
| **Values** | `0x80` = Diag, `0x81` = DevKit, `0x82` = TestKit, `0x83` = Retail (CEX) |
| **PS5 verified** | YES — used by all jailbreak implementations |
| **14.10 offset** | `DATA_BASE + 0x0DA406D` |
| **Writable from userland** | NO |

### `qa_flags` (at `security_flags + 0x24`)

| Property | Value |
|---|---|
| **Type** | Dword (or multi-byte field — PS4 documents 16 bytes of QA flags) |
| **PS5 verified** | YES — present in all offset tables |
| **14.10 offset** | `DATA_BASE + 0x0DA4088` |
| **Writable from userland** | NO |
| **PS4 bit layout** | Partially documented: byte[0] bit 0 = debug menu, byte[1] bit 0 = PSM debug. PS5 layout unverified |

### `utoken_flags` (at `security_flags + 0x8C`)

| Property | Value |
|---|---|
| **Type** | Byte |
| **PS5 verified** | YES — present in offset tables from FW 5.00+ |
| **14.10 offset** | `DATA_BASE + 0x0DA40F0` |
| **Writable from userland** | NO |

### `ucred` structure (process credentials)

| Property | Value |
|---|---|
| **Type** | Kernel structure per process |
| **PS5 verified** | YES — extensively probed |
| **Key fields** | `+0x58` = authid (Sony-specific, replaces FreeBSD MAC/jail), `+0x60` = sceCaps (capability bitmask), `+0x64` = capability word |
| **14.10 evidence** | Sys 587 reads `cred+0x58` region: `+0x08` (bit 62 word) is zero, `+0x0C` = `0x20000000` for game process. Identity at `+0x00` never readable, never writable (probes 332a/333a) |
| **Writable from userland** | NO — no handler writes authid |
| **Relevance to Debug Settings** | Indirect. The `sceSblRcMgr*` predicates read from `security_flags`, not from `ucred`. However, jailbreaks modify `ucred` for privilege escalation alongside flag writes |

### `allproc` (kernel global — linked list of all processes)

| Property | Value |
|---|---|
| **PS5 verified** | YES — in all offset tables |
| **14.10 offset** | `DATA_BASE + 0x28D9EA0` |
| **Relevance** | Used by jailbreaks to walk processes and find their own `ucred`. Not directly related to Debug Settings visibility |

### `prison0` / `rootvnode` (kernel globals)

| Property | Value |
|---|---|
| **PS5 verified** | YES |
| **14.10 rootvnode** | `DATA_BASE + 0x315B510` |
| **Relevance** | Used for sandbox escape (replacing process root). Not related to Debug Settings visibility |

---

## 3. Device nodes

### `/dev/icc_configuration`

| Property | Value |
|---|---|
| **Type** | Device node — ICC (Inter-Chip Communication) configuration |
| **PS5 wiki** | Listed on Devices page with long name "ICC Configuration" |
| **Opens from game process** | NO — refused (probe device inventory, 259a-268a) |
| **Relevance** | ICC stores hardware identity including target_id and QA flags in sflash/NVS. Reading or writing through this device could theoretically modify boot-time identity. Completely inaccessible from game process |
| **Confidence** | MEDIUM that this device is relevant. HIGH that it is inaccessible |

### `/dev/sbl_srv`

| Property | Value |
|---|---|
| **Type** | Device node — SBL (Secure Boot Loader) service |
| **Opens from game process** | NO — refused (probes 259a-268a, 273a) |
| **Relevance** | SBL handles security and crypto. The `sceSblRcMgr*` functions are kernel-internal and do not go through this device, but SBL manages the underlying security state |

### `/dev/qafutkn`

| Property | Value |
|---|---|
| **PS5 wiki** | Listed with long name "QA flag / Utoken" |
| **Opens from game process** | Not tested — not in the 76-node inventory from probe 259a |
| **Relevance** | Directly named after QA flags and utoken. If accessible, it could be a read (or write) interface to these flags. Almost certainly credential-gated |
| **Confidence** | HIGH relevance, LOW accessibility. A game process will not be able to open this device |

### `/dev/dipsw`

| Property | Value |
|---|---|
| **Opens from game process** | YES — in the open device list |
| **Relevance** | DIP switch state is hardware-fused. Reading it tells you the console type; writing is not possible (hardware fuse). Not a path to modifying identity |

---

## 4. Syscalls tested for flag modification

| Syscall | Name | Result on 14.10 | Relevance |
|---|---|---|---|
| 643 | `set_chicken_switches` | ret=0, all 32 bits accepted. No observable effect on any gate. Process-local field at `proc+0xa34` | NOT relevant — does not modify kernel globals |
| 560 | `debug_init` | `560(1)` ret=0, all other shapes ret=-1. No observable change | NOT relevant |
| 587 | credential read | ret=0, reads 0x88 bytes. Read-only. `+0x0C` = `0x20000000` | Read-only — cannot modify |
| 202 | `sysctl` | Write to `kern.securelevel` returns -1. All sysctl writes blocked | NOT relevant |
| 588 | `dmem_page_attr` | ret=0 but protection unchanged (hypervisor enforces) | NOT relevant |
| 548 | batch VM ops | All operation codes return -1 | NOT relevant |
| 675 | reset global state | ret=0, resets 3 globals. No effect on mprotect or W^X | NOT relevant |

---

## 5. Symbols NOT found

The following symbols were searched for and not found in any PS5-specific source:

| Symbol | Where searched | Result |
|---|---|---|
| `IsDebugMenuEnable` | PS4/PS5 wikis, GitHub, web search | Not found in any primary source |
| `SettingsRootHandler.OnCheckVisible` | PS4/PS5 wikis, GitHub, web search | Not found in any source |
| `SblRcMgrIsAllowDebugMenuForSettings` | PS5 binary analysis | Not found — no PS5 binary analyzed. Named only on community wiki |
| `sceKernelIsDebugMode` | PS5 sources | Not found on PS5. May exist as an internal predicate but is not a named export in available research |

---

## Sources

- [PS4 Developer Wiki — SBL Kernel module](https://www.psdevwiki.com/ps4/SBL_Kernel_module)
- [PS4 Developer Wiki — QA Flagging](https://www.psdevwiki.com/ps4/QA_Flagging)
- [PS5 Developer Wiki — Debug Settings](https://www.psdevwiki.com/ps5/%E2%98%85_Debug_Settings)
- [PS5 Developer Wiki — Button Combo Menus](https://www.psdevwiki.com/ps5/Button_Combo_Menus)
- [PS5 Developer Wiki — Devices](https://www.psdevwiki.com/ps5/Devices)
- [Hacking Adventures — PS4 RetailKit Part 2](https://www.hackingadventures.ca/posts/ps4-retailkit-part-2/)
- [cturt — Hacking the PS4, part 3](https://cturt.github.io/ps4-3.html)
- [AlexAltea/orbital](https://github.com/AlexAltea/orbital/blob/master/resources/boot/grub/env-common.cfg) — target_id values
- [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk) — 14.10 kernel offsets
- Local: `artifacts/usb_pre_reset_2026-10-20/PS4/APOLLO/*/kernel_offset.lua`
- Local: `docs/PRIVATE_UPSTREAM_1410_KERNEL_OFFSETS_2026-10-21.md`
- Local: `docs/ATTACK_SURFACE.md` — authid gates and credential analysis
- Local: `docs/agent-work/debug-settings/agent1/STATUS.md`
- Local: probes 55a, 55e, 257a/258a, 259a-268a, 332a/333a, 356a
