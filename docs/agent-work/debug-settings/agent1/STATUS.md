# Agent 1 — Debug Settings Research Status

Last updated: 2026-11-09

## Objective

Make the genuine native Debug Settings entry appear in the PS5 14.10 Settings menu. No browser imitation or game overlay. A visible entry is sufficient; functional developer options are not required.

## Current Assessment: B- -- KASLR DEFEATED, KERNEL R/W STILL NEEDED

KASLR is defeated via the fault-code oracle (probes 1199a-1199c, 2026-11-04). The kernel image base, size and slide are known per-boot. The remaining blocker is a kernel R/W primitive. The WebKit FontFace UAF (CVE-2026-43715 variant) is the only live exploitation path -- heap pointer leak confirmed, 100% reclaim reliability, but WebProcess text base is unknown (all info-leak routes exhausted). Once kernel R/W is achieved, the known `DATA_BASE + 0x0DA4064` offset (ps5-payload-dev/sdk) can be written to enable Debug Settings.

### Evidence for this conclusion

1. **Apollo/GoldHEN kernel_offset.lua** (PS4/PS5 cross-firmware): Debug Settings visibility is controlled by `DATA_BASE_SECURITY_FLAGS` + offset `0x09` (`TARGET_ID`) and `+ 0x24` (`QA_FLAGS`) in the kernel's `.data` segment. These are **kernel virtual addresses** at fixed offsets from the kernel base. Changing them requires kernel R/W + KASLR defeat.

2. **PS5-UMTX-Jailbreak** (public): explicitly documents that Debug Settings appears only after arbitrary kernel R/W is established. The sequence is: kernel exploit -> KASLR defeat -> kernel R/W -> write QA/security flags -> exit and reopen Settings.

3. **etaHEN** (public): replaces Debug Settings with its own Toolbox by patching the ShellUI process. This also requires kernel R/W to inject into ShellUI's address space.

4. **Gezine 14.10 demonstration** (2026-10-20): showed Debug Settings visible on 14.10. Stated the 13.xx kernel exploit was patched on 14.00 and this is not Relapse. Method undisclosed. Confirms the menu CAN appear on 14.10 but does not provide a path.

5. **Syscall 643 `set_chicken_switches`** (13.60 analysis + 14.10 probes): ORs bits into `process+0xa34` of the CALLING process with no capability check. Probe 55a tested all 32 bits; probe 356a tested `0xFFFFFFFF`. Result: **no observable effect** on mprotect(RWX), sys 618/646/532 gates, sandbox policy, or syscall filtering. This field is process-local and does not affect the Settings/ShellUI process or kernel globals.

6. **Syscall 560 `debug_init`** (probes 257a/258a): `560(1)` returns 0, all other shapes return -1. After the call, no observable change to any gate: sys 656, 593, 634, mprotect(RX), mprotect(RWX), sys 643 all behave identically. Dead.

7. **No kernel pointer found** across ~400 tested BSD syscalls, 34 `/dev` nodes, all CTL_* sysctl trees, full signal frame, routing sockets, all ancillary data paths, and 8.3M+ GPU-allocated qwords. KASLR is undefeated.

8. **No kernel R/W primitive exists on 14.10**: the AIO double-free (probe 65l) is the first confirmed kernel memory corruption, but exploitation (heap spray, controlled reclaim, readback) has not been demonstrated.

## Paths Evaluated

| Path | Status | Blocker |
|------|--------|---------|
| Kernel flag write (QA_FLAGS/TARGET_ID/SECURITY_FLAGS) | BLOCKED | Requires kernel R/W + KASLR defeat |
| ShellUI process patch | BLOCKED | Requires kernel R/W to inject into another process |
| sys 643 chicken switches | DEAD | Process-local, no cross-process or kernel-global effect |
| sys 560 debug_init | DEAD | Returns 0 but changes nothing observable |
| sys 587 credential metadata | DEAD | Read-only, returns single capability bit 0x20000000 |
| sys 643 bit 62 in cred+0x60 | BLOCKED | Zero and unreadable (probe 55e) |
| sysctl write (securelevel etc.) | INCOMPLETE | One securelevel-labeled write returned -1 (probe 43f); other candidate writes conditional on failed reads and never reached. Not an exhaustive survey |
| Userland config file/registry | NOT FOUND | No accessible config store controls Settings menu |
| IPC to Settings/ShellUI | NOT FOUND | No accessible IPC channel to Settings process |
| Notification system | INVESTIGATED | sys 587/notification devices open but cannot inject menu items |

## Additional Paths Investigated During Audit

9. **libSceRegMgr.sprx (handle 51)**: Loaded in the game process. The PS5 system registry stores console settings including IDU mode and debug flags. The kernel-side registry interface (syscall 532 `regmgr_call`) privilege-gates most commands via `priv_check(td, 682)`. However, commands 0x18-0x1F, 0x2F, and 0x20 bypass this check and reach the handler — they fail at the registration table lookup (table is empty for a game process, all return `0x800D0203`). The library can't perform useful registry operations from the game's privilege level, but the dispatch IS partially reachable. (probes 192a, 307a, 433a)

10. **Syscall 591 (dlsym)**: Returns error for ALL handles (0-50) and ALL symbol name formats (C names and NID hashes). Cannot resolve library function addresses for direct calling (probe 66a, 2026-10-23).

11. **libSceSystemService.sprx (handle 142)**: Loaded in the game process, but no tested interface to communicate with ShellUI. The library's .text is XO (unreadable), and dlsym fails.

12. **Syscall 532 `regmgr_call` command analysis** (13.60 decompile + 14.10 probes): Commands 0x18-0x1F, 0x2F, and 0x20 bypass `priv_check` and reach the handler. They pass through a handle integrity check → registration table lookup that is EMPTY for a game process. Reachable commands return status errors/constants (`0x800D0203` = type/table lookup failure, `0x800D0204`, etc.). The handle checksum is forgeable (probe 429a-433a) but the registration table is empty, so every forged handle resolves to nothing. No Debug Settings influence demonstrated, but the handler is partially exercisable.

13. **Compositor sockets** (/system_tmp): Accept connections from the game jail but operate on a simple request-response protocol. Writing 8KB blacks the screen — DoS only, no menu injection. Library `.rodata` is XO, so the protocol can't be reverse-engineered from userland.

## Remaining Candidates

### 1. AIO double-free -> kernel R/W -> flag write (LONG PATH)
The only path that could eventually work requires exploiting the confirmed AIO double-free to get kernel R/W, then defeating KASLR, then writing the appropriate kernel data flags. This is a full kernel exploit chain — the core of the overall project, not specific to Debug Settings.

### 2. Unknown Sony IPC or registry mechanism
It's possible that a Sony-specific IPC message, sysctl, or configuration write could request Debug Settings visibility without kernel R/W. No evidence for this exists in the repository. The Settings app runs in a separate, more privileged process (ShellUI). All tested communication paths (compositor sockets, notifications, syscalls) are either blocked or inert.

### 3. Hardware/manufacturing mode trigger
PS5 devkits and testkits have Debug Settings natively. The distinction is the `TARGET_ID` byte in kernel data. No userland path to change this has been found. The sysarch, sysctl, and chicken-switch interfaces do not reach it.

## Blockers

1. ~~**No KASLR defeat**~~ **RESOLVED (2026-11-04):** Fault-code oracle defeats KASLR for the kernel image base per-boot. Probes 1199a-1199c sweep 512 candidates in 33s. Kernel image at `0xFFFFFFFFD4000000` (102 MB), slide `+0x54000000`. Presence-only (content unreadable due to supervisor bit). See `docs/FAULT_CODE_ORACLE_14_10.md`.
2. **No kernel R/W** — the WebKit FontFace UAF (CVE-2026-43715 variant) is the only live path. AIO double-free is dead (double-STATUS, not double-free). Canvas2D UAF is a control primitive, not an info-leak.
3. **W^X enforced at hypervisor level** — even kernel-level mprotect cannot grant execute permission
4. **Process isolation** — the game process cannot modify ShellUI's memory or kernel globals
5. **WebProcess text base unknown** — hard blocker for any WebKit code-reuse chain. All known info-leak routes are dead (p630-p658). Need a new 605.1.15-era WebKit CVE or an indirect leak path.

## DS-0 Result (2026-10-24)

Offline artifact search completed. No version-matched Settings visibility contract found in the repository. Searched all kernel handler analyses, sysent name CSVs, SDK source, Apollo offsets, webkit crossrefs, and probe results across sys 532/591/606/619/622/643/649. No Settings binary, no ShellUI binary, no Settings NID/export, and no documented service contract for menu visibility exists in local artifacts.

The kernel predicate `SblRcMgrIsAllowDebugMenuForSettings` (Agent 2, HIGH confidence) reads kernel `.data` flags. The 14.10 offset is `DATA_BASE + 0x0DA4064` (ps5-payload-dev/sdk). All four writes are documented (see INTEGRATION.md). Both require kernel R/W + KASLR defeat.

DS-1, DS-2, and DS-3 are CLOSED — DS-0 produced no service contract to test against.

## Next Actions (Updated 2026-11-09)

1. **Primary path:** WebKit FontFace UAF chain to establish kernel R/W. KASLR is defeated. Need: (a) WebProcess text base leak, (b) code-reuse chain through forged vtable dispatch.
2. ~~**KASLR defeat:**~~ **DONE** (fault oracle, probes 1199a-1199c, 2026-11-04)
3. **Monitor public disclosures:** Gezine demonstrated Debug Settings on 14.10 (2026-10-20), method undisclosed. GTA 6 launch (2026 holiday) creates urgency for community jailbreak.
4. **Kernel image acquisition:** A plaintext 14.10 kernel would verify the `0x0DA4064` offset and reveal heap object layouts for spray targeting
5. **WebProcess text base:** All known routes exhausted (p630-p658). Need new WebKit 605.1.15-era CVE or indirect leak path (JIT CodeBlock pointer via heap grooming, etc.)
