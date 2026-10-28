# Agent 1 — Cross-Agent Integration

Last updated: 2026-10-24 (post-integration with Agent 2 and Agent 3)

## Feasibility Rating

**C — the genuine Debug Settings visibility mechanism on 14.10 has not been recovered.**

- **B** applies to the specific protected routes already tested: kernel flag writes, ShellUI injection, syscall 643/560, privilege-gated 532 commands, and compositor IPC. These are measured refusals.
- **A** (documented unprivileged route) has no supporting evidence.
- The public PS5 exploit implementations all use kernel R/W to write kernel `.data` flags, but that does not prove every possible 14.10 route requires kernel R/W — only that no alternative has been identified.

This rating follows Agent 3's framework and is more epistemically honest than the earlier "NOT ACHIEVABLE FROM USERLAND ALONE" absolute, which overstated what the evidence can support.

## Agent 2 Findings (branch `debugsettings/agent2`, commit 5601441)

### 14.10-Specific Offset
- **`DATA_BASE + 0x0DA4064`** for `security_flags` on 14.10 (from ps5-payload-dev/sdk)
- 13.60 offset was `0x0D79064` — the delta is `+0x2B000`, consistent with typical firmware drift
- Source: Agent 2's `ACCESS_REQUIREMENTS.md`

### Kernel Predicate: `SblRcMgrIsAllowDebugMenuForSettings`
- Agent 2 identified this as the Settings-side gate function (HIGH confidence)
- Calls `sceSblRcMgrIsAllowDebugMenuForSettings()` which reads four kernel `.data` fields
- Returns nonzero → Debug Settings entry visible in the native Settings app
- The `sceSblRcMgr*` family includes `IsAssist`, `IsAllowULDebugger`, `IsAllowSLDebugger`, etc.
- `IsDebugMenuEnable` and `SettingsRootHandler.OnCheckVisible` are LOW confidence (not found in 14.10 symbols)
- Source: Agent 2's `SYMBOL_REFERENCE_MAP.md`

### Agent 2 Minimum Viable Path
1. Defeat KASLR (no known method on 14.10)
2. Establish kernel R/W (AIO double-free unexploited)
3. Write four kernel `.data` fields (recipe below)
4. Exit and reopen Settings

### Agent 2 Four Write Approaches Evaluated
1. **Kernel flag write** — requires kernel R/W → BLOCKED
2. **ShellUI binary patch** — requires kernel R/W → BLOCKED
3. **GPU DMA bypass** — requires kernel exploit → BLOCKED
4. **Supported service API** — no contract identified → UNKNOWN

## Agent 3 Findings (branch `debugsettings/agent3`, commit 49734bd)

### Corrections to Agent 1 Claims
Agent 3 identified three inaccuracies in Agent 1's STATUS.md (now corrected):

1. **Syscall 532 reachability**: STATUS.md stated "all commands return -1." Incorrect. The 14.10 argument map (probe 307a) shows commands 0x18-0x1F, 0x2F, 0x20 bypass `priv_check` and return status errors/constants (`0x800D0203`, `0x800D0204`). These reach the handler but fail at the registration table lookup (table is empty for game process). The distinction matters: the handler IS reachable for a subset, it just has nothing to operate on.

2. **Sysctl write survey**: STATUS.md stated "all sysctl writes fail." Incomplete. Only one securelevel-labeled write was attempted (probe 43f, returned -1). Other candidate writes in that probe were conditional on reads that themselves failed, so the writes were never reached. This is not an exhaustive write survey.

3. **Syscall 585 label**: TEST_QUEUE T-001 called sys 585 "PID discovery." The corrected label is `is_in_sandbox` (returned 1 on 14.10). A process list would not authorize Settings access regardless.

### Agent 3 Capability Matrix
Rigorous distinction between "working" and "unproven":
- **Working:** Lua entry, native execution (child thread marker), syscall invocation, module enumeration, app-scoped files, selected sysctl reads, AF_UNIX connects to 3 compositor sockets
- **Unproven:** Settings-facing service contract, game-authorized config write, meaningful debug setter, Settings process memory access, kernel R/W

### Agent 3 Test Proposals (DS-0 through DS-3)
See TEST_QUEUE.md for Agent 1 disposition on each.

### Agent 3 System Boundary Map
- Game process (UID 1, sandboxed) → kernel authorization boundary → privileged system processes → Settings application (visibility decision unknown)
- No direct game-to-Settings call is supported by any capture
- Module presence (`libSceRegMgr`, `libSceSystemService`) establishes loaded stubs, not callable APIs

## Exact Debug Settings Kernel Writes (from public PS5 exploit source)

Source: Cryptogenic's `PS5-IPV6-Kernel-Exploit` (`document/en/ps5/exploit.js`), confirmed across FW 3.00-4.51 and cross-referenced with Apollo 13.60 PS5 offsets.

All offsets are relative to the kernel data segment base (`data_base_addr`), NOT kernel .text base. The structure offsets `+0x09`, `+0x24`, `+0x8C` from `SECURITY_FLAGS` are constant across every known firmware (3.00-13.60).

| # | Target | Operation | Value | Size |
|---|--------|-----------|-------|------|
| 1 | `SECURITY_FLAGS` (u32) | OR | `0x14` | 4 bytes |
| 2 | `TARGET_ID` (SF+0x09, u8) | SET | `0x82` (DEX target) | 1 byte |
| 3 | `QA_FLAGS+1` (SF+0x25, u16) | OR | `0x103` | 2 bytes |
| 4 | `UTOKEN_FLAGS` (SF+0x8C, u8) | OR | `0x01` | 1 byte |

Order: security_flags -> target_id -> qa_flags -> utoken_flags.

After writing: fully exit Settings and reopen to refresh the menu.

### Firmware-specific `SECURITY_FLAGS` base offsets

| Firmware | `SECURITY_FLAGS` RVA from DATA_BASE | Source |
|----------|--------------------------------------|--------|
| 3.00-4.51 | per-FW table in exploit.js | Cryptogenic |
| 13.60 | `0x0D79064` | Apollo kernel_offset.lua |
| 14.10 | `0x0DA4064` | ps5-payload-dev/sdk (Agent 2) |

### 14.10 blockers for this path

1. The kernel data segment base address is UNKNOWN (no KASLR defeat)
2. No kernel R/W primitive exists (AIO double-free is confirmed but unexploited)
3. The `0x0DA4064` offset needs independent verification (single SDK source)

### How other jailbreaks reach these addresses

- **PS5-UMTX-Jailbreak**: kernel exploit → KASLR defeat (pipe buffer kptr leak) → kernel R/W via corrupted pipe → write flags
- **P2JB/Poops**: kernel exploit → GPU DMA to bypass kernel .data read-only → write flags
- **etaHEN**: same kernel R/W → patches ShellUI instead of/in addition to flags

## Consensus Across All Three Agents

All three agents independently concluded:
1. No userland path to Debug Settings has been identified
2. The known path requires kernel R/W + KASLR defeat
3. The AIO double-free is the most promising kernel primitive but is unexploited
4. No Settings-facing service contract is documented for 14.10

Differences:
- Agent 1 initially rated the situation as "NOT ACHIEVABLE FROM USERLAND" (absolute)
- Agent 2 concluded "no userland path" with focus on the four-write recipe
- Agent 3 rated "C — unknown" noting the Settings predicate itself hasn't been recovered, so an undiscovered supported route can't be ruled out definitively
- The integrated rating is **C** — honest about what we don't know

## What Offline Agents Should Investigate Next

1. **DS-0 (Agent 3 proposal, APPROVED)**: Search local artifacts for a version-matched 14.10 Settings visibility contract. No console interaction.
2. **14.10 kernel image analysis**: If the encrypted kernel can be analyzed, locate the SECURITY_FLAGS structure and verify the `0x0DA4064` offset.
3. **ShellUI binary analysis**: If a PS5 ShellUI binary is available from public sources, analyze the Debug Settings visibility check implementation.
4. **Gezine's method**: Monitor public disclosures. The 2026-10-20 post shows it's possible on 14.10 but the method is private.

## Cross-References

- `JAILBREAK_CHAIN_14_10.md`: Gates 1-6 document the full chain. Debug Settings is effectively Gate 5 (persistent privilege/policy effect) or later.
- `docs/AIO_DOUBLE_FREE_14_10.md`: The only confirmed kernel memory corruption primitive. If exploited, this is the path to kernel R/W which would unlock Debug Settings.
- `docs/ATTACK_SURFACE.md`: Full syscall status map showing what's accessible.
- `docs/agent-work/debug-settings/agent2/ACCESS_REQUIREMENTS.md`: Agent 2's detailed requirements hierarchy and 14.10 offset.
- `docs/agent-work/debug-settings/agent2/SHELL_VISIBILITY_REPORT.md`: Settings architecture analysis.
- `docs/agent-work/debug-settings/agent2/SYMBOL_REFERENCE_MAP.md`: Symbol confidence ratings.
- Agent 3 deliverables in separate checkout (`C:\...\PS5-14.10-Research-agent3\docs\agent-work\debug-settings\agent3\`): USERLAND_CAPABILITY_MATRIX.md, TEST_PROPOSALS.md, SYSTEM_BOUNDARY_MAP.md.
