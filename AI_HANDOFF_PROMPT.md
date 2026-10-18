# PS5 14.10 Kernel Exploit Research — AI Handoff Prompt

Historical handoff notes follow. For current scope, read [the ledger guide](docs/RESEARCH_EVIDENCE.md) and the probe index: later 56c/56f record selected existing Lua C redirects, distinct from the unsupported fn_addr/ROP model. Internal dispatch, arbitrary ABI and kernel access remain unverified.

---

## ROLE

You are continuing PS5 firmware 14.10 kernel exploit research. The repo is at `https://github.com/ZigZagBoi1/ps5-14.10-research`. Clone it first. Read `CLAUDE.md` thoroughly — it has all environment constraints, probe patterns, and dead ends.

## WHAT EXISTS

**Target:** PS5 at 10.0.0.96:9026, firmware 14.10, FreeBSD r230171, 16KB pages.
**Entry:** Lua 5.1 scripts sent via `python tools/send_probe.py --save <probe.lua>`.
**Per-connection ASLR:** Every TCP connection spawns a fresh process. All addresses must be re-derived each run.

**Working primitives:**
- `make_syscall(N)` — tested syscall invocation bypasses the Lua resolver filter; kernel authorization still applies
- Heap R/W via GPU mmap (256+ pages, no guard pages)
- Userland ASLR bypass via dynlib_get_info(593) — 39 modules
- Network: RAW socket + IP_HDRINCL

**Hard walls (don't waste time):**
- No fn_addr/ROP execution established; later selected CClosure results are separate userland evidence
- W^X enforced (mmap RWX → RW only, mprotect EXEC always fails)
- XOM on system libs (reading .text crashes process; eboot is RX)
- No threading (fork/rfork/thr_new all blocked)
- No kernel pointers found in any test so far
- KASLR defeat NOT achieved

## CRITICAL CORRECTIONS — READ BEFORE TOUCHING PROBES

The overnight batch (probes/phase14_final_push/) was written by AI subagents that made errors. A subsequent audit found:

1. **Syscall 565 is NOT RDMSR.** The probe `54i_sys565_rdmsr_copyout.lua` was built on a wrong assumption. The verified handler analysis says 565/566 are PTE-related with "different index ranges". Syscall 626 is the actual RDMSR handler. The "667 bytes copied to userspace" claim for sys 565 is wrong — the actual RDMSR read handler is syscall **567**, and it copies **8 bytes**, not 667. 0x29b (667) was a line-number argument to an internal call, not a copy length.

2. **Syscall 567 returned -1 for every counter** when tested with the corrected probe. Output and guard bytes were untouched. This path does not currently produce a disclosure.

3. **Syscall 572 returns a 72-byte userland VM-mapping record** (start/end addresses, protection bits, "SceLibcHeap" name). It's useful for mapping user memory but does NOT leak kernel addresses or PTEs.

4. **Syscalls 563/564 return 0** (success) but their effect is PMC configuration, not info leak.

5. **`tools/quick_send.sh` may not exist** in the local tools listing despite being claimed as committed. Verify before relying on it.

6. **Many 54-series probes have NOT been run on the PS5 yet.** Do not assume any results. The following have been run by the audit AI and produced no kernel pointers: 567 (ret=-1), 572 (userland VM record), 563/564 (ret=0, PMC config).

## WHAT TO ACTUALLY DO

### Step 1: Verify loader connectivity
Send a trivial identity probe first:
```lua
print("=== CONNECTION TEST ===")
print("Firmware: " .. (tostring(syscall.version) or "unknown"))
local sc20 = (function() local t = {} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=20 setmetatable(t, getmetatable(syscall.pipe)) return t end)()
local ok, pid = pcall(function() return sc20() end)
if ok then print("PID: " .. tostring(pid)) else print("getpid failed") end
print("=== DONE ===")
```

### Step 2: Run these probes in order (highest probability first)

**Priority 1 — `54f_kaslr_deep.lua`** (8 KASLR attempts in one probe)
BUT first audit it: check sections A-H for the same syscall-mislabeling errors. Section G (AIO 661-670) is the most valuable — these have NEVER been tested on 14.10. Section F (sys 593 deep scan of all 39 modules) is also high-value — previous scans only checked text base, not the full 0x160-byte struct.

**Priority 2 — `54a2_rdmsr_precise.lua`** (sys 626 RDMSR/WRMSR)
This targets the correct syscall (626). If WRMSR works on LSTAR, that's kernel code execution. But sys 626 returned -1 in the 51b survey, so manage expectations.

**Priority 3 — `54b_jail_bypass.lua`** (sys 629, cmpq $1 fast path)
Byte-verified conditional in 13.60 handler. Quick test.

**Priority 4 — `54c_aio_full_attack.lua`** (AIO 661-670)
Full AIO chain with pointer deobfuscation (x ^ (x>>4)) and stack clash. This is the Relapse jailbreak's target vector, never tested on 14.10.

**Priority 5 — `53a_aio_retest.lua`** (AIO survival test)
If 54c or 54f Section G crash, this tests whether AIO calls actually kill the process or just return errors.

**Priority 6 — `54d_dmem_page_flip.lua`** (sys 588 page attrs)
No priv_check in 13.60 handler. If it can set RWX on GPU mmap pages, that's W^X bypass.

**Priority 7 — `53b_afroute_retest.lua`** (AF_ROUTE KASLR)
Relapse technique, previous test was botched. Properly formed RTM_GET.

### Step 3: For each result, look for:
- `>>> KPTR` — kernel pointer found (KASLR defeat)
- `WRMSR SUCCEEDED` — can write MSRs (kernel code exec path)
- `ret=0` on prot=7 in 54d — RWX memory achieved
- `NEWLY ACCESSIBLE` in 54b — jail bypass unlocked syscalls
- Any non-zero buffer contents after a ret=0 syscall
- Any value in 0xFFFF8000_00000000 to 0xFFFFFFFE_FFFFFFFF range

### Step 4: If any probe yields a kernel pointer
Follow-up probes are pre-written:
- `55a_post_kaslr_kread.lua` — kernel memory reader (fill in kernel_base)
- `55b_post_kaslr_kwrite.lua` — kernel write for uid=0
- `55c_msr_code_exec.lua` — if WRMSR works
- `55d_rwx_shellcode.lua` — if DMEM page flip works
- `55e_aio_race.lua` — if AIO survives
- `55f_post_jail.lua` — if jail bypass works

These need a `kernel_base` value filled in from the leak. The sysent table is at kernel_base + 0xe6e5c0.

## KEY REFERENCE FILES
- `CLAUDE.md` — environment, constraints, probe template, ALL dead ends
- `docs/VERIFIED_HANDLER_ANALYSIS.md` — 8 critical findings from 13.60 handler RE (4 byte-verified, 4 plausible)
- `docs/WEBKIT_FINDINGS.md` — WebKit entry vector (JSC Bug 317632, heap corruption + OOB read on 14.10)
- `docs/FINDINGS.md` — detailed technical findings
- `docs/ATTACK_SURFACE.md` — complete syscall status map
- `evidence/2026-10-18-implementation-followup/implementation-research/IMPLEMENTATION_RESEARCH_REPORT.md` — deep AIO 663 handler analysis (801 instructions)
- `evidence/deep_result_scan.md` — forensic scan of all existing results
- `tools/analyze_result.py` — auto-analyzer for probe output (if it exists)

## RULES
1. **Read CLAUDE.md fully before writing any probe.** It has Lua 5.1 constraints, the make_syscall pattern, uint64 requirements, and 50+ documented dead ends.
2. **Verify claims against raw bytes before acting on them.** The overnight batch had syscall mislabeling errors. Cross-check handler numbers against `docs/ps5_13.60_sysent.json`.
3. **Every address must be re-derived per connection.** Never hardcode addresses. Use dynlib_get_info or tostring(syscall.pipe).
4. **pcall everything.** XO page reads and bad syscall args kill the process.
5. **Kernel pointers: h >= 0xFFFF8000 AND h < 0xFFFFFFFF.** Values like 0xFFFFFFFF_00000000 are bitmasks/sentinels, NOT pointers.
6. **No AI attribution in commits, PRs, or code.** Author: ZigZagBoi1 <marwantech2004@gmail.com>
7. **Don't repeat dead ends** — the list in CLAUDE.md is extensive. Read it.
8. **Be honest about what is verified vs. speculative.** The previous AI session was too optimistic in places.

## THE HONEST ASSESSMENT

No kernel vulnerability or KASLR bypass has been demonstrated on 14.10. The strongest remaining leads are:
1. **AIO 661-670** — completely untested on 14.10, verified exploitable patterns in 13.60 dumps
2. **sys 626 RDMSR** — 39 RDMSR opcodes in 13.60 handler, but returned -1 in survey (may need correct arg format)
3. **sys 629 jail bypass** — byte-verified cmpq $1 conditional, never tested
4. **sys 593 deep struct scan** — previous scans only checked module base fields, not the full 0x160 bytes across all 39 modules
5. **AF_ROUTE RTM_GET** — Relapse KASLR technique, previous test was malformed

The PS5's kernel sandbox is strong. Most obvious paths are blocked. But the AIO subsystem and several Sony-custom syscalls have never been properly tested on this firmware. That's the gap.
