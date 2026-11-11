# PS5 14.10 Kernel Research — AI Guide

## What This Project Is

Systematic kernel exploit research on PlayStation 5 firmware 14.10. Goal: **userland code exec → kernel R/W → hypervisor bypass**. We have userland code execution via a Lua 5.1 loader on TCP 9026. We need kernel memory access.

## Session Protocol

Context compacts; memory does not survive it, files do. Two files carry a session:
`results/STATE.md` (mutable, rewritten in place) and `results/INDEX.md` (append-only ledger).

**Start, in this order:**
1. `python tools/state.py check --ip <console>` — prints state, last ten ledger rows, port 9026 status.
2. Re-measure kernel base with `.local/1331a.lua` (re-randomises on every reboot).
3. `grep -rn "<topic>" results/INDEX.md docs/ probes/` before writing a probe. Add `-- prior art:` header.

**After every run:** `python tools/state.py row <probe> --claim "..." --result "..." --grade M|V|S|D`
then `python tools/state.py set last_probe=... next_action=...`

**Grades:** `M` measured · `S` source-read · `I` inference · `V` void (no evidence) · `D` dead end

**Void captures:** 55c (arg4=0x100, entry-check reject), 54o/54p/55g (no post-call marker), 1334a budget rows (died at 568).

## Key Research State

**Confirmed capabilities:** KASLR defeat (fault oracle), heap R/W (GPU mmap), userland ASLR bypass (dynlib_get_info 593), child thread ROP syscalls (5-arg via thr_new 455), CClosure redirect (selected targets), native.fcall_with_rax, network packet injection, WebKit Canvas2D UAF (CVE-2026-43720), FontFace UAF chain (VP leaked at p691).

**Hard blockers:** W^X enforced (bit 0x4 refused), no kernel R/W primitive, WebProcess text base RVA pending, heap NX (no JIT on PS5), DFG/FTL OFF.

**Active vector:** WebKit FontFace UAF — VP leaked, RVA determination needed. Canvas2D getContext reentry UAF confirmed as control primitive.

**Reference docs (load when needed):**
- `docs/DEAD_ENDS_REFERENCE.md` — all ~140 confirmed dead ends
- `docs/ATTACK_PRIORITY_REFERENCE.md` — active vectors, WebKit details, blockers
- `docs/FINDINGS.md` — detailed technical findings
- `docs/ATTACK_SURFACE.md` — complete syscall status map
- `docs/PROBE_INDEX.md` — every probe with status

## Continuation System

When resuming (`continue`):
1. Read `results/STATE.md` for last checkpoint
2. Read `results/INDEX.md` tail for recent work
3. Verify git state (`git log --oneline -5`, `git status`)
4. Resume next unfinished action from checkpoint

Checkpoint file: `results/CHECKPOINT.md` — written after each milestone.

## How to Write Probes

### Template
```lua
-- CRASH_CLASS: LOW | MODERATE | HIGH | RISKY
-- PROBE XX: one-line description
-- Context: what we know, what we're testing, why

print("=== PROBE XX: TITLE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
```

### Lua 5.1 Constraints
1. **uint64 for addresses >32 bits:** `uint64(string.format("0x%X%08X", hi, lo))`
2. **pcall everything risky**
3. **No `goto`/labels** — use `repeat...until true` + `break`
4. **XO pages kill past pcall** — never read system lib .text. Eboot .text is RX and safe.
5. **Fresh ASLR every connection** — never hardcode addresses
6. **memory.alloc(N)** for heap buffers; zero before use
7. **Kernel pointer detection:** `h >= 0xFFFF8000` (but `0xFFFFFFFF_*` are sentinels)

### Key Patterns
```lua
-- make_syscall usage
local sc = make_syscall(202)  -- sysctl
local ret = sc(arg1, arg2, arg3, arg4, arg5, arg6)

-- Module base discovery (userland only, not kernel ASLR)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(handle), info) end)

-- GPU mmap (heap R/W)
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(512*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
```

## Sending Probes

```bash
# Python
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua

# PowerShell
.\tools\send_probe.ps1 probes\<phase>\<name>.lua -Save
```

## Repository Layout

```
probes/         — Lua/HTML probes by phase (phase1-phase17+)
results/        — Output logs, STATE.md, INDEX.md, CHECKPOINT.md
docs/           — Technical findings, evidence audits, reference docs
tools/          — send_probe.py, state.py, analysis scripts, tests
evidence/       — Ghidra references, handler analysis
swarm/          — Multi-agent infrastructure
```

## When Analyzing Results

1. **Kernel pointers** are `0xFFFF8xxx_xxxxxxxx`. Values like `0xFFFFFFFF_00000000` are sentinels.
2. **ret=0** = success, **ret=-1** = failure, **ret=-999** = pcall crash.
3. Cross-reference `docs/FINDINGS.md` and dead ends before declaring something new.
4. A kill does not prove a slot is absent — see `docs/SYSCALL_ABSENT_VS_LETHAL.md`.

## Evidence Rules

- Never claim kernel R/W without device-tested evidence
- Distinguish: userland corruption ≠ kernel base discovery ≠ kernel memory access
- A void capture proves nothing; cite captures with post-call markers
- Update `results/STATE.md` and `results/INDEX.md` after every run
- Check `docs/DEAD_ENDS_REFERENCE.md` before re-investigating a topic

## Git Conventions

- **Author:** Rithik Janarthanan <janarthananrithik@gmail.com>
- **No AI attribution** in commits, PRs, or code.
- Short, descriptive commit messages.
