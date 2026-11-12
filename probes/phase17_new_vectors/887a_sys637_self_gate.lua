-- CRASH_CLASS: MODERATE
-- PROBE 887a: sys 637 -- does targeting self (pid 0) skip the capability gate?
--
-- Context: 13.60 Ghidra naming gives 637 = set_phys_fmem_limit, and every
-- earlier test of it returned -1: probe 51b called sc637(buf, 0x200) and got
-- 0xFFFFFFFF_FFFFFFFF (docs/ALL_RESULTS.md:4577, docs/ATTACK_SURFACE.md:202).
-- A public claim (X, kuzi, 2026-10-23, unverified) says that when the target
-- PID argument is 0/SELF, sys 637 skips its capability check and writes a
-- 64-bit value into kernel structures. If true, the shape we tested was wrong
-- (we passed a buffer, not a pid), and the handler accepts writes for self.
--
-- What we measure:
--   A. self pid via sys 20
--   B. 637(0, L) vs 637(pid, L) vs 637(pid, 0) -- does the pid change the gate?
--   C. observable side effects of an accepted call: sys 671 resource classes,
--      and a 256 MB mmap
--   D. same pid-0 idea on two other gated handlers (622, 601), last because
--      both have wedged the process in earlier probes

print("=== PROBE 887a: SYS 637 SELF-GATE ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function u64(hi, lo)
    return uint64(string.format("0x%08X%08X", hi, lo))
end
local function show(tag, ok, rv)
    if not ok then
        print(string.format("  [%s] PCALL-FAIL", tag))
        return
    end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X (lo=%u)", tag, h, l, l))
end

-- A. self pid
local sc20 = make_syscall(20)
local pid = 0
repeat
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
until true
print(string.format("[A] self pid = %u", pid))

-- C-prefix: resource-class baseline (671 sel=-1 mode=1: A=6144 B=3948 measured
-- in probe 55e). Read it before any 637 call so a change is attributable.
local function res_class(mode)
    local sc671 = make_syscall(671)
    local buf = memory.alloc(0x40)
    if not buf then return nil, nil end
    safe_wd(buf, 0)
    local ok, rv = pcall(function()
        return sc671(uint64(0xFFFFFFFF), uint64(mode), uint64(buf))
    end)
    if not ok then return nil, nil end
    return safe_rd(buf), safe_rd(buf + 4)
end
local a0, b0 = res_class(1)
print(string.format("[C0] 671 mode=1 before: A=%s B=%s", tostring(a0), tostring(b0)))

-- B. the gate test. L is a large but plausible 1 GiB limit so an accepted
-- write cannot starve the process we are running in.
local LIMIT = 0x40000000
local sc637 = make_syscall(637)

print("[B1] 637(0, 0x40000000) -- pid 0 / SELF:")
local ok1, rv1 = pcall(function() return sc637(uint64(0), uint64(LIMIT)) end)
show("637 self", ok1, rv1)

print(string.format("[B2] 637(%u, 0x40000000) -- explicit own pid:", pid))
local ok2, rv2 = pcall(function() return sc637(uint64(pid), uint64(LIMIT)) end)
show("637 pid", ok2, rv2)

print(string.format("[B3] 637(%u, 0) -- explicit own pid, zero limit:", pid))
local ok3, rv3 = pcall(function() return sc637(uint64(pid), uint64(0)) end)
show("637 pid 0-limit", ok3, rv3)

-- C. did an accepted call change anything we can see?
local a1, b1 = res_class(1)
print(string.format("[C1] 671 mode=1 after:  A=%s B=%s", tostring(a1), tostring(b1)))
print(string.format("  A delta = %s", tostring((a1 or 0) - (a0 or 0))))

local sc477 = make_syscall(477)
local okm, rvm = pcall(function()
    return sc477(uint64(0), uint64(256 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
show("mmap 1MB-after-637", okm, rvm)

-- D. does the pid-0 idea generalise? Both of these were non-lethal at their
-- first command in earlier probes (55b/55d); they stay last.
print("[D1] 622 cmd 0x100 with arg1=0:")
local sc622 = make_syscall(622)
local buf622 = memory.alloc(0x80)
safe_wd(buf622, 0)
local okd1, rvd1 = pcall(function()
    return sc622(uint64(0), uint64(0x100), uint64(buf622), uint64(0x80))
end)
show("622 arg1=0", okd1, rvd1)
print(string.format("  buf622[0]=0x%08X", safe_rd(buf622) or 0))

print("[D2] 601 cmd 0x00 with p1=0:")
local sc601 = make_syscall(601)
local buf601 = memory.alloc(0x80)
safe_wd(buf601, 0)
local okd2, rvd2 = pcall(function()
    return sc601(uint64(0), uint64(0), uint64(buf601), uint64(0x80))
end)
show("601 p1=0", okd2, rvd2)
print(string.format("  buf601[0]=0x%08X", safe_rd(buf601) or 0))

print("")
print("=== PROBE 887a DONE ===")
