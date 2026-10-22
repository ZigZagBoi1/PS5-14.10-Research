-- CRASH_CLASS: MODERATE
-- PROBE 237a: the live AIO batch path, 660 handles, and a real protection oracle
--
-- Context: 235a reached three things that no six-zero sweep could.
--   659 returns 0 with count=3 and two non-zero handles (0x13, 0x14).
--   660 rejects those handles with -1 while leaving size=0x160.
--   662/664/663 with count=1 return ret=0 and a per-item status of 0x80020003,
--     so the AIO batch handlers RUN on 14.10 and reject the item, rather than
--     killing the process. Every earlier 661-670 sweep was refused by the
--     count check (contract: 1..128) or died at 661/665.
--
-- This probe asks three separate questions:
--   [A] 659 again, printing every slot, so the handle space is known.
--   [B] 660 with each candidate handle and with the size gate set to something
--       other than 0x160, to see whether -1 is the handle or the gate.
--   [C] 662/663/664 across id encodings (the contract splits an id into a high
--       16-bit slot index and a low 16-bit handle), looking for any status
--       other than 0x80020003.
--   [D] 547 as the protection oracle: mmap a GPU page, read its region record,
--       call mprotect(RWX), read it again. The earlier W^X result was measured
--       by mprotect's return value alone; 674 cannot see these mappings
--       (235a reported not-found for both), 547 is the handler that reports
--       the effective protection of one address.

print("=== PROBE 237a: LIVE AIO PATH, 660 HANDLES, PROTECTION ORACLE ===")
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
    if type(val) == "number" then val = uint64(val) end
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return "-1" end
        return string.format("0x%08X_%08X", h, l)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

print(string.format("PID: %d", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local sc659 = make_syscall(659)
local sc660 = make_syscall(660)
local sc662 = make_syscall(662)
local sc663 = make_syscall(663)
local sc664 = make_syscall(664)
local sc547 = make_syscall(547)
local sc477 = make_syscall(477)
local sc74 = make_syscall(74)

-- ============================================================
-- [A] 659: enumerate module handles
-- ============================================================
print("")
print("[A] 659 { handles_out, capacity, count_out }")

local CAP = 64
local hbuf = memory.alloc(CAP * 4 + 0x100)
local cbuf = memory.alloc(0x40)
for i = 0, (CAP * 4 + 0xFF) / 4 - 1 do safe_wd(hbuf + i * 4, 0) end
safe_wq(cbuf, 0)

local okA, retA = pcall(function()
    return sc659(uint64(hbuf), uint64(CAP), uint64(cbuf))
end)
print(string.format("  ret=%s count=%s", tostring(retA), hexval(safe_rq(cbuf))))
local handles = {}
if okA then
    for i = 0, CAP - 1 do
        local hv = safe_rd(hbuf + i * 4)
        if hv and hv ~= 0 then
            handles[#handles + 1] = hv
            print(string.format("  handle[%d] = 0x%X", i, hv))
        end
    end
end
print("  handles found: " .. #handles)

-- ============================================================
-- [B] 660: one module record per candidate handle
-- ============================================================
print("")
print("[B] 660 { module_handle, pad, info_inout } size gate 0x160")

local info = memory.alloc(0x200)
local function try660(label, handle, gatesize)
    for i = 0, 0x3F do safe_wq(info + i * 8, 0) end
    safe_wq(info, gatesize)
    local ok, ret = pcall(function() return sc660(uint64(handle), uint64(0), uint64(info)) end)
    if not ok then
        print(string.format("  %s handle=%s gate=%s -> PCALL-FAIL", label, sgn(handle), sgn(gatesize)))
        return
    end
    local size = safe_rq(info)
    local segcount = safe_rd(info + 0x120)
    local name = ""
    for i = 0, 15 do
        local ch = safe_rd(info + 8 + i * 4)
        if ch == nil or ch == 0 then break end
        name = name .. string.char(ch % 256)
    end
    print(string.format("  %s handle=%s gate=%s -> ret=%s size=%s segcount=%s name=%q",
        label, sgn(handle), sgn(gatesize), sgn(ret), sgn(size), sgn(segcount), name))
end

try660("h0x13", uint64(0x13), uint64(0x160))
try660("h0x14", uint64(0x14), uint64(0x160))
try660("h0x15", uint64(0x15), uint64(0x160))
try660("h0x13-small", uint64(0x13), uint64(0x100))
try660("h0x13-big", uint64(0x13), uint64(0x200))

-- ============================================================
-- [C] 662/663/664: id encodings, count=1
-- ============================================================
print("")
print("[C] AIO batch with id encodings (contract: high16 slot, low16 handle)")

local ids = memory.alloc(0x40)
local states = memory.alloc(0x40)
local timeout = memory.alloc(0x20)

local candidates = {
    { "0", 0x00000000 },
    { "h13", 0x00000013 },
    { "h14", 0x00000014 },
    { "s0h13", 0x00000013 },
    { "s1h13", 0x00010013 },
    { "s2h13", 0x00020013 },
    { "s3h13", 0x00030013 },
    { "s0h14", 0x00010014 },
    { "s1h14", 0x00010014 },
    { "s1", 0x00010000 },
    { "s2", 0x00020000 },
}

for _, cand in ipairs(candidates) do
    local label, id = cand[1], cand[2]
    safe_wd(ids, id)
    safe_wd(states, 0x7A7A7A7A)
    local ok2, r2 = pcall(function() return sc662(uint64(ids), uint64(1), uint64(states)) end)
    local s2 = ok2 and sgn(r2) or "PCALL-FAIL"
    local st2 = ok2 and sgn(safe_rd(states)) or "-"
    safe_wd(states, 0x7B7B7B7B)
    local ok4, r4 = pcall(function() return sc664(uint64(ids), uint64(1), uint64(states)) end)
    local s4 = ok4 and sgn(r4) or "PCALL-FAIL"
    local st4 = ok4 and sgn(safe_rd(states)) or "-"
    safe_wd(states, 0x7C7C7C7C)
    safe_wq(timeout, 0)
    local ok3, r3 = pcall(function() return sc663(uint64(ids), uint64(1), uint64(states), uint64(0), uint64(timeout)) end)
    local s3 = ok3 and sgn(r3) or "PCALL-FAIL"
    local st3 = ok3 and sgn(safe_rd(states)) or "-"
    print(string.format("  id=%-6s 662: ret=%-20s state=%-12s | 664: ret=%-20s state=%-12s | 663: ret=%-20s state=%s",
        label, s2, st2, s4, st4, s3, st3))
end

-- count=2 with the two real handles
safe_wd(ids, 0x13)
safe_wd(ids + 4, 0x14)
safe_wd(states, 0x7D7D7D7D)
safe_wd(states + 4, 0x7D7D7D7D)
local okpair, rpair = pcall(function() return sc664(uint64(ids), uint64(2), uint64(states)) end)
print(string.format("  pair(0x13,0x14) count=2 -> ret=%s state0=%s state1=%s",
    okpair and sgn(rpair) or "PCALL-FAIL", sgn(safe_rd(states)), sgn(safe_rd(states + 4))))

-- ============================================================
-- [D] 547 as a protection oracle around mprotect
-- ============================================================
print("")
print("[D] 547 region record around mprotect(RWX)")

local region = memory.alloc(0x40)

local function region547(addr)
    for i = 0, 7 do safe_wq(region + i * 8, 0) end
    local ok, ret = pcall(function() return sc547(uint64(addr), uint64(region)) end)
    if not ok then return "PCALL-FAIL" end
    local startq = safe_rq(region)
    local endq = safe_rq(region + 8)
    local prot = safe_rq(region + 0x10)
    return string.format("ret=%s start=%s end=%s prot=%s",
        sgn(ret), sgn(startq), sgn(endq), sgn(prot))
end

local gpu = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_h, gpu_l = get_hi_lo(gpu)
print(string.format("  gpu mmap = %s", hexval(gpu)))
if gpu_h == 0 and gpu_l ~= 0xFFFFFFFF then
    safe_wd(gpu_l, 0x11223344)
    print(string.format("  before mprotect: %s", region547(uint64(gpu_l))))
    local prot_ret = sc74(uint64(gpu_l), uint64(0x4000), uint64(7))
    print(string.format("  mprotect(RWX) ret=%s", sgn(prot_ret)))
    print(string.format("  after  mprotect: %s", region547(uint64(gpu_l))))
    safe_wd(gpu_l, 0x55667788)
    print(string.format("  write after mprotect: read=%s", sgn(safe_rd(gpu_l))))
else
    print("  gpu mmap failed, section D skipped")
end

print("")
print("=== PROBE 237a COMPLETE ===")
