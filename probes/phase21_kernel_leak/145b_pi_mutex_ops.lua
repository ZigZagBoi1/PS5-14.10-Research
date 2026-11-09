-- CRASH_CLASS: LOW
-- PROBE 145b: PI-mutex operations via SROP (main thread only)
--
-- Tests PI lock/unlock/trylock behavior and churn for kernel stability

print("=== PROBE 145b: PI MUTEX OPS ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC_S = 0x40
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC_S + 0x08, a1) end
    if a2 then wq(srop_ctx + MC_S + 0x10, a2) end
    if a3 then wq(srop_ctx + MC_S + 0x18, a3) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

-- Get TID
local tid_buf = gpu + 0x100
wq(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local main_tid = to_num(safe_rd(tid_buf))
print("tid=" .. main_tid)

-- Futex area
local futex = gpu + 0x1000

print("")
print("--- [A] Lock/Unlock cycle ---")
wd(futex, 0)
local rv_l = srop(454, ua(futex), uint64(13), uint64(0))
print("[A] LOCK_PI rv=" .. hex(rv_l) .. " futex=" .. string.format("0x%X", safe_rd(futex) or 0))

local rv_u = srop(454, ua(futex), uint64(15), uint64(0))
print("[A] UNLOCK_PI rv=" .. hex(rv_u) .. " futex=" .. string.format("0x%X", safe_rd(futex) or 0))

print("")
print("--- [B] 100 lock/unlock cycles ---")
local lok, uok, lfail, ufail = 0, 0, 0, 0
for i = 1, 100 do
    wd(futex + 4, 0)
    local r1 = srop(454, ua(futex + 4), uint64(13), uint64(0))
    if to_num(r1) == 0 then lok = lok + 1 else lfail = lfail + 1 end
    local r2 = srop(454, ua(futex + 4), uint64(15), uint64(0))
    if to_num(r2) == 0 then uok = uok + 1 else ufail = ufail + 1 end
end
print("[B] lock_ok=" .. lok .. " lock_fail=" .. lfail)
print("[B] unlock_ok=" .. uok .. " unlock_fail=" .. ufail)
print("[B] pid=" .. to_num(sc20()))

print("")
print("--- [C] 64 distinct mutexes ---")
local alloc_ok = 0
for i = 0, 63 do
    wd(futex + 0x100 + i * 4, 0)
    local rv = srop(454, ua(futex + 0x100 + i * 4), uint64(13), uint64(0))
    if to_num(rv) == 0 then alloc_ok = alloc_ok + 1 end
end
print("[C] locked " .. alloc_ok .. "/64")

local free_ok = 0
for i = 0, 63 do
    local rv = srop(454, ua(futex + 0x100 + i * 4), uint64(15), uint64(0))
    if to_num(rv) == 0 then free_ok = free_ok + 1 end
end
print("[C] unlocked " .. free_ok .. "/64")
print("[C] pid=" .. to_num(sc20()))

print("")
print("--- [D] Double-unlock test ---")
wd(futex + 0x200, 0)
local dl = srop(454, ua(futex + 0x200), uint64(13), uint64(0))
print("[D] lock rv=" .. hex(dl))
local du1 = srop(454, ua(futex + 0x200), uint64(15), uint64(0))
print("[D] unlock1 rv=" .. hex(du1))
local du2 = srop(454, ua(futex + 0x200), uint64(15), uint64(0))
print("[D] unlock2 rv=" .. hex(du2) .. " (double-unlock)")
print("[D] futex=" .. string.format("0x%X", safe_rd(futex + 0x200) or 0))
print("[D] pid=" .. to_num(sc20()))

print("")
print("--- [E] Lock without prior clear ---")
wd(futex + 0x204, 0x12345678)
local el = srop(454, ua(futex + 0x204), uint64(13), uint64(0))
print("[E] lock(non-zero futex) rv=" .. hex(el))
print("[E] futex=" .. string.format("0x%X", safe_rd(futex + 0x204) or 0))

wd(futex + 0x208, main_tid)
local el2 = srop(454, ua(futex + 0x208), uint64(13), uint64(0))
print("[E] lock(own TID) rv=" .. hex(el2))
print("[E] futex=" .. string.format("0x%X", safe_rd(futex + 0x208) or 0))

print("")
print("--- [F] SET_CEILING / TRYLOCK_PI ---")
wd(futex + 0x300, 0)
local sc = srop(454, ua(futex + 0x300), uint64(12), uint64(100))
print("[F] SET_CEILING(100) rv=" .. hex(sc))
print("[F] futex=" .. string.format("0x%X", safe_rd(futex + 0x300) or 0))

local tl = srop(454, ua(futex + 0x300), uint64(14), uint64(0))
print("[F] TRYLOCK_PI rv=" .. hex(tl))
print("[F] futex=" .. string.format("0x%X", safe_rd(futex + 0x300) or 0))

print("[F] pid=" .. to_num(sc20()))

print("")
print("=== PROBE 145b COMPLETE ===")
