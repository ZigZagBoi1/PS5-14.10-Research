-- CRASH_CLASS: MODERATE
-- PROBE 138b: sbl_srv (Secure Boot Loader) device deep scan
--
-- sbl_srv is a Sony-specific device likely related to the Secure Boot Loader.
-- Try open, fstat, read, write, ioctl with various code groups.

print("=== PROBE 138b: sbl_srv ===")

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

--------------------------------------------------------------------
-- SECTION A: Open sbl_srv
--------------------------------------------------------------------
print("")
print("--- [A] open sbl_srv ---")

local fd = -1
local open_modes = {
    {f=0x2004, n="RDWR|NONBLOCK|CLOEXEC"},
    {f=0x0004, n="RDONLY|NONBLOCK"},
    {f=0x2002, n="RDWR"},
    {f=0x0002, n="RDWR"},
    {f=0x2000, n="CLOEXEC|RDONLY"},
    {f=0x0000, n="RDONLY"},
}
for _, m in ipairs(open_modes) do
    ws(path_buf, "/dev/sbl_srv")
    local rv = srop(5, ua(path_buf), uint64(m.f))
    local rvh, rvl = get_hi_lo(rv)
    if rvl > 0 and rvl < 256 and rvh == 0 then
        fd = rvl
        print("[A] opened fd=" .. fd .. " mode=" .. m.n)
        break
    end
    print("[A] mode " .. m.n .. " = " .. hex(rv))
end

if fd < 0 then
    print("[A] ALL OPEN FAILED")
    print("pid=" .. to_num(sc20()))
    print("=== DONE ===")
    return
end

--------------------------------------------------------------------
-- SECTION B: fstat
--------------------------------------------------------------------
print("")
print("--- [B] fstat ---")
zero(stat_buf, 0x100)
srop(189, uint64(fd), ua(stat_buf))
for off = 0, 0x78, 8 do
    local v = safe_rq(stat_buf + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh > 0 or vl > 0 then
            local label = ""
            if off == 0x00 then label = " st_dev" end
            if off == 0x08 then label = " st_ino" end
            if off == 0x10 then label = " st_mode" end
            if off == 0x18 then label = " st_nlink" end
            if off == 0x30 then label = " st_size" end
            if off == 0x50 then label = " st_rdev" end
            print(string.format("[B] +0x%02X: %s%s", off, hex(v), label))
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("  *** KERNEL POINTER! ***")
            end
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: read attempt
--------------------------------------------------------------------
print("")
print("--- [C] read ---")
zero(rd_buf, 0x200)
local rv_rd = srop(3, uint64(fd), ua(rd_buf), uint64(0x200))
local rdh, rdl = get_hi_lo(rv_rd)
if rdl > 0 and rdl <= 0x200 and rdh == 0 then
    print("[C] read: " .. rdl .. " bytes!")
    local s = ""
    for i = 0, math.min(rdl, 64) - 1 do
        s = s .. string.format("%02X ", to_num(memory.read_byte(rd_buf + i)))
    end
    print("[C] data: " .. s)
    for off = 0, math.min(rdl, 0x200) - 1, 8 do
        local v = safe_rq(rd_buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[C] *** KPTR read+0x%02X: %s ***", off, hex(v)))
            end
        end
    end
else
    print("[C] read=" .. hex(rv_rd))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: ioctl scan (SBL group 'S' = 0x53)
--------------------------------------------------------------------
print("")
print("--- [D] ioctl scan ---")
local ioctl_hits = 0

-- Sony SBL uses group 'S' = 0x53 based on known PS4 codes
-- Also try 's' = 0x73, and generic groups
local groups = {0x53, 0x73, 0x44, 0x42, 0x41}
for _, grp in ipairs(groups) do
    for cmd = 0, 15 do
        -- Read (direction=0x40) with different data sizes
        for _, sz in ipairs({4, 8, 16, 32, 64}) do
            local code = 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd
            zero(io_buf, 0x100)
            local rv_io = srop(54, uint64(fd), uint64(code), ua(io_buf))
            local ioh, iol = get_hi_lo(rv_io)
            if iol == 0 and ioh == 0 then
                ioctl_hits = ioctl_hits + 1
                print(string.format("[D] *** ioctl 0x%08X WORKS! (grp=0x%02X cmd=%d sz=%d)", code, grp, cmd, sz))
                for off = 0, math.min(sz, 64) - 1, 8 do
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
        -- Write+Read (direction=0xC0) with sz=4,8
        for _, sz in ipairs({4, 8}) do
            local code = 0xC0000000 + (sz * 0x10000) + (grp * 0x100) + cmd
            zero(io_buf, 0x100)
            local rv_io = srop(54, uint64(fd), uint64(code), ua(io_buf))
            local ioh, iol = get_hi_lo(rv_io)
            if iol == 0 and ioh == 0 then
                ioctl_hits = ioctl_hits + 1
                print(string.format("[D] *** ioctl 0x%08X WORKS! (WR grp=0x%02X cmd=%d)", code, grp, cmd))
            end
        end
    end
end

-- Also try void ioctls (direction=0x20)
for _, grp in ipairs(groups) do
    for cmd = 0, 7 do
        local code = 0x20000000 + (grp * 0x100) + cmd
        local rv_io = srop(54, uint64(fd), uint64(code), ua(io_buf))
        local ioh, iol = get_hi_lo(rv_io)
        if iol == 0 and ioh == 0 then
            ioctl_hits = ioctl_hits + 1
            print(string.format("[D] *** void ioctl 0x%08X WORKS!", code))
        end
    end
end

print("[D] ioctl_hits=" .. ioctl_hits)
srop(6, uint64(fd))
print("[D] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
