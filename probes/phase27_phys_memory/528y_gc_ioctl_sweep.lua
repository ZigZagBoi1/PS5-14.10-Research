-- CRASH_CLASS: MODERATE
-- PROBE 528y: Broad ioctl sweep on /dev/gc
--
-- 528x: narrow ioctl sweep returned -1 for all tested commands.
-- PS5 GNM uses /dev/gc for GPU command submission.
-- The ioctl number encodes: direction(2) | size(14) | type(8) | nr(8)
-- Sony's type byte is likely 'g' (0x67) or a custom value.
-- Sweep all nr values 0-255 for a few candidate type bytes.
--
-- ALSO: try submit via write() on /dev/gc (some drivers accept writes).
-- ALSO: try /dev/dipsw (DIP switch device, sometimes used for debug).

print("=== PROBE 528y: GC IOCTL SWEEP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    return N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
end

local gc_fd = open_dev("/dev/gc")
print("gc fd=" .. gc_fd)

local sc_ioctl = mk(54)
local ioctl_buf = memory.alloc(0x200)

-- ============================================================
-- [A] Sweep type bytes with size=0x10, direction=RW (0xC0)
-- _IOWR(type, nr, 16)
-- ============================================================
print("")
print("[A] Ioctl sweep: _IOWR(type, nr, 16)")

local accepted = {}
-- Try common type bytes: 'g'(0x67), 'd'(0x64), 'G'(0x47), 0x90-0x9F, 'S'(0x53)
local types = {0x67, 0x64, 0x47, 0x53, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96}

for _, typ in ipairs(types) do
    for nr = 0, 31 do
        -- Zero buffer
        for i = 0, 31, 4 do wd(N(ioctl_buf) + i, 0) end

        -- Construct ioctl: _IOWR(typ, nr, 16) = 0xC010_tt_nn
        local cmd = 0xC0100000 + typ * 256 + nr

        local ok_i, rv_i = pcall(function()
            return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(ioctl_buf))
        end)
        if ok_i then
            local ret = N(rv_i)
            if ret ~= -1 then
                table.insert(accepted, {cmd, ret})
                print(string.format("  0x%08X (type=0x%02X nr=%d): rv=%d ***", cmd, typ, nr, ret))
            end
        end
    end
end

-- ============================================================
-- [B] Also try simple ioctl with no data (IO direction = 0)
-- _IO(type, nr) = 0x0000_tt_nn
-- ============================================================
print("")
print("[B] Ioctl _IO(type, nr)")

for _, typ in ipairs(types) do
    for nr = 0, 31 do
        local cmd = typ * 256 + nr
        local ok_i, rv_i = pcall(function()
            return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(0))
        end)
        if ok_i then
            local ret = N(rv_i)
            if ret ~= -1 then
                table.insert(accepted, {cmd, ret})
                print(string.format("  0x%04X (type=0x%02X nr=%d): rv=%d ***", cmd, typ, nr, ret))
            end
        end
    end
end

-- ============================================================
-- [C] Larger sizes: _IOWR(type, nr, 128) and _IOWR(type, nr, 256)
-- ============================================================
print("")
print("[C] Ioctl with larger sizes")

for _, typ in ipairs({0x67, 0x92, 0x93, 0x94}) do
    for nr = 0, 15 do
        for _, sz in ipairs({0x80, 0x100}) do
            for i = 0, 63, 4 do wd(N(ioctl_buf) + i, 0) end
            local cmd = 0xC0000000 + sz * 0x10000 + typ * 256 + nr
            local ok_i, rv_i = pcall(function()
                return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(ioctl_buf))
            end)
            if ok_i then
                local ret = N(rv_i)
                if ret ~= -1 then
                    table.insert(accepted, {cmd, ret})
                    print(string.format("  0x%08X (type=0x%02X nr=%d sz=0x%X): rv=%d ***",
                        cmd, typ, nr, sz, ret))
                end
            end
        end
    end
end

-- ============================================================
-- [D] Try write() on /dev/gc with a small PM4 buffer
-- ============================================================
print("")
print("[D] write() on /dev/gc")

local sc_write = mk(4)
local wbuf = memory.alloc(0x100)
-- NOP PM4 packet
wd(N(wbuf), 0xC0FF1000)  -- type 3, NOP, big count
wd(N(wbuf) + 4, 0)

local ok_w, rv_w = pcall(function()
    return sc_write(uint64(gc_fd), uint64(wbuf), uint64(16))
end)
if ok_w then
    print("  write(gc, 16): rv=" .. N(rv_w))
else
    print("  write(gc, 16): crash/blocked")
end

-- ============================================================
-- [E] Check /dev/submit_done and /dev/gc_done device nodes
-- ============================================================
print("")
print("[E] Other GPU devices")

local gpu_devs = {
    "/dev/gc0", "/dev/gc1", "/dev/gpu", "/dev/submit",
    "/dev/sdma", "/dev/sdma0", "/dev/sdma1",
    "/dev/compute", "/dev/compute0",
    "/dev/gfx", "/dev/gfx0",
    "/dev/dipsw",
}
for _, dev in ipairs(gpu_devs) do
    local fd = open_dev(dev)
    if fd >= 0 and fd < 200 then
        print(string.format("  %s: fd=%d ***", dev, fd))
        pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
    end
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)

print("")
print(string.format("total accepted ioctls: %d", #accepted))
for _, a in ipairs(accepted) do
    print(string.format("  0x%08X rv=%d", a[1], a[2]))
end

print("")
print("=== 528y DONE ===")
